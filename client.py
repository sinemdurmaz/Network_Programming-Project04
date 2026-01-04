from __future__ import annotations
import argparse, os, threading, uuid, time

# Hata yakalama modülü
import json 

from common import ALL_MODES, SECURE_MODES, OBFS_MODES
from transport import StopAndWaitTransport
from carriers.udp_carrier import UDPCarrier
from carriers.https_client import HTTPSClientCarrier
import app_protocol as ap
from security import encrypt, decrypt
import urllib3
# SSL Uyarılarını Sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def main():
    apg = argparse.ArgumentParser()
    apg.add_argument("--mode", required=True, choices=sorted(ALL_MODES))
    apg.add_argument("--username", required=True)
    apg.add_argument("--client-id", default=None)
    apg.add_argument("--psk", default=None, help="Pre-shared key")
    apg.add_argument("--udp-host", default="127.0.0.1")
    apg.add_argument("--udp-port", type=int, default=9000)
    apg.add_argument("--https-url", default="https://127.0.0.1:9443")
    args = apg.parse_args()

    client_id = args.client_id or str(uuid.uuid4())
    psk = args.psk or os.environ.get("CEN437_PSK", "demo-password")

    if args.mode in OBFS_MODES:
        carrier = HTTPSClientCarrier(base_url=args.https_url, client_id=client_id, verify_tls=False)
        dest = client_id 
    else:
        carrier = UDPCarrier(bind_host="", bind_port=0)
        dest = (args.udp_host, args.udp_port)

    tp = StopAndWaitTransport(carrier)
    sock_lock = threading.Lock()

    def send_app(msg_dict):
        raw = ap.encode(msg_dict)
        if args.mode in SECURE_MODES:
            raw = encrypt(psk, raw)
        with sock_lock:
            tp.tp_send(raw, dest)

    def recv_loop():
        # print("[Sistem] Dinleme modu aktif...") 
        while True:
            # 1. Kilit Kontrolü
            if not sock_lock.acquire(blocking=False):
                time.sleep(0.05)
                continue
            
            try:
                # 2. Veri Bekle
                item = tp.tp_recv(timeout=0.1)
            except Exception:
                item = None
            finally:
                sock_lock.release()

            if not item:
                continue

            payload, src, _ = item
            
            # 3. Gelen Veriyi İşle (HATA YÖNETİMİ GÜÇLENDİRİLDİ)
            try:
                # Önce şifreli gibi davranıp çözmeyi dene
                decrypted_payload = None
                if args.mode in SECURE_MODES:
                    try:
                        decrypted_payload = decrypt(psk, payload)
                        payload = decrypted_payload # Başarılıysa payload'ı güncelle
                    except Exception:
                        # Şifre çözülemezse, belki plaintext gelmiştir.
                        # Olduğu gibi bırak ve aşağıda decode etmeyi dene.
                        pass

                msg = ap.decode(payload)
                
            except (UnicodeDecodeError, json.JSONDecodeError):
                # Bu paket okunabilir bir metin değil (muhtemelen ACK veya Binary)
                # Ekrana hata basıp kullanıcıyı korkutma, sessizce geç.
                continue
            except Exception as e:
                # Diğer bilinmeyen hatalar
                print(f"\n[Sistem] Paket atlandı: {e}")
                print("> ", end="", flush=True)
                continue

            # 4. Mesajı Göster
            msg_type = msg.get("type")
            
            if msg_type == ap.MSG_CHAT:
                sender = msg.get("from", "?")
                text = msg.get("text", "")
                print(f"\n[{sender}] {text}")
                print("> ", end="", flush=True)
            elif msg_type in ["ACK", "HELLO_ACK"]:
                # Sistem mesajlarını görmezden gel
                pass
            else:
                # Bilinmeyen türleri yazdır (Debug için)
                print(f"\n[Server] {msg}")
                print("> ", end="", flush=True)

    # --- ANA AKIŞ ---
    print("[Sistem] Bağlanılıyor...")
    
    # Handshake
    try:
        send_app(ap.hello(client_id=client_id, username=args.username))
        send_app(ap.mode_select(args.mode))
    except TimeoutError:
        print("[HATA] Sunucu cevap vermiyor. Server'ı yeniden başlatın.")
        return

    print(f"[Client] Bağlandı: {args.username} ({args.mode})")
    print("Mesaj yazıp Enter'a basın. Çıkış: /quit")

    # Dinlemeyi Başlat
    t = threading.Thread(target=recv_loop, daemon=True)
    t.start()

    while True:
        try:
            text = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            text = "/quit"

        if not text:
            continue

        if text.lower() in ("/quit", "/exit"):
            send_app(ap.bye())
            break
        
        try:
            send_app(ap.chat(from_user=args.username, text=text))
        except TimeoutError:
            print("\n[HATA] Mesaj gitmedi (Timeout).")
        except Exception:
            pass # Gönderim hatalarını yut, akışı bozma

if __name__ == "__main__":
    main()