from __future__ import annotations
import argparse
import os
import json

from carriers.udp_carrier import UDPCarrier
from transport import StopAndWaitTransport
import app_protocol as ap
from server_core import ChatServerCore

def main():
    apg = argparse.ArgumentParser()
    apg.add_argument("--host", default="0.0.0.0")
    apg.add_argument("--port", type=int, default=9000)
    apg.add_argument("--psk", default=None, help="Pre-shared key")
    args = apg.parse_args()

    psk = args.psk or os.environ.get("CEN437_PSK", "demo-password")
    
    carrier = UDPCarrier(bind_host=args.host, bind_port=args.port)
    tp = StopAndWaitTransport(carrier)
    core = ChatServerCore(psk=psk)

    # --- YENİ: ZİYARETÇİ DEFTERİ (ADDRESS BOOK) ---
    # Core modülün unutkanlığına karşı kendi listemizi tutuyoruz.
    active_addresses = set()
    # ----------------------------------------------

    print(f"==================================================")
    print(f"[UDP SERVER] Hafızalı Mod Aktif... Port: {args.host}:{args.port}")
    if psk:
        print(f"[GÜVENLİK] Şifreleme AKTİF (PSK: {psk})")
    print(f"==================================================")

    while True:
        item = tp.tp_recv(timeout=1.0)
        if not item:
            continue
        
        payload, src, _ = item
        
        # --- KAYIT: Gelen herkesi deftere ekle ---
        if src not in active_addresses:
            print(f"[+] Yeni Kullanıcı Tespit Edildi: {src}")
            active_addresses.add(src)
        # -----------------------------------------

        # 1. Şifre Çözme
        if psk:
            try:
                from security import decrypt
                payload = decrypt(psk, payload)
            except Exception:
                pass

        # 2. Mesaj Türünü Analiz Et
        try:
            msg_dict = ap.decode(payload)
            msg_type = msg_dict.get("type")
            sender_name = msg_dict.get("from", "Bilinmeyen")
            msg_text = msg_dict.get("text", "")
            if msg_type == "CHAT":
                print(f"[CHAT] {sender_name}: {msg_text}")
        except:
            msg_dict = {}
            msg_type = "UNKNOWN"
            msg_text = ""

        # 3. Mesajı Çekirdeğe İlet
        resp, broadcast = core.handle_message(src, payload)
        
        # --- MANUEL YAYIN (Core broadcast yapmasa bile biz yaparız) ---
        if not broadcast and msg_type == "CHAT" and msg_text:
            broadcast = msg_text
        
        # 4. Yayın Yap (Broadcast) -> ARTIK KENDİ DEFTERİMİZİ KULLANIYORUZ
        if broadcast:
            # print(f"[YAYIN] {len(active_addresses)} kişiye dağıtılıyor...")
            
            # Listeyi kopyalayıp dönelim (Loop sırasında değişmesin diye)
            current_targets = list(active_addresses)
            
            for target_addr in current_targets:
                # Kendisine geri yollama (Yankı engelleme)
                # İsterseniz test için bu iki satırı silebilirsiniz.
                if str(target_addr) == str(src):
                    continue
                
                # Paketi hazırla
                out_msg = ap.encode(ap.chat(from_user=sender_name, text=broadcast))
                
                # Herkese şifreli gönder
                if psk:
                    from security import encrypt
                    out_msg = encrypt(psk, out_msg)
                
                try:
                    tp.tp_send(out_msg, target_addr)
                    # print(f"    -> Gönderildi: {target_addr}")
                except Exception:
                    # Gönderim başarısızsa listeden silmeyelim, belki geçici hatadır.
                    pass

        # 5. Cevap Gönder (ACK/Response - Sadece gönderene)
        if resp is not None:
            if psk:
                from security import encrypt
                resp = encrypt(psk, resp)
            try:
                tp.tp_send(resp, src)
            except Exception:
                pass

if __name__ == "__main__":
    main()