from __future__ import annotations
import argparse, base64, os
from flask import Flask, request, jsonify

from carriers.https_server import HTTPSServerQueues
from transport import parse_packet, build_packet, FLAG_DATA, FLAG_ACK
from server_core import ChatServerCore
import app_protocol as ap
from common import SECURE_MODES

app = Flask(__name__)
queues = HTTPSServerQueues()
core: ChatServerCore | None = None
PSK = None # Varsayılan olarak None

recv_expect = {}  # client_id -> expected seq (0/1)
active_clients = set()

def _handle_transport_packet(client_id: str, raw: bytes):
    global recv_expect, active_clients
    
    try:
        pkt = parse_packet(raw)
    except Exception:
        return

    if pkt.flags & FLAG_ACK:
        return

    if pkt.flags & FLAG_DATA:
        expect = recv_expect.get(client_id, 0)
        
        if pkt.seq == expect:
            recv_expect[client_id] = 1 - expect
            
            # 1. Şifre Çözme (Decrypt)
            payload = pkt.payload
            if PSK:
                try:
                    from security import decrypt
                    payload = decrypt(PSK, payload)
                except Exception:
                    pass 
            
            try:
                msg_dict = ap.decode(payload)
                sender_name = msg_dict.get("from", "Bilinmeyen")
            except:
                sender_name = "Bilinmeyen"

            # 2. Core'a ilet
            resp_payload, broadcast = core.handle_message(client_id, payload)

            # --- CEVAP (Response) ---
            if resp_payload is not None:
                final_resp = resp_payload
                if PSK: 
                    from security import encrypt
                    final_resp = encrypt(PSK, resp_payload)

                out = build_packet(flags=FLAG_DATA, seq=0, ack=0, payload=final_resp)
                queues.push_to_client(client_id, out)

            # --- YAYIN (Broadcast) ---
            if broadcast:
                out_msg_plain = ap.encode(ap.chat(from_user=sender_name, text=broadcast))
                
                targets = list(active_clients)
                for target_id in targets:
                    if target_id == client_id:
                        continue
                    
                    final_broadcast = out_msg_plain
                    # Sadece PSK varsa şifrele
                    if PSK:
                        from security import encrypt
                        final_broadcast = encrypt(PSK, out_msg_plain)
                    
                    out_pkt = build_packet(flags=FLAG_DATA, seq=1, ack=0, payload=final_broadcast)
                    queues.push_to_client(target_id, out_pkt)

        # ACK Gönder
        ack_pkt = build_packet(flags=FLAG_ACK, seq=0, ack=pkt.seq, payload=b"")
        queues.push_to_client(client_id, ack_pkt)

@app.post("/api/data")
def api_data():
    data = request.get_json(force=True, silent=True) or {}
    client_id = str(data.get("client_id", ""))
    
    if client_id:
        active_clients.add(client_id)

    p64 = data.get("packet", "")
    try:
        raw = base64.b64decode(p64)
    except Exception:
        raw = b""

    if client_id:
        queues.push_from_client(client_id, raw)
        while True:
            pkt = queues.pop_inbound(client_id, timeout=0.0)
            if pkt is None:
                break
            _handle_transport_packet(client_id, pkt)

    out = queues.pop_to_client(client_id, max_items=20)
    out64 = [base64.b64encode(p).decode("ascii") for p in out]
    return jsonify({"packets": out64})

@app.get("/api/poll")
def api_poll():
    client_id = request.args.get("client_id", "")
    if client_id:
        active_clients.add(client_id)
        
    out = queues.pop_to_client(client_id, max_items=20)
    out64 = [base64.b64encode(p).decode("ascii") for p in out]
    return jsonify({"packets": out64})

def main():
    global core, PSK
    apg = argparse.ArgumentParser()
    apg.add_argument("--host", default="0.0.0.0")
    apg.add_argument("--port", type=int, default=9443)
    apg.add_argument("--cert", required=True)
    apg.add_argument("--key", required=True)
    apg.add_argument("--psk", default=None, help="Pre-shared key")
    args = apg.parse_args()

    # BURASI DÜZELTİLDİ: Varsayılan "demo-password" silindi.
    # Eğer kullanıcı parametre girmezse PSK None olur (Şifresiz mod).
    PSK = args.psk or os.environ.get("CEN437_PSK") 
    
    core = ChatServerCore(psk=PSK)
    
    print(f"[HTTPS server] https://{args.host}:{args.port}")
    if PSK:
        print(f"[INFO] Secure OBFS Mode Active (PSK: {PSK})")
    else:
        print(f"[INFO] Plaintext OBFS Mode Active (NO ENCRYPTION)")
    
    app.run(host=args.host, port=args.port, ssl_context=(args.cert, args.key), threaded=True)

if __name__ == "__main__":
    main()