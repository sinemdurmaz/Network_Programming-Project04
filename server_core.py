from __future__ import annotations
from typing import Dict, Any, Tuple

from common import SECURE_MODES, ALL_MODES
import app_protocol as ap
from security import encrypt, decrypt

class ChatServerCore:
    def __init__(self, psk: str, server_name: str = "CEN437-Server"):
        self.psk = psk
        self.server_name = server_name
        self.clients: Dict[Any, Dict[str, Any]] = {}

    def _maybe_decrypt(self, mode: str, payload: bytes) -> bytes:
        return decrypt(self.psk, payload) if mode in SECURE_MODES else payload

    def _maybe_encrypt(self, mode: str, payload: bytes) -> bytes:
        return encrypt(self.psk, payload) if mode in SECURE_MODES else payload

    def handle_message(self, src, raw_payload: bytes) -> Tuple[bytes | None, str | None]:
        mode = self.clients.get(src, {}).get("mode", "default")
        try:
            msg = ap.decode(self._maybe_decrypt(mode, raw_payload))
        except Exception as e:
            err = ap.encode(ap.error(f"decode/decrypt failed: {e}"))
            return self._maybe_encrypt(mode, err), None

        mtype = msg.get("type")

        if mtype == ap.MSG_HELLO:
            username = msg.get("username", "anon")
            self.clients[src] = {"username": username, "mode": "default"}
            return ap.encode(ap.hello_ack(self.server_name)), None

        if mtype == ap.MSG_MODE_SELECT:
            req_mode = msg.get("mode")
            if req_mode not in ALL_MODES:
                resp = ap.encode(ap.error("unknown mode"))
                return self._maybe_encrypt(mode, resp), None
            self.clients.setdefault(src, {"username": "anon", "mode": req_mode})
            self.clients[src]["mode"] = req_mode
            resp = ap.encode({"type": "MODE_ACK", "mode": req_mode})
            return self._maybe_encrypt(req_mode, resp), None

        if mtype == ap.MSG_CHAT:
            username = self.clients.get(src, {}).get("username", "anon")
            text = msg.get("text", "")
            resp = ap.encode({"type": "CHAT_ACK", "ok": True})
            return self._maybe_encrypt(mode, resp), f"{username}: {text}"

        if mtype == ap.MSG_BYE:
            self.clients.pop(src, None)
            return ap.encode({"type": "BYE_ACK"}), None

        resp = ap.encode(ap.error("unknown message type"))
        return self._maybe_encrypt(mode, resp), None
