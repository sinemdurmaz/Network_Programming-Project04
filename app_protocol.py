from __future__ import annotations
import json
from typing import Any, Dict

MSG_HELLO = "HELLO"
MSG_HELLO_ACK = "HELLO_ACK"
MSG_MODE_SELECT = "MODE_SELECT"
MSG_CHAT = "CHAT"
MSG_ERROR = "ERROR"
MSG_BYE = "BYE"

def encode(msg: Dict[str, Any]) -> bytes:
    return json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def decode(raw: bytes) -> Dict[str, Any]:
    return json.loads(raw.decode("utf-8"))

def hello(client_id: str, username: str) -> Dict[str, Any]:
    return {"type": MSG_HELLO, "client_id": client_id, "username": username}

def hello_ack(server_name: str) -> Dict[str, Any]:
    return {"type": MSG_HELLO_ACK, "server": server_name}

def mode_select(mode: str) -> Dict[str, Any]:
    return {"type": MSG_MODE_SELECT, "mode": mode}

def chat(from_user: str, text: str) -> Dict[str, Any]:
    return {"type": MSG_CHAT, "from": from_user, "text": text}

def error(reason: str) -> Dict[str, Any]:
    return {"type": MSG_ERROR, "reason": reason}

def bye() -> Dict[str, Any]:
    return {"type": MSG_BYE}
