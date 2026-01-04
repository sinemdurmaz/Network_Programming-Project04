from __future__ import annotations
import time, threading, queue
from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class ClientQueues:
    inbound: "queue.Queue[bytes]" = field(default_factory=queue.Queue)
    outbound: "queue.Queue[bytes]" = field(default_factory=queue.Queue)
    last_seen: float = field(default_factory=time.time)

class HTTPSServerQueues:
    """Server-side in-memory queues per client_id."""

    def __init__(self):
        self._lock = threading.Lock()
        self._clients: Dict[str, ClientQueues] = {}

    def _get(self, client_id: str) -> ClientQueues:
        with self._lock:
            if client_id not in self._clients:
                self._clients[client_id] = ClientQueues()
            cq = self._clients[client_id]
            cq.last_seen = time.time()
            return cq

    def push_from_client(self, client_id: str, raw_packet: bytes) -> None:
        self._get(client_id).inbound.put(raw_packet)

    def pop_inbound(self, client_id: str, timeout: float = 0.0) -> Optional[bytes]:
        cq = self._get(client_id)
        try:
            return cq.inbound.get(timeout=timeout)
        except Exception:
            return None

    def push_to_client(self, client_id: str, raw_packet: bytes) -> None:
        self._get(client_id).outbound.put(raw_packet)

    def pop_to_client(self, client_id: str, max_items: int = 10) -> List[bytes]:
        cq = self._get(client_id)
        out: List[bytes] = []
        for _ in range(max_items):
            try:
                out.append(cq.outbound.get_nowait())
            except Exception:
                break
        return out
