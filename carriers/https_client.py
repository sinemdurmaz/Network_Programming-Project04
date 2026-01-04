from __future__ import annotations
import base64, time, queue
from typing import Optional, Any
import requests

class HTTPSClientCarrier:
    """Client-side HTTPS tunnel carrier."""

    def __init__(self, base_url: str, client_id: str, verify_tls: bool = False, poll_interval: float = 0.6):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.verify_tls = verify_tls
        self.poll_interval = poll_interval
        self._in_q: "queue.Queue[bytes]" = queue.Queue()

    def _enqueue_from_response(self, resp_json):
        for p64 in resp_json.get("packets", []):
            try:
                self._in_q.put(base64.b64decode(p64))
            except Exception:
                continue

    def send(self, raw_packet: bytes, dest: Any = None) -> None:
        body = {"client_id": self.client_id, "packet": base64.b64encode(raw_packet).decode("ascii")}
        r = requests.post(self.base_url + "/api/data", json=body, verify=self.verify_tls, timeout=5)
        r.raise_for_status()
        self._enqueue_from_response(r.json())

    def recv(self, timeout: Optional[float]):
        try:
            pkt = self._in_q.get_nowait()
            return pkt, self.client_id
        except Exception:
            pass

        start = time.time()
        while True:
            remaining = None if timeout is None else max(0.0, timeout - (time.time() - start))
            if remaining == 0.0 and timeout is not None:
                return None
            r = requests.get(self.base_url + "/api/poll", params={"client_id": self.client_id},
                             verify=self.verify_tls, timeout=5)
            r.raise_for_status()
            self._enqueue_from_response(r.json())
            try:
                pkt = self._in_q.get(timeout=self.poll_interval if remaining is None else min(self.poll_interval, remaining))
                return pkt, self.client_id
            except Exception:
                continue

    def close(self):
        return
