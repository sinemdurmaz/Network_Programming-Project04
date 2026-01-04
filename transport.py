from __future__ import annotations
import struct, zlib, time, threading
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any

from common import PROTOCOL_VERSION, FLAG_DATA, FLAG_ACK

_HEADER_FMT = "!BBHHHI"  # ver, flags, seq, ack, length, crc32
HEADER_LEN = struct.calcsize(_HEADER_FMT)  # 12

@dataclass
class Packet:
    version: int
    flags: int
    seq: int
    ack: int
    length: int
    crc32: int
    payload: bytes

def _crc32(header_wo_crc: bytes, payload: bytes) -> int:
    return zlib.crc32(header_wo_crc + payload) & 0xFFFFFFFF

def build_packet(flags: int, seq: int, ack: int, payload: bytes) -> bytes:
    length = len(payload)
    header_wo_crc = struct.pack("!BBHHH", PROTOCOL_VERSION, flags, seq, ack, length)
    crc = _crc32(header_wo_crc, payload)
    header = struct.pack(_HEADER_FMT, PROTOCOL_VERSION, flags, seq, ack, length, crc)
    return header + payload

def parse_packet(raw: bytes) -> Packet:
    if len(raw) < HEADER_LEN:
        raise ValueError("packet too short")
    ver, flags, seq, ack, length, crc = struct.unpack(_HEADER_FMT, raw[:HEADER_LEN])
    payload = raw[HEADER_LEN:]
    if len(payload) != length:
        raise ValueError("bad length")
    header_wo_crc = struct.pack("!BBHHH", ver, flags, seq, ack, length)
    calc = _crc32(header_wo_crc, payload)
    if calc != crc:
        raise ValueError("bad checksum")
    return Packet(ver, flags, seq, ack, length, crc, payload)

class Carrier:
    """Carrier abstraction.

    Implementations must provide:
      - send(raw_packet: bytes, dest) -> None
      - recv(timeout: float|None) -> (raw_packet: bytes, src) | None
      - close() -> None
    """
    def send(self, raw_packet: bytes, dest: Any) -> None: ...
    def recv(self, timeout: Optional[float]) -> Optional[Tuple[bytes, Any]]: ...
    def close(self) -> None: ...

class StopAndWaitTransport:
    """Stop-and-wait ARQ per peer (one outstanding DATA at a time per peer)."""

    def __init__(self, carrier: Carrier, timeout: float = 0.8, max_retries: int = 10):
        self.carrier = carrier
        self.timeout = timeout
        self.max_retries = max_retries

        self._send_seq: Dict[Any, int] = {}
        self._recv_expect: Dict[Any, int] = {}

        import queue
        self._rx_queue: "queue.Queue[Tuple[bytes, Any, dict]]" = queue.Queue()

        self._closed = False
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def close(self):
        self._closed = True
        try:
            self.carrier.close()
        except Exception:
            pass

    def _rx_loop(self):
        while not self._closed:
            item = self.carrier.recv(timeout=0.2)
            if not item:
                continue
            raw, src = item
            try:
                pkt = parse_packet(raw)
            except Exception:
                continue  # drop corrupt packet

            if pkt.flags & FLAG_ACK:
                self._rx_queue.put((b"", src, {"type": "ack", "ack": pkt.ack}))
                continue

            if pkt.flags & FLAG_DATA:
                expect = self._recv_expect.get(src, 0)
                if pkt.seq == expect:
                    self._recv_expect[src] = 1 - expect
                    self._rx_queue.put((pkt.payload, src, {"type": "data", "seq": pkt.seq}))
        
                # ACK received seq (even for duplicates)
                ack_pkt = build_packet(flags=FLAG_ACK, seq=0, ack=pkt.seq, payload=b"")
                self.carrier.send(ack_pkt, src)

    def tp_send(self, data: bytes, dest: Any) -> None:
        print(f"DEBUG: Mesaj su adrese gonderiliyor -> {dest}")
        seq = self._send_seq.get(dest, 0)
        raw = build_packet(flags=FLAG_DATA, seq=seq, ack=0, payload=data)

        retries = 0
        deadline = time.time() + self.timeout
        while True:
            self.carrier.send(raw, dest)

            while time.time() < deadline:
                try:
                    payload, src, meta = self._rx_queue.get(timeout=0.05)
                except Exception:
                    continue

                if meta.get("type") == "ack" and src == dest and meta.get("ack") == seq:
                    self._send_seq[dest] = 1 - seq
                    return

                # Not our ACK; if it's DATA, keep it for the app
                if meta.get("type") == "data":
                    self._rx_queue.put((payload, src, meta))

            retries += 1
            if retries >= self.max_retries:
                raise TimeoutError("tp_send: ACK not received")
            deadline = time.time() + self.timeout

    def tp_recv(self, timeout: Optional[float] = None) -> Optional[Tuple[bytes, Any, dict]]:
        end = None if timeout is None else (time.time() + timeout)
        while True:
            remaining = None if end is None else max(0.0, end - time.time())
            if remaining == 0.0 and end is not None:
                return None
            try:
                payload, src, meta = self._rx_queue.get(timeout=0.05 if remaining is None else min(0.05, remaining))
            except Exception:
                continue
            if meta.get("type") == "data":
                return payload, src, meta
            # ignore ACKs for app
