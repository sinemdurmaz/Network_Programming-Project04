from __future__ import annotations
import socket, select, os  # <-- os modülü eklendi
from typing import Optional, Any

class UDPCarrier:
    def __init__(self, bind_host: str = "", bind_port: int = 0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # --- WINDOWS ICMP YAMASI BAŞLANGICI ---
        # Bu blok, hedef port kapalıyken Windows'un socket'i kapatmasını engeller
        if os.name == 'nt':
            try:
                # SIO_UDP_CONNRESET = 0x9800000C
                self.sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            except (AttributeError, OSError):
                pass
        # --- WINDOWS ICMP YAMASI BİTİŞİ ---

        self.sock.bind((bind_host, bind_port))
        self.sock.setblocking(False)

    def send(self, raw_packet: bytes, dest: Any) -> None:
        host, port = dest
        self.sock.sendto(raw_packet, (host, port))

    def recv(self, timeout: Optional[float]):
        # select.select çağrısı, soket okunabilir olana kadar veya timeout olana kadar bekler
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return None
        try:
            data, addr = self.sock.recvfrom(65535)
            return data, addr
        except ConnectionResetError:
            # Yamaya rağmen nadir durumlarda hata gelirse None dönerek döngüyü kırmamasını sağla
            return None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass