"""Minimal RFC 6455 WebSocket over asyncio streams (stdlib only): server upgrade + client connect."""
from __future__ import annotations
import asyncio, base64, hashlib, os, struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 1 << 20


class Closed(Exception):
    pass


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


class WebSocket:
    def __init__(self, reader, writer, mask: bool):
        self.r, self.w, self.mask, self.closed = reader, writer, mask, False
        self.bytes_in = self.bytes_out = 0

    async def send(self, text: str):
        await self._send_frame(0x1, text.encode("utf-8"))

    async def _send_frame(self, opcode: int, data: bytes):
        if self.closed:
            raise Closed()
        if len(data) > MAX_FRAME:
            raise Closed("message too large")
        hdr = bytearray([0x80 | opcode])
        n = len(data)
        mbit = 0x80 if self.mask else 0
        if n < 126:
            hdr.append(mbit | n)
        elif n < 65536:
            hdr += bytes([mbit | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([mbit | 127]) + struct.pack("!Q", n)
        if self.mask:
            k = os.urandom(4)
            hdr += k
            data = bytes(b ^ k[i % 4] for i, b in enumerate(data))
        self.w.write(bytes(hdr) + data)
        self.bytes_out += len(hdr) + len(data)
        await asyncio.wait_for(self.w.drain(), 10)

    async def recv(self) -> str:
        buf = bytearray()
        fragmented = False
        while True:
            b1, b2 = await self.r.readexactly(2)
            op, n = b1 & 0x0F, b2 & 0x7F
            fin = bool(b1 & 0x80)
            if b1 & 0x70 or bool(b2 & 0x80) != (not self.mask) or op not in (0, 1, 8, 9, 10):
                await self.close(1002)
                raise Closed("invalid frame flags, opcode or masking")
            length_code = n
            if n == 126:
                n = struct.unpack("!H", await self.r.readexactly(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", await self.r.readexactly(8))[0]
            if (length_code == 126 and n < 126) or (length_code == 127 and (n < 65536 or n >= 1 << 63)):
                await self.close(1002)
                raise Closed("noncanonical frame length")
            if op >= 8 and (not fin or n > 125):
                await self.close(1002)
                raise Closed("invalid control frame")
            if n > MAX_FRAME or (op < 8 and len(buf) + n > MAX_FRAME):
                await self.close(1009)
                raise Closed("frame too large")
            k = await self.r.readexactly(4) if b2 & 0x80 else None
            data = await self.r.readexactly(n)
            self.bytes_in += n + 2
            if k:
                data = bytes(b ^ k[i % 4] for i, b in enumerate(data))
            if op == 0x8:
                if len(data) == 1:
                    await self.close(1002)
                    raise Closed("invalid close payload")
                if len(data) >= 2:
                    code = struct.unpack("!H", data[:2])[0]
                    if code not in (1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014) and not 3000 <= code <= 4999:
                        await self.close(1002)
                        raise Closed("invalid close code")
                    try:
                        data[2:].decode("utf-8")
                    except UnicodeError:
                        await self.close(1007)
                        raise Closed("invalid close reason") from None
                await self.close()
                raise Closed()
            if op == 0x9:
                await self._send_frame(0xA, data)
                continue
            if op == 0xA:
                continue
            if (op == 0 and not fragmented) or (op == 1 and fragmented):
                await self.close(1002)
                raise Closed("invalid continuation sequence")
            fragmented = not fin
            buf.extend(data)
            if fin:
                try:
                    return buf.decode("utf-8")
                except UnicodeError:
                    await self.close(1007)
                    raise Closed("invalid UTF-8") from None

    async def close(self, code: int = 1000):
        if not self.closed:
            try:
                await self._send_frame(0x8, struct.pack("!H", code))
            except Exception:
                pass
            finally:
                self.closed = True
                self.w.close()
                try:
                    await asyncio.wait_for(self.w.wait_closed(), 2)
                except (AttributeError, OSError, asyncio.TimeoutError):
                    pass


async def connect(host: str, port: int, path: str = "/vws") -> WebSocket:
    if any(c in host + path for c in ("\r", "\n")) or not path.startswith("/"):
        raise ValueError("invalid WebSocket target")
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
    key = base64.b64encode(os.urandom(16)).decode()
    w.write((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    await w.drain()
    try:
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin-1").split("\r\n")
        headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:] if line)}
        if (lines[0].split()[:2] != ["HTTP/1.1", "101"]
                or headers.get("sec-websocket-accept") != accept_key(key)
                or headers.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in {v.strip().lower() for v in headers.get("connection", "").split(",")}):
            raise Closed("handshake rejected")
    except BaseException:
        w.close()
        raise
    return WebSocket(r, w, mask=True)
