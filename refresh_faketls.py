"""Refresh the Nexus public FakeTLS feed using end-to-end Telegram probes."""
import base64
import concurrent.futures
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import socket
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FEED = Path("telegram-faketls.txt")
SOURCES = (
    "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/faketls/tg.txt",
    "https://raw.githubusercontent.com/tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt",
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
)
CLOUDFLARE = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")
NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
MAX_PER_SOURCE = 48
MAX_PUBLISHED = 12


@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    secret: bytes

    def link(self):
        return "tg://proxy?" + urlencode({"server": self.host, "port": self.port, "secret": self.secret.hex()})


def download(url, limit):
    with urlopen(url, timeout=10) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download exceeds the size limit")
    return data.decode("utf-8-sig")


def valid_name(name):
    return len(name) <= 200 and NAME.fullmatch(name) and not name.endswith((".local", ".localhost"))


def parse(line):
    try:
        uri = urlsplit(line.strip())
        if (uri.scheme, uri.netloc) not in (("tg", "proxy"), ("https", "t.me")):
            return None
        if uri.path not in ("", "/proxy") or uri.fragment:
            return None
        fields = parse_qs(uri.query, strict_parsing=True, max_num_fields=3)
        host, port, encoded = (fields[key][0] for key in ("server", "port", "secret"))
        host = host.lower()
        port = int(port)
        if not valid_name(host) or not 1 <= port <= 65535 or len(encoded) > 434:
            return None
        if re.fullmatch(r"[0-9a-fA-F]+", encoded) and len(encoded) % 2 == 0:
            secret = bytes.fromhex(encoded)
        else:
            secret = base64.b64decode(encoded.rstrip("=") + "=" * (-len(encoded.rstrip("=")) % 4), altchars=b"-_", validate=True)
        if not 21 <= len(secret) <= 217 or secret[0] != 0xEE:
            return None
        if not valid_name(secret[17:].decode("ascii")):
            return None
        return Proxy(host, port, secret)
    except (ValueError, KeyError, UnicodeError):
        return None


def exact(sock, count, deadline):
    data = bytearray()
    while len(data) < count:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("Probe deadline")
        sock.settimeout(left)
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("Connection closed")
        data.extend(chunk)
    return bytes(data)


def record(sock, deadline):
    header = exact(sock, 5, deadline)
    size = int.from_bytes(header[3:], "big")
    if header[1:3] != b"\x03\x03" or size > 18432:
        raise ValueError("Invalid FakeTLS record")
    return header + exact(sock, size, deadline)


def handshake(sock, key, domain, deadline):
    def ext(kind, data):
        return struct.pack(">HH", kind, len(data)) + data

    extensions = ext(0, struct.pack(">HBH", len(domain) + 3, 0, len(domain)) + domain)
    extensions += bytes.fromhex("00170000ff010000000a00080006001d00170018000b000201000010000e000c02683208687474702f312e31000d000a00080403080404010807")
    extensions += ext(51, struct.pack(">HHH", 36, 29, 32) + os.urandom(32))
    extensions += bytes.fromhex("002d00020101002b00050403040303")
    suites = bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8")
    prefix = b"\x03\x03" + bytes(32) + b"\x20" + os.urandom(32) + struct.pack(">H", len(suites)) + suites + b"\x01\x00"
    extensions += ext(21, bytes(502 - len(prefix) - len(extensions)))
    hello = prefix + struct.pack(">H", len(extensions)) + extensions
    frame = b"\x16\x03\x01" + struct.pack(">H", len(hello) + 4) + b"\x01" + len(hello).to_bytes(3, "big") + hello
    challenge = bytearray(hmac.digest(key, frame, "sha256"))
    for index, byte in enumerate(struct.pack("<I", int(time.time())), 28):
        challenge[index] ^= byte
    sock.sendall(frame[:11] + challenge + frame[43:])
    server, change, app = (record(sock, deadline) for _ in range(3))
    if len(server) < 43 or server[0] != 22 or change != b"\x14\x03\x03\x00\x01\x01" or app[0] != 23:
        raise ValueError("Invalid FakeTLS handshake")
    supplied = server[11:43]
    expected = hmac.digest(key, challenge + server[:11] + bytes(32) + server[43:] + change + app, "sha256")
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("Invalid FakeTLS authentication")


def telegram_probe(sock, key, dc, deadline):
    header = bytearray(os.urandom(64))
    header[0] = 0x89
    header[4] |= 1
    header[56:62] = b"\xdd" * 4 + struct.pack("<h", dc)

    def cipher(seed):
        return Cipher(algorithms.AES(hashlib.sha256(seed[8:40] + key).digest()),
                      modes.CTR(seed[40:56])).encryptor()

    encrypt, decrypt = cipher(bytes(header)), cipher(bytes(header[::-1]))
    payload = header[:56] + encrypt.update(bytes(header))[56:]
    nonce = os.urandom(16)
    message_id = (time.time_ns() * 2**32 // 10**9) & ~3
    message = struct.pack("<QQII", 0, message_id, 20, 0xBE7E8EF1) + nonce
    padding = os.urandom(7)
    payload += encrypt.update(struct.pack("<I", len(message) + len(padding)) + message + padding)
    sock.sendall(b"\x14\x03\x03\x00\x01\x01\x17\x03\x03" + struct.pack(">H", len(payload)) + payload)
    response = bytearray()
    for _ in range(8):
        frame = record(sock, deadline)
        if frame[0] != 23:
            return False
        response.extend(decrypt.update(frame[5:]))
        if len(response) < 4:
            continue
        size, = struct.unpack_from("<I", response)
        if not 76 <= size <= 4096:
            return False
        if len(response) >= 4 + size:
            auth_key, _, body_size, constructor = struct.unpack_from("<QQII", response, 4)
            return (auth_key == 0 and 56 <= body_size <= size - 20 and
                    constructor == 0x05162463 and hmac.compare_digest(response[28:44], nonce))
    return False


def probe(proxy, cloudflare):
    try:
        addresses = tuple(dict.fromkeys(ipaddress.ip_address(info[4][0])
                                       for info in socket.getaddrinfo(proxy.host, proxy.port, type=socket.SOCK_STREAM)))
        if not addresses or any(not ip.is_global or ip.is_multicast or
                                any(ip.version == block.version and ip in block for block in cloudflare)
                                for ip in addresses):
            return None
        # Pin the connection to the address examined above. No second DNS lookup.
        for ip in addresses[:2]:
            try:
                for dc in (2, 4):
                    with socket.socket(socket.AF_INET if ip.version == 4 else socket.AF_INET6) as sock:
                        deadline = time.monotonic() + 4
                        sock.settimeout(4)
                        sock.connect((str(ip), proxy.port))
                        handshake(sock, proxy.secret[1:17], proxy.secret[17:], deadline)
                        if not telegram_probe(sock, proxy.secret[1:17], dc, deadline):
                            break
                else:
                    return ip
            except (OSError, EOFError, ValueError):
                continue
    except (OSError, ValueError):
        pass
    return None


def main():
    # Fail closed if either official address list is unavailable.
    ranges = []
    for family, url in zip((4, 6), CLOUDFLARE):
        blocks = [ipaddress.ip_network(line) for line in download(url, 32_768).splitlines() if line.strip()]
        if not blocks or any(block.version != family for block in blocks):
            raise ValueError("Invalid Cloudflare IP list")
        ranges.extend(blocks)
    candidates = {}
    previous = FEED.read_text(encoding="utf-8").splitlines()
    batches = [previous]
    for url in SOURCES:
        try:
            batches.append(download(url, 4_000_000).splitlines())
        except (OSError, ValueError):
            print(f"Source unavailable: {url}")
    for lines in batches:
        seen = set()
        for line in lines:
            candidate = parse(line)
            if candidate and candidate.host not in seen:
                seen.add(candidate.host)
                candidates.setdefault(candidate, None)
                if len(seen) == MAX_PER_SOURCE:
                    break
    print(f"Checking {len(candidates)} candidates against Telegram DC2 and DC4")
    results = []
    seen_ips = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for pos in range(0, len(candidates), 16):
            batch = list(candidates)[pos:pos + 16]
            for proxy, ip in zip(batch, pool.map(lambda item: probe(item, ranges), batch)):
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    results.append(proxy.link())
            if len(results) >= MAX_PUBLISHED:
                break
    if not results:
        print("No confirmed proxies; retaining previous catalog.")
        return
    lines = ["# Nexus public Telegram MTProto FakeTLS catalog",
             "# Verified from a GitHub Actions runner against DC2 and DC4.",
             *results[:MAX_PUBLISHED]]
    FEED.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Published {min(len(results), MAX_PUBLISHED)} verified proxies.")


if __name__ == "__main__":
    main()
