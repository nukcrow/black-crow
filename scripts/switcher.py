#!/usr/bin/env python3
"""nukcrow configuration collector (tuned for Irancell / MCI).

Writes only sub1.txt ... sub20.txt and bot.txt under sub/general.

Pipeline: fetch -> parse/filter -> score (Iran profile) -> TCP + TLS/WS probe
-> real end-to-end proxy test (VLESS/Trojan over ws/tcp+TLS) -> tiered,
diversity-capped selection -> write.

NOTE: tests run from the GitHub runner, outside Iran. They prove the server is
alive and speaks TLS / WebSocket on the given path; they cannot prove it is
reachable from a specific Iranian ISP. The Iran profile (scoring + caps) is a
heuristic built on what the Iranian collectors and iboxz have in common.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
OUT_DIR = Path("sub/general")
REMARK = "nukcrow"

# 20 general subscriptions, 2,000 configs each (40,000 max).
SUBS = tuple((f"sub{i}.txt", 2000) for i in range(1, 21))
TOTAL_CONFIGS = sum(size for _, size in SUBS)
BOT_MAX_CONFIGS = 5000  # soft cap: fewer is fine

# ----------------------------------------------------------------------------
# Network / performance
# ----------------------------------------------------------------------------
FETCH_TIMEOUT = 15
FETCH_WORKERS = 32
MAX_FETCH_BYTES = 12_000_000
TCP_TIMEOUT = 2.5
PROBE_TIMEOUT = 4.0
E2E_TIMEOUT = 5.0
TEST_WORKERS = 300
MAX_PER_SOURCE = 50_000
MAX_CANDIDATES = 200_000   # unique parsed candidates kept
MAX_TEST = 80_000          # best-scored candidates actually tested

# ----------------------------------------------------------------------------
# Filter / selection knobs
# ----------------------------------------------------------------------------
ALLOWED_SCHEMES = {"vless", "vmess", "trojan", "ss"}
ALLOWED_NETS = {"tcp", "ws", "grpc", "xhttp", "splithttp", "httpupgrade", "h2", "http"}  # kcp/quic are UDP: dropped
SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
BLOCKED_PORTS = {22, 25, 53, 110, 143, 465, 587, 993, 995, 3306}
KEEP_PLAIN_VLESS = False   # vless without TLS/reality leaks traffic and is easy to fingerprint
INCLUDE_IPV6 = False       # runner has no IPv6, so these cannot be tested; set True to pass them untested
PROBE_ENABLED = True       # TLS handshake (+ WebSocket upgrade) on top of TCP connect
E2E_ENABLED = True         # real VLESS/Trojan request through the proxy (ws or tcp + TLS, no flow)
E2E_HOST = "connectivitycheck.gstatic.com"  # non-Cloudflare target (Workers cannot reach CF IPs)
E2E_PATH = "/generate_204"
FILL_TO_FULL = True        # top up with weaker tiers (probe/e2e failed, TCP ok) when verified ones run short
PRIORITY_BONUS = 40        # score bonus for configs that come from Iran-checked lists
WS_STRICT = True           # ws must answer "101 Switching Protocols"; False accepts any HTTP reply
MAX_PER_HOST = 3           # configs per host (Cloudflare IPs: per host+SNI)
MAX_PER_SUBNET = 20        # configs per /24 (IPv4) or /64 (IPv6); Cloudflare IPs exempt
PORT_443_SHARE = 0.35      # max share of one output taken by port 443
OTHER_PORT_SHARE = 0.10    # max share of one output taken by any other single port
CF_PORTS_TLS = {443, 2053, 2083, 2087, 2096, 8443}
CF_PORTS_PLAIN = {80, 8080, 8880, 2052, 2082, 2086, 2095}

CLOUDFLARE_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 "
    "108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 "
    "162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
).split()]

# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------
GH = "https://raw.githubusercontent.com/"

# Ten separate small collectors for bot.txt (verified alive, mixed profiles:
# iboxz-style VLESS/Reality + Iranian TLS/WS/gRPC domain-based collectors).
# OpenRay ranks configs using Iran-side checks (MCI / Irancell / TCI trackers).
IRAN_CHECKED = [GH + "sakha1370/OpenRay/refs/heads/main/output_iran/" + n for n in (
    "iran_top100_checked.txt", "mci_top100.txt", "irancell_top100.txt")]
PRIORITY_SOURCES = set(IRAN_CHECKED)

BOT_SOURCES = [GH + p for p in (
    "iboxz/free-v2ray-collector/main/main/mix.txt",
    "sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
    "sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt",
    "youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "Leon406/SubCrawler/master/sub/share/vless",
    "mheidari98/.proxy/refs/heads/main/vless",
    "Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
)]

# Hand-picked general sources (all verified alive, dead/404 and 100 MB lists removed).
RAW_SOURCES = IRAN_CHECKED + [GH + p for p in (
    # OpenRay validated pools
    "sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt",
    "sakha1370/OpenRay/refs/heads/main/output/kind/trojan.txt",
    # Iranian collectors
    "HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "MhdiTaheri/V2rayCollector/main/sub/mix",
    "MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "mheidari98/.proxy/refs/heads/main/vless",
    "Arefgh72/v2ray-proxy-pars-tester/main/output/github_all.txt",
    "Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
    "mehrtat/vless-collector/main/vless.txt",
    "coldwater-10/V2ray-Config/main/Sub7.txt",
    "snaCW/Config/main/config.txt",
    # iboxz and similar curated, small, tested lists
    "iboxz/free-v2ray-collector/main/main/mix.txt",
    "iboxz/free-v2ray-collector/main/main/vless",
    "iboxz/free-v2ray-collector/main/main/vmess",
    "iboxz/free-v2ray-collector/main/main/trojan",
    "V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-vl",
    "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-vm",
    "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-tr",
    # Large fresh pools
    "Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
    "barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "barry-far/V2ray-config/main/Sub2.txt",
    "sakha1370/OpenRay/main/output/all_valid_proxies.txt",
    "Leon406/SubCrawler/master/sub/share/vless",
    "SoliSpirit/v2ray-configs/main/all_configs.txt",
    "SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_001.txt",
    "Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt",
    "Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_013.txt",
    "liMilCo/v2r/main/configs.txt",
    "Argh94/Proxy-List/refs/heads/main/All_Config.txt",
    "roosterkid/openproxylist/main/V2RAY_RAW.txt",
)]

URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>'\"]+", re.I)
HOST_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)

TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE

# fingerprint -> (tcp_ms, probe_ms | None) | None ; shared by general and bot runs
TEST_CACHE: dict[str, tuple[float, float | None, bool | None] | None] = {}


# ----------------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------------
def decode64(value: str) -> str:
    value = value.strip().replace("-", "+").replace("_", "/")
    if not value:
        return ""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "ignore")
    except (ValueError, UnicodeDecodeError):
        return ""


def normalize_text(value: str) -> str:
    return (value or "").replace("\\/", "/").replace("\\.", ".").replace("&#x20;", " ")


def extract_uris(text: str) -> list[str]:
    return [u for u in (m.rstrip(",;.)]}") for m in URI_PATTERN.findall(normalize_text(text))) if u]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_ipv6(host: str) -> bool:
    return ":" in host


@lru_cache(maxsize=None)
def is_cloudflare(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in CLOUDFLARE_NETS)


def valid_host(host: str) -> bool:
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return all(HOST_LABEL.fullmatch(label) for label in host.split("."))


def decode_ss_userinfo(value: str) -> str:
    value = unquote(value)
    return value if ":" in value else decode64(value)


def parse_uri(uri: str) -> dict | None:
    uri = uri.strip()
    scheme = uri.partition("://")[0].lower()
    if scheme not in ALLOWED_SCHEMES:
        return None
    d = {"scheme": scheme, "security": "none", "net": "tcp", "sni": "", "hosthdr": "",
         "path": "", "flow": "", "pbk": ""}
    try:
        if scheme == "vmess":
            data = json.loads(decode64(uri.split("://", 1)[1]))
            user_id = str(data.get("id", ""))
            uuid.UUID(user_id)
            host, port = str(data.get("add", "")), int(str(data.get("port", "")))
            d.update(
                identity=user_id.lower(),
                security="tls" if str(data.get("tls", "")).lower() == "tls" else "none",
                net=str(data.get("net") or "tcp").lower(),
                sni=str(data.get("sni") or ""), hosthdr=str(data.get("host") or ""),
                path=str(data.get("path") or ""),
            )
        elif scheme == "ss":
            body = uri.split("://", 1)[1].split("#", 1)[0]
            if "?" in body:
                body, query = body.split("?", 1)
                if "plugin" in query.lower():
                    return None  # plugin-based ss needs extra client support
            body = body.rstrip("/")
            if "@" in body:
                userinfo, address = body.rsplit("@", 1)
            else:
                decoded = decode64(body)
                if "@" not in decoded:
                    return None
                userinfo, address = decoded.rsplit("@", 1)
            host, port_text = address.rsplit(":", 1)
            method, _, password = decode_ss_userinfo(userinfo).partition(":")
            if not password or method.lower() not in SS_METHODS:
                return None
            port = int(port_text.strip("/"))
            d["identity"] = f"{method.lower()}:{password}"
        else:
            parsed = urlparse(uri)
            host, port = parsed.hostname or "", parsed.port
            identity = unquote(parsed.username or "")
            if not host or not identity or port is None:
                return None
            if scheme == "vless":
                uuid.UUID(identity)
            q = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
            d.update(
                identity=identity,
                security=q.get("security", "").lower() or ("tls" if scheme == "trojan" else "none"),
                net=q.get("type", "").lower() or "tcp",
                sni=q.get("sni") or q.get("peer") or "", hosthdr=q.get("host", ""),
                path=q.get("path") or q.get("serviceName") or "",
                flow=q.get("flow", "").lower(), pbk=q.get("pbk", ""),
            )
        host = host.strip().strip("[]").lower().rstrip(".")
        if not valid_host(host) or not 1 <= port <= 65535:
            return None
        if d["net"] == "raw":
            d["net"] = "tcp"
        d.update(host=host, port=port)
        return d
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        return None


def acceptable(d: dict) -> bool:
    sec, scheme = d["security"], d["scheme"]
    if d["port"] in BLOCKED_PORTS or sec not in {"none", "tls", "reality"}:
        return False
    if d["net"] not in ALLOWED_NETS:
        return False
    if is_ipv6(d["host"]) and not INCLUDE_IPV6:
        return False
    if sec == "none" and (scheme == "trojan" or (scheme == "vless" and not KEEP_PLAIN_VLESS)):
        return False
    if sec == "reality" and not (d["pbk"] and d["sni"]):
        return False
    return True


def fingerprint(d: dict) -> str:
    key = "|".join(str(d[k]) for k in (
        "scheme", "identity", "host", "port", "security", "net", "sni", "hosthdr", "path", "flow"))
    return hashlib.sha256(key.encode()).hexdigest()


def iran_score(d: dict) -> int:
    """Heuristic: what the Iranian collectors and iboxz lists have in common.

    TLS/Reality on CDN-friendly ports, ws/grpc transport, real SNI/Host,
    domain- or Cloudflare-fronted endpoints, VLESS first.
    """
    sec, net, port = d["security"], d["net"], d["port"]
    domain = not is_ip(d["host"])
    cf = is_cloudflare(d["host"])
    score = {"vless": 10, "trojan": 9, "vmess": 7, "ss": 5}[d["scheme"]]
    score += {"reality": 5, "tls": 9}.get(sec, 0)  # reality weight lowered: reports of fast RST after its handshake
    score += {"ws": 8, "grpc": 8, "xhttp": 6, "splithttp": 6, "httpupgrade": 5, "h2": 5}.get(net, 4)
    score += 4 * (domain or cf) + 4 * cf
    if sec != "none" and (d["sni"] or d["hosthdr"]):
        score += 3
    elif sec == "tls" and not domain:
        score -= 4
    if d["hosthdr"] and d["sni"] and d["hosthdr"].lower() == d["sni"].lower():
        score += 2
    if net == "ws" and d["path"] not in ("", "/"):
        score += 1
    if sec != "none" and port in CF_PORTS_TLS:
        score += 3
    elif sec == "none" and port in CF_PORTS_PLAIN:
        score += 1
    if d["flow"] == "xtls-rprx-vision":
        score += 4
    return score


def make_entry(uri: str) -> dict | None:
    d = parse_uri(uri)
    if d is None or not acceptable(d):
        return None
    return {"uri": uri.split("#", 1)[0].strip(), "d": d, "fp": fingerprint(d), "score": iran_score(d)}


def render(uri: str) -> str:
    return uri.split("#", 1)[0].strip() + "#" + REMARK


# ----------------------------------------------------------------------------
# Fetch
# ----------------------------------------------------------------------------
def normalized_sources(values: Iterable[str]) -> list[str]:
    result, seen = [], set()
    for value in values:
        url = value.strip().split("#", 1)[0]
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc and url not in seen:
            seen.add(url)
            result.append(url)
    return result


def fetch_source(url: str) -> list[str]:
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "nukcrow-collector/2.0", "Accept": "*/*"})
            with urlopen(request, timeout=FETCH_TIMEOUT) as response:
                if response.status != 200:
                    continue
                charset = response.headers.get_content_charset() or "utf-8"
                text = normalize_text(response.read(MAX_FETCH_BYTES).decode(charset, "replace"))
            uris = extract_uris(text) or extract_uris(decode64(text))
            uris = uris[:MAX_PER_SOURCE]
            print(f"[FETCH] {url} -> {len(uris)}")
            return uris
        except HTTPError as exc:
            if exc.code in (404, 410):
                print(f"[FETCH-ERROR] {url} -> {exc.code}")
                return []
        except (URLError, OSError) as exc:
            if attempt == 2:
                print(f"[FETCH-ERROR] {url} -> {exc}")
        time.sleep(0.4 * (attempt + 1))
    return []


def collect_sources(sources: Iterable[str]) -> list[dict]:
    sources = normalized_sources(sources)
    print(f"[SOURCE] usable sources = {len(sources)}")
    entries: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {pool.submit(fetch_source, src): src for src in sources}
        for future in as_completed(futures):
            prio = futures[future] in PRIORITY_SOURCES
            try:
                uris = future.result()
            except Exception as exc:  # one bad source must not stop the rest
                print(f"[SOURCE-ERROR] {exc}")
                continue
            for uri in uris:
                entry = make_entry(uri)
                if not entry:
                    continue
                if prio:
                    entry["score"] += PRIORITY_BONUS
                old = entries.get(entry["fp"])
                if old is None:
                    if len(entries) < MAX_CANDIDATES:
                        entries[entry["fp"]] = entry
                elif entry["score"] > old["score"]:
                    entries[entry["fp"]] = entry
    print(f"[COLLECT] accepted unique configs = {len(entries)}")
    return list(entries.values())


# ----------------------------------------------------------------------------
# Testing
# ----------------------------------------------------------------------------
def ws_frame(data: bytes) -> bytes:
    mask = os.urandom(4)
    n = len(data)
    head = b"\x82" + (bytes([0x80 | n]) if n < 126 else b"\xfe" + struct.pack(">H", n))
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def ws_parse(buf: bytes) -> tuple[int, bytes, int] | None:
    if len(buf) < 2:
        return None
    n, hdr = buf[1] & 0x7F, 2
    if n == 126:
        if len(buf) < 4:
            return None
        n, hdr = int.from_bytes(buf[2:4], "big"), 4
    elif n == 127:
        if len(buf) < 10:
            return None
        n, hdr = int.from_bytes(buf[2:10], "big"), 10
    if len(buf) < hdr + n:
        return None
    return buf[0] & 0x0F, buf[hdr:hdr + n], hdr + n


def e2e_capable(d: dict) -> bool:
    return (d["scheme"] in ("vless", "trojan") and d["net"] in ("ws", "tcp")
            and d["security"] == "tls" and not d["flow"])


def e2e_request(d: dict) -> bytes:
    host = E2E_HOST.encode()
    payload = (f"GET {E2E_PATH} HTTP/1.1\r\nHost: {E2E_HOST}\r\n"
               "User-Agent: curl/8.5\r\nConnection: close\r\n\r\n").encode()
    if d["scheme"] == "vless":  # ver, uuid, no addons, TCP, port 80, domain
        return (b"\x00" + uuid.UUID(d["identity"]).bytes + b"\x00\x01" + struct.pack(">H", 80)
                + b"\x02" + bytes([len(host)]) + host + payload)
    password = hashlib.sha224(d["identity"].encode()).hexdigest().encode()
    return (password + b"\r\n\x01\x03" + bytes([len(host)]) + host + struct.pack(">H", 80)
            + b"\r\n" + payload)


def read_e2e(stream, d: dict, buf: bytes, deadline: float) -> bytes:
    data, ws = b"", d["net"] == "ws"
    while time.perf_counter() < deadline and len(data) < 4096:
        if ws:
            while (frame := ws_parse(buf)) is not None:
                op, payload, used = frame
                buf = buf[used:]
                if op == 8:
                    return data
                if op in (0, 1, 2):
                    data += payload
        else:
            data, buf = data + buf, b""
        if b"HTTP/1" in data:
            break
        stream.settimeout(max(0.2, deadline - time.perf_counter()))
        chunk = stream.recv(4096)
        if not chunk:
            break
        buf += chunk
    return data


def open_stream(sock: socket.socket, d: dict):
    """TLS (if any) + WebSocket upgrade (if ws). Returns (stream, leftover) or (stream, None)."""
    sock.settimeout(PROBE_TIMEOUT)
    stream = sock
    if d["security"] in ("tls", "reality"):
        name = d["sni"] or d["hosthdr"] or (None if is_ip(d["host"]) else d["host"])
        stream = TLS_CTX.wrap_socket(sock, server_hostname=name)
    if d["net"] != "ws":
        return stream, b""
    path = d["path"] if d["path"].startswith("/") else "/" + d["path"]
    stream.sendall((
        f"GET {quote(path, safe='/?&=:%@+,;-._~!$()*')} HTTP/1.1\r\n"
        f"Host: {d['hosthdr'] or d['sni'] or d['host']}\r\n"
        "User-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = stream.recv(2048)
        if not chunk:
            break
        buf += chunk
    head, _, leftover = buf.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0]
    ok = b" 101" in line if WS_STRICT else line.startswith(b"HTTP/")
    return stream, (leftover if ok else None)


def test_entry(entry: dict) -> tuple[float, float | None, bool | None] | None:
    """Returns None (TCP failed) or (tcp_ms, probe_ms | None, e2e_ok | None)."""
    d = entry["d"]
    start = time.perf_counter()
    try:
        sock = socket.create_connection((d["host"], d["port"]), timeout=TCP_TIMEOUT)
    except OSError:
        return None
    tcp_ms = (time.perf_counter() - start) * 1000
    if not PROBE_ENABLED:
        sock.close()
        return tcp_ms, tcp_ms, None
    stream, probe_ms, attempted = sock, None, False
    try:
        stream, leftover = open_stream(sock, d)
        if leftover is None:
            return tcp_ms, None, None
        probe_ms = (time.perf_counter() - start) * 1000
        if not (E2E_ENABLED and e2e_capable(d)):
            return tcp_ms, probe_ms, None
        attempted = True
        request = e2e_request(d)
        stream.sendall(ws_frame(request) if d["net"] == "ws" else request)
        data = read_e2e(stream, d, leftover, time.perf_counter() + E2E_TIMEOUT)
        ok = b"HTTP/1" in data and (d["scheme"] != "vless" or data[:1] == b"\x00")
        return tcp_ms, probe_ms, ok
    except (OSError, ValueError):  # ssl.SSLError is an OSError; bad IDNA is a ValueError
        return tcp_ms, probe_ms, (False if attempted else None) if probe_ms is not None else None
    finally:
        stream.close()
        sock.close()


def benchmark(entries: list[dict]) -> list[dict]:
    """Adds 'tier' and 'lat'. Tier 0 = proxied end-to-end, 1 = TLS/WS verified, 3 = TCP only."""
    todo = sorted((e for e in entries if e["fp"] not in TEST_CACHE), key=lambda e: -e["score"])[:MAX_TEST]
    print(f"[TEST] testing {len(todo)} configs (TCP{' + TLS/WS + e2e' if PROBE_ENABLED else ''})")
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {pool.submit(test_entry, e): e for e in todo}
        for count, future in enumerate(as_completed(futures), 1):
            TEST_CACHE[futures[future]["fp"]] = future.result()
            if count % 1000 == 0:
                print(f"[TEST] {count}/{len(todo)}")
    out = []
    for e in entries:
        r = TEST_CACHE.get(e["fp"])
        if not r:
            continue
        tcp_ms, probe_ms, e2e = r
        if probe_ms is not None and e2e is not False:
            out.append({**e, "tier": 0 if e2e else 1, "lat": probe_ms})
        else:
            out.append({**e, "tier": 3, "lat": tcp_ms})
    tiers = Counter(e["tier"] for e in out)
    print(f"[TEST] tcp ok = {len(out)}, e2e ok = {tiers[0]}, tls/ws ok = {tiers[1]}, weak = {tiers[3]}")
    if PROBE_ENABLED and out and (tiers[0] + tiers[1]) * 50 < len(out):
        print("[WARN] probe pass rate under 2%; treating all TCP-reachable configs as tier 1")
        return [{**e, "tier": 1} for e in out]
    return out


# ----------------------------------------------------------------------------
# Selection
# ----------------------------------------------------------------------------
def host_key(e: dict) -> str:
    d = e["d"]
    if is_cloudflare(d["host"]):
        return f"{d['host']}|{(d['hosthdr'] or d['sni']).lower()}"
    return d["host"]


def net_key(e: dict) -> str:
    host = e["d"]["host"]
    if is_cloudflare(host):
        return host_key(e)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return str(ipaddress.ip_network(f"{host}/{24 if ip.version == 4 else 64}", strict=False))


def select_diverse(entries: list[dict], limit: int) -> list[str]:
    """Best tier first; inside a tier every port is spread proportionally."""
    max_tier = 3 if FILL_TO_FULL else 1
    hosts, nets, ports = Counter(), Counter(), Counter()
    result: list[str] = []
    summary = {}

    def port_cap(port: int) -> int:
        return max(1, int(limit * (PORT_443_SHARE if port == 443 else OTHER_PORT_SHARE)))

    for tier in (0, 1, 3):
        if tier > max_tier or len(result) >= limit:
            continue
        ranked = sorted((e for e in entries if e["tier"] == tier),
                        key=lambda e: (-e["score"], round(e["lat"] / 150), e["fp"]))
        chosen: list[dict] = []
        deferred: list[dict] = []

        def take(e: dict) -> None:
            hk, nk = host_key(e), net_key(e)
            if hosts[hk] < MAX_PER_HOST and nets[nk] < MAX_PER_SUBNET:
                hosts[hk] += 1
                nets[nk] += 1
                ports[e["d"]["port"]] += 1
                chosen.append(e)

        room = limit - len(result)
        for e in ranked:  # pass 1: respect per-port caps
            if len(chosen) >= room:
                break
            if ports[e["d"]["port"]] >= port_cap(e["d"]["port"]):
                deferred.append(e)
            else:
                take(e)
        for e in deferred:  # pass 2: relax port caps only if still short
            if len(chosen) >= room:
                break
            take(e)

        totals = Counter(e["d"]["port"] for e in chosen)
        seen: Counter = Counter()
        keyed = []
        for e in chosen:
            port = e["d"]["port"]
            keyed.append(((seen[port] + 0.5) / totals[port], port, e["uri"]))
            seen[port] += 1
        keyed.sort()
        result.extend(uri for _, _, uri in keyed)
        summary[tier] = len(keyed)
    print(f"[SELECT] {len(result)}/{limit} selected; by tier {summary}; top ports {ports.most_common(6)}")
    return result


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
def prepare_output_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    expected = {name for name, _ in SUBS} | {"bot.txt"}
    for path in OUT_DIR.glob("*.txt"):
        if path.name not in expected:
            path.unlink()
            print(f"[REMOVE] {path.name}")


def write_configs(filename: str, configs: list[str]) -> None:
    rendered = [render(uri) for uri in configs]
    (OUT_DIR / filename).write_text("\n".join(rendered) + ("\n" if rendered else ""), encoding="utf-8")
    print(f"[WRITE] {filename} = {len(rendered)}")


def write_subscriptions(selected: list[str]) -> None:
    # Best configs go to sub1 first. If fewer than TOTAL_CONFIGS survive, shrink every
    # file proportionally so no subscription is left empty.
    ratio = min(1.0, len(selected) / TOTAL_CONFIGS)
    offset = 0
    for filename, size in SUBS:
        count = max(1, int(size * ratio)) if selected else 0
        write_configs(filename, selected[offset:offset + count])
        offset += count


def write_bot() -> None:
    entries = benchmark(collect_sources(BOT_SOURCES)) if BOT_SOURCES else []
    write_configs("bot.txt", select_diverse(entries, BOT_MAX_CONFIGS) if entries else [])


def verify_outputs() -> None:
    sizes = dict(SUBS)
    actual = {path.name for path in OUT_DIR.glob("*.txt")}
    if actual != set(sizes) | {"bot.txt"}:
        raise RuntimeError(f"Unexpected output files: {sorted(actual)}")
    seen, total = set(), 0
    for filename, size in sizes.items():
        lines = (OUT_DIR / filename).read_text(encoding="utf-8").splitlines()
        if len(lines) > size:
            raise RuntimeError(f"{filename}: {len(lines)} lines, limit {size}")
        for line in lines:
            if not line.endswith("#" + REMARK):
                raise RuntimeError(f"{filename} has an incorrect remark.")
            entry = make_entry(line)
            token = entry["fp"] if entry else line
            if token in seen:
                raise RuntimeError(f"Duplicate config across subscriptions: {filename}")
            seen.add(token)
        total += len(lines)
    bot_lines = (OUT_DIR / "bot.txt").read_text(encoding="utf-8").splitlines()
    if len(bot_lines) > BOT_MAX_CONFIGS:
        raise RuntimeError("bot.txt exceeds its cap.")
    print(f"[VERIFY] general = {total}/{TOTAL_CONFIGS}, bot = {len(bot_lines)}/{BOT_MAX_CONFIGS}")


def main() -> None:
    print(f"nukcrow collector: up to {TOTAL_CONFIGS} configs across 20 subscriptions + bot.txt")
    prepare_output_dir()
    entries = benchmark(collect_sources(RAW_SOURCES))
    write_subscriptions(select_diverse(entries, TOTAL_CONFIGS))
    write_bot()
    verify_outputs()
    print("DONE")


if __name__ == "__main__":
    main()
