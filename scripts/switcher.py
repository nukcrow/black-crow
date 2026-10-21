#!/usr/bin/env python3
"""NUKCROW configuration collector.

Writes sub1.txt ... sub20.txt and bot.txt under sub/general.
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
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

OUT_DIR = Path("sub/general")
REMARK = "nukcrow"

# Optional list of configurations the user has personally confirmed working.
# Put one URI per line in this file beside switcher.py.
KNOWN_WORKING_FILE = Path("known_working_configs.txt")
KNOWN_WORKING_BONUS = 200

SUBS = tuple((f"sub{i}.txt", 2000) for i in range(1, 21))
TOTAL_CONFIGS = sum(size for _, size in SUBS)
BOT_MAX_CONFIGS = 2000

# -----------------------------------------------------------------------------
# Network / performance
# -----------------------------------------------------------------------------

FETCH_TIMEOUT = 15
FETCH_WORKERS = 32
MAX_FETCH_BYTES = 12_000_000
TCP_TIMEOUT = 2.5
PROBE_TIMEOUT = 4.0
E2E_TIMEOUT = 5.0
TEST_WORKERS = 200
MAX_PER_SOURCE = 50_000
MAX_CANDIDATES = 200_000
MAX_TEST = 120_000

# -----------------------------------------------------------------------------
# Filtering / selection
# -----------------------------------------------------------------------------

ALLOWED_SCHEMES = {"vless", "vmess", "trojan", "ss"}
ALLOWED_NETS = {
    "tcp", "ws", "grpc", "xhttp", "splithttp",
    "httpupgrade", "h2", "http",
}
SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
BLOCKED_PORTS = {22, 25, 53, 110, 143, 465, 587, 993, 995, 3306}

PLAIN_VLESS_WS = True
INCLUDE_IPV6 = False
PROBE_ENABLED = True
E2E_ENABLED = True

E2E_HOST = "connectivitycheck.gstatic.com"
E2E_PATH = "/generate_204"

FILL_TO_FULL = True
PRIORITY_BONUS = 40
CONSENSUS_MIN = 3
CONSENSUS_BONUS = 8

BONUS_PORTS = {23576, 8388}
BONUS_PORT_SCORE = 3

COMMON_SNI = {
    "google.com",
    "www.google.com",
    "play.google.com",
    "yahoo.com",
    "www.cloudflare.com",
    "aws.amazon.com",
    "www.amazon.com",
    "www.microsoft.com",
    "www.speedtest.net",
    "speedtest.net",
    "bmi.ir",
    "telewebion.com",
    "deepl.com",
    "api-maps.yandex.ru",
    "www.mozilla.org",
    "addons.mozilla.org",
}
COMMON_SNI_SCORE = 2

AGGREGATORS = {
    "limilco/v2r",
    "solispirit/v2ray-configs",
    "epodonios/v2ray-configs",
    "barry-far/v2ray-config",
    "mheidari98/.proxy",
    "matinghanbari/v2ray-configs",
    "leon406/subcrawler",
    "delta-kronecker/v2ray-config",
    "argh94/proxy-list",
    "roosterkid/openproxylist",
    "wuqb2i4f/xray-config-toolkit",
}

FAMILY_BONUS = {
    ("vless", "tls", "ws"): 3,
    ("vless", "reality", "tcp"): 3,
    ("vless", "none", "ws"): 1,
    ("vless", "tls", "tcp"): 1,
    ("vmess", "tls", "ws"): 2,
    ("vmess", "none", "ws"): 1,
    ("vmess", "none", "tcp"): 1,
    ("ss", "none", "tcp"): 2,
    ("trojan", "tls", "tcp"): 2,
    ("trojan", "tls", "ws"): 2,
}

FAMILY_MAX_SHARE = 0.35
RELAX_FACTOR = 3
WS_STRICT = True
MAX_PER_HOST = 3
MAX_PER_SUBNET = 20

# Every port gets the same share limit. No special port preference.
PORT_SHARES: dict[int, float] = {}
OTHER_PORT_SHARE = 0.10

CF_PORTS_TLS = {443, 2053, 2083, 2087, 2096, 8443}
CF_PORTS_PLAIN = {80, 8080, 8880, 2052, 2082, 2086, 2095}

CLOUDFLARE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
]

# -----------------------------------------------------------------------------
# Sources
# -----------------------------------------------------------------------------

GH = "https://raw.githubusercontent.com/"

IRAN_CHECKED = [
    GH + "sakha1370/OpenRay/refs/heads/main/output_iran/" + name
    for name in (
        "iran_top100_checked.txt",
        "mci_top100.txt",
        "irancell_top100.txt",
    )
]
PRIORITY_SOURCES = set(IRAN_CHECKED)

BOT_SOURCES = IRAN_CHECKED + [
    GH + path
    for path in (
        "iboxz/free-v2ray-collector/main/main/mix.txt",
        "youfoundamin/V2rayCollector/main/mixed_iran.txt",
        "HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
        "HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
        "HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
        "HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
        "MhdiTaheri/V2rayCollector/main/sub/mix",
        "MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
        "mehrtat/vless-collector/main/vless.txt",
        "Arefgh72/v2ray-proxy-pars-tester/main/output/github_all.txt",
        "Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
        "coldwater-10/V2Ray-Config/main/Sub7.txt",
        "snaCW/Config/main/config.txt",
        "Danialsamadi/v2go/main/AllConfigsSub.txt",
        "10ium/V2Hub3/main/merged_base64",
        "MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
        "F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
        "V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
        "sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt",
        "sakha1370/OpenRay/refs/heads/main/output/kind/trojan.txt",
        "mheidari98/.proxy/refs/heads/main/vless",
        "Surfboardv2ray/TGParse/main/splitted/mixed",
        "mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "barry-far/V2ray-config/main/All_Configs_Sub.txt",
        "SoliSpirit/v2ray-configs/main/all_configs.txt",
        "Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    )
]

RAW_SOURCES = IRAN_CHECKED + [
    GH + path
    for path in (
        "sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt",
        "sakha1370/OpenRay/refs/heads/main/output/kind/trojan.txt",
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
        "coldwater-10/V2Ray-Config/main/Sub7.txt",
        "snaCW/Config/main/config.txt",
        "iboxz/free-v2ray-collector/main/main/mix.txt",
        "iboxz/free-v2ray-collector/main/main/vless",
        "iboxz/free-v2ray-collector/main/main/vmess",
        "iboxz/free-v2ray-collector/main/main/trojan",
        "V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
        "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
        "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-vl",
        "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-vm",
        "wuqb2i4f/xray-config-toolkit/main/output/base64/mix-protocol-tr",
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
        "MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
        "MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
        "mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "10ium/V2Hub3/main/merged_base64",
        "Danialsamadi/v2go/main/AllConfigsSub.txt",
        "Surfboardv2ray/TGParse/main/splitted/mixed",
        "F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
        "F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",
        "ALIILAPRO/v2rayNG-Config/main/server.txt",
        "ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha.txt",
        "barry-far/V2ray-config/main/All_Configs_Sub.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_80.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_8443.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_2053.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_2087.txt",
        "hamedcode/port-based-v2ray-configs/main/sub/port_8080.txt",
        "Surfboardv2ray/TGParse/main/splitted/vless",
        "sevcator/5ubscrpt10n/main/protocols/vl.txt",
        "sevcator/5ubscrpt10n/main/protocols/vm.txt",
        "sevcator/5ubscrpt10n/main/protocols/ss.txt",
        "sevcator/5ubscrpt10n/main/protocols/tr.txt",
        "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/mix.txt",
    )
]

URI_PATTERN = re.compile(r"""(?:vless|vmess|trojan|ss)://[^\s<>'"]+""", re.I)
HOST_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)

TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE

TEST_CACHE: dict[str, tuple[float, float | None, bool | None] | None] = {}
# Measured TCP/TLS/WS connection latency, keyed by the fragment-free URI.
LATENCY_BY_URI: dict[str, float] = {}


# -----------------------------------------------------------------------------
# Parsing
# -----------------------------------------------------------------------------

def decode64(value: str) -> str:
    value = value.strip().replace("-", "+").replace("_", "/")
    if not value:
        return ""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode(
            "utf-8", "ignore"
        )
    except (ValueError, UnicodeDecodeError):
        return ""


def normalize_text(value: str) -> str:
    return (value or "").replace("\\/", "/").replace("\\.", ".")


def extract_uris(text: str) -> list[str]:
    return [
        item
        for item in (match.rstrip(",;.)]}") for match in URI_PATTERN.findall(normalize_text(text)))
        if item
    ]


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

    d = {
        "scheme": scheme,
        "security": "none",
        "net": "tcp",
        "sni": "",
        "hosthdr": "",
        "path": "",
        "flow": "",
        "pbk": "",
    }

    try:
        if scheme == "vmess":
            data = json.loads(decode64(uri.split("://", 1)[1]))
            user_id = str(data.get("id", ""))
            uuid.UUID(user_id)

            host = str(data.get("add", ""))
            port = int(str(data.get("port", "")))

            d.update(
                identity=user_id.lower(),
                security="tls" if str(data.get("tls", "")).lower() == "tls" else "none",
                net=str(data.get("net") or "tcp").lower(),
                sni=str(data.get("sni") or ""),
                hosthdr=str(data.get("host") or ""),
                path=str(data.get("path") or ""),
            )

        elif scheme == "ss":
            body = uri.split("://", 1)[1].split("#", 1)[0]

            if "?" in body:
                body, query = body.split("?", 1)
                if "plugin" in query.lower():
                    return None

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

            q = {
                key: value[0]
                for key, value in parse_qs(
                    parsed.query, keep_blank_values=True
                ).items()
            }

            d.update(
                identity=identity,
                security=q.get("security", "").lower()
                or ("tls" if scheme == "trojan" else "none"),
                net=q.get("type", "").lower() or "tcp",
                sni=q.get("sni") or q.get("peer") or "",
                hosthdr=q.get("host", ""),
                path=q.get("path") or q.get("serviceName") or "",
                flow=q.get("flow", "").lower(),
                pbk=q.get("pbk", ""),
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

    if sec == "none":
        if scheme == "trojan":
            return False
        if scheme == "vless" and not (
            PLAIN_VLESS_WS
            and d["net"] == "ws"
            and d["port"] in CF_PORTS_PLAIN
        ):
            return False

    if sec == "reality" and not (d["pbk"] and d["sni"]):
        return False

    return True


def fingerprint(d: dict) -> str:
    key = "|".join(
        str(d[k])
        for k in (
            "scheme", "identity", "host", "port", "security",
            "net", "sni", "hosthdr", "path", "flow",
        )
    )
    return hashlib.sha256(key.encode()).hexdigest()


def iran_score(d: dict) -> int:
    sec, net, port = d["security"], d["net"], d["port"]
    domain = not is_ip(d["host"])
    cf = is_cloudflare(d["host"])

    score = {"vless": 10, "trojan": 9, "vmess": 7, "ss": 8}[d["scheme"]]
    score += {"reality": 8, "tls": 9}.get(sec, 0)
    score += {
        "ws": 8,
        "grpc": 8,
        "xhttp": 6,
        "splithttp": 6,
        "httpupgrade": 5,
        "h2": 5,
    }.get(net, 4)

    score += 4 * (domain or cf) + 4 * cf

    # Rank Cloudflare-fronted TLS/WS candidates higher only when the URI has
    # the expected transport metadata. This is a routing heuristic, not proof
    # that the endpoint is reachable from an Iranian ISP.
    if cf and sec == "tls" and port in CF_PORTS_TLS:
        score += 4
        if net in {"ws", "grpc", "httpupgrade", "xhttp", "splithttp"}:
            score += 2
        if d["sni"] and d["hosthdr"] and d["sni"].lower() == d["hosthdr"].lower():
            score += 3
    elif cf and sec == "none" and port not in CF_PORTS_PLAIN:
        score -= 3

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

    if port in BONUS_PORTS:
        score += BONUS_PORT_SCORE

    if d["flow"] == "xtls-rprx-vision":
        score += 4

    if COMMON_SNI & {d["sni"].lower(), d["hosthdr"].lower()}:
        score += COMMON_SNI_SCORE

    score += FAMILY_BONUS.get((d["scheme"], sec, net), 0)
    return score


def make_entry(uri: str) -> dict | None:
    d = parse_uri(uri)
    if d is None or not acceptable(d):
        return None

    return {
        "uri": uri.split("#", 1)[0].strip(),
        "d": d,
        "fp": fingerprint(d),
        "score": iran_score(d),
        "known_working": False,
    }


def load_known_working_configs() -> list[dict]:
    """Load user-confirmed configs from an optional adjacent text file."""
    if not KNOWN_WORKING_FILE.is_file():
        return []

    try:
        text = KNOWN_WORKING_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[KNOWN-WORKING-ERROR] {exc}")
        return []

    entries: dict[str, dict] = {}
    for uri in extract_uris(text):
        entry = make_entry(uri)
        if entry is None:
            continue
        entry["known_working"] = True
        entry["score"] += KNOWN_WORKING_BONUS
        entries.setdefault(entry["fp"], entry)

    print(f"[KNOWN-WORKING] loaded {len(entries)} confirmed configs from {KNOWN_WORKING_FILE}")
    return list(entries.values())


def render(uri: str) -> str:
    clean = uri.split("#", 1)[0].strip()
    latency = LATENCY_BY_URI.get(clean)
    # Preserve a per-config measured latency in the URI fragment so the Worker
    # can show it in each category. This is connection latency, not ICMP ping.
    remark = f"{REMARK}-{round(latency)}ms" if latency is not None else REMARK
    return clean + "#" + remark


# -----------------------------------------------------------------------------
# Fetching
# -----------------------------------------------------------------------------

def normalized_sources(values: Iterable[str]) -> list[str]:
    result, seen = [], set()

    for value in values:
        url = value.strip().split("#", 1)[0]
        parsed = urlparse(url)

        if parsed.scheme in {"http", "https"} and parsed.netloc and url not in seen:
            seen.add(url)
            result.append(url)

    return result


def source_group(url: str) -> str:
    group = "/".join(urlparse(url).path.strip("/").split("/")[:2]).lower()
    return "aggregators" if group in AGGREGATORS else group


def fetch_source(url: str) -> list[str]:
    for attempt in range(3):
        try:
            request = Request(
                url,
                headers={
                    "User-Agent": "nukcrow-collector/2.0",
                    "Accept": "*/*",
                },
            )

            with urlopen(request, timeout=FETCH_TIMEOUT) as response:
                if response.status != 200:
                    continue

                charset = response.headers.get_content_charset() or "utf-8"
                text = normalize_text(
                    response.read(MAX_FETCH_BYTES).decode(charset, "replace")
                )

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
    host_groups: defaultdict[str, set[str]] = defaultdict(set)

    # Seed the candidate pool with configs personally confirmed by the user.
    # These remain eligible even when a remote CI runner cannot reach them.
    for entry in load_known_working_configs():
        entries[entry["fp"]] = entry

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {pool.submit(fetch_source, src): src for src in sources}

        for future in as_completed(futures):
            src = futures[future]
            priority = src in PRIORITY_SOURCES
            group = source_group(src)

            try:
                uris = future.result()
            except Exception as exc:
                print(f"[SOURCE-ERROR] {exc}")
                continue

            for uri in uris:
                entry = make_entry(uri)
                if not entry:
                    continue

                host_groups[entry["d"]["host"]].add(group)

                if priority:
                    entry["score"] += PRIORITY_BONUS

                old = entries.get(entry["fp"])

                if old is None:
                    if len(entries) < MAX_CANDIDATES:
                        entries[entry["fp"]] = entry
                else:
                    # Keep user-confirmed status when the same URI is also
                    # found in a repository; do not lose its ranking bonus.
                    if old.get("known_working"):
                        entry["known_working"] = True
                        entry["score"] += KNOWN_WORKING_BONUS
                    if entry["score"] > old["score"]:
                        entries[entry["fp"]] = entry

    consensus = 0

    for entry in entries.values():
        if len(host_groups[entry["d"]["host"]]) >= CONSENSUS_MIN:
            entry["score"] += CONSENSUS_BONUS
            consensus += 1

    print(
        f"[COLLECT] accepted unique configs = {len(entries)}, "
        f"consensus hosts boosted = {consensus}"
    )
    return list(entries.values())


# -----------------------------------------------------------------------------
# Testing
# -----------------------------------------------------------------------------

def ws_frame(data: bytes) -> bytes:
    mask = os.urandom(4)
    length = len(data)

    if length < 126:
        head = b"\x82" + bytes([0x80 | length])
    elif length < 65536:
        head = b"\x82\xfe" + struct.pack(">H", length)
    else:
        head = b"\x82\xff" + struct.pack(">Q", length)

    return head + mask + bytes(
        byte ^ mask[i % 4] for i, byte in enumerate(data)
    )


def ws_parse(buf: bytes) -> tuple[int, bytes, int] | None:
    if len(buf) < 2:
        return None

    length, header = buf[1] & 0x7F, 2

    if length == 126:
        if len(buf) < 4:
            return None
        length, header = int.from_bytes(buf[2:4], "big"), 4

    elif length == 127:
        if len(buf) < 10:
            return None
        length, header = int.from_bytes(buf[2:10], "big"), 10

    if len(buf) < header + length:
        return None

    return buf[0] & 0x0F, buf[header:header + length], header + length


def e2e_capable(d: dict) -> bool:
    if d["flow"] or d["scheme"] not in ("vless", "trojan"):
        return False

    if d["security"] == "tls":
        return d["net"] in ("ws", "tcp")

    return (
        d["security"] == "none"
        and d["scheme"] == "vless"
        and d["net"] == "ws"
    )


def e2e_request(d: dict) -> bytes:
    host = E2E_HOST.encode()
    payload = (
        f"GET {E2E_PATH} HTTP/1.1\r\n"
        f"Host: {E2E_HOST}\r\n"
        "User-Agent: curl/8.5\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    if d["scheme"] == "vless":
        return (
            b"\x00"
            + uuid.UUID(d["identity"]).bytes
            + b"\x00\x01"
            + struct.pack(">H", 80)
            + b"\x02"
            + bytes([len(host)])
            + host
            + payload
        )

    password = hashlib.sha224(d["identity"].encode()).hexdigest().encode()
    return (
        password
        + b"\r\n\x01\x03"
        + bytes([len(host)])
        + host
        + struct.pack(">H", 80)
        + b"\r\n"
        + payload
    )


def read_e2e(stream, d: dict, buf: bytes, deadline: float) -> bytes:
    data = b""
    websocket = d["net"] == "ws"

    while time.perf_counter() < deadline and len(data) < 4096:
        if websocket:
            while (frame := ws_parse(buf)) is not None:
                opcode, payload, used = frame
                buf = buf[used:]

                if opcode == 8:
                    return data

                if opcode in (0, 1, 2):
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
    sock.settimeout(PROBE_TIMEOUT)
    stream = sock

    if d["security"] in ("tls", "reality"):
        name = (
            d["sni"]
            or d["hosthdr"]
            or (None if is_ip(d["host"]) else d["host"])
        )
        stream = TLS_CTX.wrap_socket(sock, server_hostname=name)
        # Cloudflare-fronted configs must complete the TLS handshake on a
        # known TLS port to qualify for the strong TLS/WS tier.
        if is_cloudflare(d["host"]) and d["port"] not in CF_PORTS_TLS:
            stream.close()
            raise OSError("Cloudflare IP on a non-standard TLS port")

    if d["net"] != "ws":
        return stream, b""

    path = d["path"] if d["path"].startswith("/") else "/" + d["path"]

    request = (
        f"GET {quote(path, safe='/?&=:%@+,;-.~!$()*')} HTTP/1.1\r\n"
        f"Host: {d['hosthdr'] or d['sni'] or d['host']}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()

    stream.sendall(request)
    buf = b""

    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = stream.recv(2048)
        if not chunk:
            break
        buf += chunk

    head, _, leftover = buf.partition(b"\r\n\r\n")
    line = head.split(b"\r\n", 1)[0]
    ok = b" 101" in line if WS_STRICT else line.startswith(b"HTTP/")

    return stream, leftover if ok else None


def test_entry(entry: dict) -> tuple[float, float | None, bool | None] | None:
    d = entry["d"]
    start = time.perf_counter()

    try:
        sock = socket.create_connection(
            (d["host"], d["port"]),
            timeout=TCP_TIMEOUT,
        )
    except OSError:
        return None

    tcp_ms = (time.perf_counter() - start) * 1000

    if not PROBE_ENABLED:
        sock.close()
        return tcp_ms, tcp_ms, None

    stream = sock
    probe_ms = None
    attempted = False

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

        data = read_e2e(
            stream,
            d,
            leftover,
            time.perf_counter() + E2E_TIMEOUT,
        )

        ok = b"HTTP/1" in data and (
            d["scheme"] != "vless" or data[:1] == b"\x00"
        )

        return tcp_ms, probe_ms, ok

    except (OSError, ValueError):
        result = False if attempted and probe_ms is not None else None
        return tcp_ms, probe_ms, result

    finally:
        try:
            stream.close()
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def benchmark(entries: list[dict]) -> list[dict]:
    todo = sorted(
        (entry for entry in entries if entry["fp"] not in TEST_CACHE),
        key=lambda entry: -entry["score"],
    )[:MAX_TEST]

    print(
        f"[TEST] testing {len(todo)} configs "
        f"(TCP{' + TLS/WS + e2e' if PROBE_ENABLED else ''})"
    )

    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {
            pool.submit(test_entry, entry): entry
            for entry in todo
        }

        for count, future in enumerate(as_completed(futures), 1):
            try:
                TEST_CACHE[futures[future]["fp"]] = future.result()
            except Exception:
                TEST_CACHE[futures[future]["fp"]] = None

            if count % 1000 == 0:
                print(f"[TEST] {count}/{len(todo)}")

    output = []

    for entry in entries:
        result = TEST_CACHE.get(entry["fp"])
        if not result:
            if entry.get("known_working"):
                # Tier 2 means user-confirmed, but not verified from this run.
                # Do not invent a ping value for these configs.
                output.append({**entry, "tier": 2, "lat": 9999.0})
            continue

        tcp_ms, probe_ms, e2e = result

        if probe_ms is not None and e2e is True:
            tier = 0
            measured = probe_ms
        elif probe_ms is not None and e2e is False:
            tier = 2 if entry.get("known_working") else 1
            measured = probe_ms
        elif entry.get("known_working"):
            tier = 2
            measured = tcp_ms
        else:
            tier = 3
            measured = tcp_ms

        output.append({**entry, "tier": tier, "lat": measured})
        LATENCY_BY_URI[entry["uri"].split("#", 1)[0].strip()] = measured

    tiers = Counter(entry["tier"] for entry in output)

    print(
        f"[TEST] tcp ok = {len(output)}, "
        f"e2e ok = {tiers[0]}, tls/ws ok = {tiers[1]}, "
        f"user-confirmed fallback = {tiers[2]}, weak = {tiers[3]}"
    )

    if PROBE_ENABLED and output and (tiers[0] + tiers[1]) * 50 < len(output):
        print(
            "[WARN] probe pass rate under 2%; "
            "treating TCP-reachable configs as tier 1"
        )
        return [
            {**entry, "tier": 2 if entry.get("known_working") else 1}
            for entry in output
        ]

    return output


# -----------------------------------------------------------------------------
# Diverse selection
# -----------------------------------------------------------------------------

def host_key(entry: dict) -> str:
    d = entry["d"]

    if is_cloudflare(d["host"]):
        return f"{d['host']}|{(d['hosthdr'] or d['sni']).lower()}"

    return d["host"]


def net_key(entry: dict) -> str:
    host = entry["d"]["host"]

    if is_cloudflare(host):
        return host_key(entry)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host

    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{host}/{prefix}", strict=False))


def family_key(entry: dict) -> tuple[str, str, str]:
    d = entry["d"]
    return d["scheme"], d["security"], d["net"]


def select_diverse(entries: list[dict], limit: int) -> list[str]:
    """Select across tiers with equal per-port caps and relaxed fallback."""

    max_tier = 3 if FILL_TO_FULL else 1

    hosts = Counter()
    nets = Counter()
    ports = Counter()
    families = Counter()

    result: list[str] = []
    summary = {}

    # Identical cap for every port; no special 443/8080/23576 preference.
    def port_cap(port: int) -> int:
        return max(1, int(limit * OTHER_PORT_SHARE))

    family_cap = max(1, int(limit * FAMILY_MAX_SHARE))

    for tier in (0, 1, 2, 3):
        if tier > max_tier or len(result) >= limit:
            continue

        ranked = sorted(
            (entry for entry in entries if entry["tier"] == tier),
            key=lambda entry: (
                0 if entry.get("known_working") else 1,
                round(entry["lat"] / 25),
                -entry["score"],
                entry["fp"],
            ),
        )

        chosen = []
        picked = set()
        deferred = []

        def take(entry: dict, factor: int = 1) -> bool:
            hk = host_key(entry)
            nk = net_key(entry)
            port = entry["d"]["port"]

            if (
                hosts[hk] >= MAX_PER_HOST * factor
                or nets[nk] >= MAX_PER_SUBNET * factor
            ):
                return False

            hosts[hk] += 1
            nets[nk] += 1
            ports[port] += 1
            families[family_key(entry)] += 1

            chosen.append(entry)
            picked.add(entry["fp"])
            return True

        room = limit - len(result)

        # Pass 1: equal port cap and family cap.
        for entry in ranked:
            if len(chosen) >= room:
                break

            port = entry["d"]["port"]
            family = family_key(entry)

            if ports[port] >= port_cap(port) or families[family] >= family_cap:
                deferred.append(entry)
            else:
                take(entry)

        # Pass 2: relax port/family caps if necessary.
        for entry in deferred:
            if len(chosen) >= room:
                break
            take(entry)

        # Pass 3: relax host/subnet caps as a last resort.
        if FILL_TO_FULL and len(chosen) < room:
            for entry in ranked:
                if len(chosen) >= room:
                    break
                if entry["fp"] not in picked:
                    take(entry, RELAX_FACTOR)

        # Interleave ports so one port is not grouped together in the file.
        totals = Counter(entry["d"]["port"] for entry in chosen)
        seen = Counter()
        keyed = []

        for entry in chosen:
            port = entry["d"]["port"]
            keyed.append(
                ((seen[port] + 0.5) / totals[port], port, entry["uri"])
            )
            seen[port] += 1

        keyed.sort()
        result.extend(uri for _, _, uri in keyed)
        summary[tier] = len(keyed)

    print(
        f"[SELECT] {len(result)}/{limit} selected; "
        f"by tier {summary}; top ports {ports.most_common(15)}"
    )
    print(
        "[SELECT] families "
        f"{[(f'{a}/{b}/{c}', count) for (a, b, c), count in families.most_common(6)]}"
    )

    return result[:limit]


# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

def prepare_output_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    expected = {name for name, _ in SUBS} | {"bot.txt"}

    for path in OUT_DIR.glob("*.txt"):
        if path.name not in expected:
            path.unlink()
            print(f"[REMOVE] {path.name}")


def write_configs(filename: str, configs: list[str]) -> None:
    rendered = [render(uri) for uri in configs]
    path = OUT_DIR / filename

    path.write_text(
        "\n".join(rendered) + ("\n" if rendered else ""),
        encoding="utf-8",
    )

    print(f"[WRITE] {filename} = {len(rendered)}")


def write_subscriptions(selected: list[str]) -> None:
    ratio = min(1.0, len(selected) / TOTAL_CONFIGS)

    if ratio < 1.0:
        print(
            f"[WARN] only {len(selected)}/{TOTAL_CONFIGS} configs available; "
            f"subscriptions shrunk to {ratio:.0%}"
        )

    offset = 0

    for filename, size in SUBS:
        count = max(1, int(size * ratio)) if selected else 0
        write_configs(filename, selected[offset:offset + count])
        offset += count


def write_bot() -> None:
    entries = benchmark(collect_sources(BOT_SOURCES)) if BOT_SOURCES else []
    selected = select_diverse(entries, BOT_MAX_CONFIGS) if entries else []

    if len(selected) < BOT_MAX_CONFIGS:
        print(f"[WARN] bot.txt short: {len(selected)}/{BOT_MAX_CONFIGS}")

    write_configs("bot.txt", selected)


def verify_outputs() -> None:
    sizes = dict(SUBS)
    expected = set(sizes) | {"bot.txt"}
    actual = {path.name for path in OUT_DIR.glob("*.txt")}

    if actual != expected:
        raise RuntimeError(f"Unexpected output files: {sorted(actual)}")

    seen = set()
    total = 0

    for filename, size in sizes.items():
        lines = (OUT_DIR / filename).read_text(
            encoding="utf-8"
        ).splitlines()

        if len(lines) > size:
            raise RuntimeError(
                f"{filename}: {len(lines)} lines, limit {size}"
            )

        for line in lines:
            if not re.search(r"#" + re.escape(REMARK) + r"(?:-\d+ms)?$", line):
                raise RuntimeError(f"{filename} has an incorrect remark or latency tag.")

            entry = make_entry(line)
            token = entry["fp"] if entry else line

            if token in seen:
                raise RuntimeError(
                    f"Duplicate config across subscriptions: {filename}"
                )

            seen.add(token)

        total += len(lines)

    bot_lines = (OUT_DIR / "bot.txt").read_text(
        encoding="utf-8"
    ).splitlines()

    if len(bot_lines) > BOT_MAX_CONFIGS:
        raise RuntimeError("bot.txt exceeds its cap.")

    print(
        f"[VERIFY] general = {total}/{TOTAL_CONFIGS}, "
        f"bot = {len(bot_lines)}/{BOT_MAX_CONFIGS}"
    )


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main() -> None:
    print(
        f"nukcrow collector: up to {TOTAL_CONFIGS} configs "
        "across 20 subscriptions + bot.txt"
    )

    prepare_output_dir()

    entries = benchmark(collect_sources(RAW_SOURCES))
    selected = select_diverse(entries, TOTAL_CONFIGS)

    write_subscriptions(selected)
    write_bot()
    verify_outputs()

    print("DONE")


if __name__ == "__main__":
    main()
