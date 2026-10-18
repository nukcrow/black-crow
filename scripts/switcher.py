#!/usr/bin/env python3
"""nukcrow configuration collector (tuned for Irancell / MCI).

Writes only sub1.txt ... sub20.txt and bot.txt under sub/general.

Pipeline: fetch -> parse/filter -> score (Iran profile) -> TCP + TLS/WS probe
-> real end-to-end proxy test (VLESS/Trojan over ws/tcp+TLS, plain VLESS over ws)
-> tiered, diversity-capped selection -> write.

NOTE: tests run from the GitHub runner, outside Iran. They prove the server is
alive and speaks TLS / WebSocket on the given path; they cannot prove it is
reachable from a specific Iranian ISP. The Iran profile (scoring + caps) is a
heuristic derived from an analysis of 17 Iranian collector files (~25k configs):
host overlap between sources, scheme/security/transport mix, ports and SNIs, and
the OpenRay lists that are checked from inside Iran.
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

# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
OUT_DIR = Path("sub/general")
REMARK = "nukcrow"

# 20 general subscriptions, 2,000 configs each (40,000 max).
SUBS = tuple((f"sub{i}.txt", 2000) for i in range(1, 21))
TOTAL_CONFIGS = sum(size for _, size in SUBS)
BOT_MAX_CONFIGS = 2000  # bot.txt target (filled from every tier; a warning is printed if short)

# ----------------------------------------------------------------------------
# Network / performance
# ----------------------------------------------------------------------------
FETCH_TIMEOUT = 15
FETCH_WORKERS = 32
MAX_FETCH_BYTES = 12_000_000
TCP_TIMEOUT = 2.5
PROBE_TIMEOUT = 4.0
E2E_TIMEOUT = 5.0
TEST_WORKERS = 500
MAX_PER_SOURCE = 50_000
MAX_CANDIDATES = 200_000    # unique parsed candidates kept
MAX_TEST = 120_000          # best-scored candidates actually tested

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
PLAIN_VLESS_WS = True      # plain vless is kept only as ws on Cloudflare plain ports (~34% of cross-source consensus)
INCLUDE_IPV6 = False       # runner has no IPv6, so these cannot be tested; set True to pass them untested
PROBE_ENABLED = True       # TLS handshake (+ WebSocket upgrade) on top of TCP connect
E2E_ENABLED = True         # real VLESS/Trojan request through the proxy (ws or tcp + TLS, plain vless ws, no flow)
E2E_HOST = "connectivitycheck.gstatic.com"  # non-Cloudflare target (Workers cannot reach CF IPs)
E2E_PATH = "/generate_204"
FILL_TO_FULL = True        # top up with weaker tiers (probe/e2e failed, TCP ok) when verified ones run short
PRIORITY_BONUS = 40        # score bonus for configs that come from Iran-checked lists
CONSENSUS_MIN = 3          # host listed by this many independent collectors (mirrors collapsed) ...
CONSENSUS_BONUS = 8        # ... gets this score bonus
BONUS_PORTS = {23576, 8388}  # common non-standard reality / ss ports across collectors and Iran-checked data
BONUS_PORT_SCORE = 3
COMMON_SNI = {
    "google.com", "www.google.com", "play.google.com", "yahoo.com", "www.cloudflare.com",
    "aws.amazon.com", "www.amazon.com", "www.microsoft.com", "www.speedtest.net", "speedtest.net",
    "bmi.ir", "telewebion.com", "deepl.com", "api-maps.yandex.ru", "www.mozilla.org",
    "addons.mozilla.org",
}
COMMON_SNI_SCORE = 2
# Mirror/aggregator repos copy each other (e.g. limilco <-> SoliSpirit share ~6,000 identical configs),
# so together they count as ONE vote in the consensus bonus.
AGGREGATORS = {
    "limilco/v2r", "solispirit/v2ray-configs", "epodonios/v2ray-configs", "barry-far/v2ray-config",
    "mheidari98/.proxy", "matinghanbari/v2ray-configs", "leon406/subcrawler",
    "delta-kronecker/v2ray-config", "argh94/proxy-list", "roosterkid/openproxylist",
    "wuqb2i4f/xray-config-toolkit",
}
# (scheme, security, net) families that dominate configs shared by 2+ repos
FAMILY_BONUS = {
    ("vless", "tls", "ws"): 3, ("vless", "reality", "tcp"): 3, ("vless", "none", "ws"): 1,
    ("vless", "tls", "tcp"): 1, ("vmess", "tls", "ws"): 2, ("vmess", "none", "ws"): 1,
    ("vmess", "none", "tcp"): 1, ("ss", "none", "tcp"): 2, ("trojan", "tls", "tcp"): 2,
    ("trojan", "tls", "ws"): 2,
}
FAMILY_MAX_SHARE = 0.35    # max share of one output taken by a single (scheme, security, net) family
RELAX_FACTOR = 3           # last resort when still short: host/subnet caps x3 (FILL_TO_FULL)
WS_STRICT = True           # ws must answer "101 Switching Protocols"; False accepts any HTTP reply
MAX_PER_HOST = 3           # configs per host (Cloudflare IPs: per host+SNI)
MAX_PER_SUBNET = 20        # configs per /24 (IPv4) or /64 (IPv6); Cloudflare IPs exempt
PORT_SHARES = {443: 0.35, 8080: 0.15, 23576: 0.15}  # max share of one output per port
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

IRAN_CHECKED = [GH + "sakha1370/OpenRay/refs/heads/main/output_iran/" + n for n in (
    "iran_top100_checked.txt", "mci_top100.txt", "irancell_top100.txt")]
PRIORITY_SOURCES = set(IRAN_CHECKED)

BOT_SOURCES = IRAN_CHECKED + [GH + p for p in (
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
    "coldwater-10/V2ray-Config/main/Sub7.txt",
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
)]

RAW_SOURCES = IRAN_CHECKED + [GH + p for p in (
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
    "coldwater-10/V2ray-Config/main/Sub7.txt",
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
)]

URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>'\"]+", re.I)
HOST_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)

TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE

TEST_CACHE: dict[str, tuple[float, float | None, bool | None] | None] = {}


# ----------------------------------------------------------------------------
# Parsing & Helpers
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
    if sec == "none":
        if scheme == "trojan":
            return False
        if scheme == "vless" and not (PLAIN_VLESS_WS and d["net"] == "ws" and d["port"] in CF_PORTS_PLAIN):
            return False
    if sec == "reality" and not (d["pbk"] and d["sni"]):
        return False
    return True


def fingerprint(d: dict) -> str:
    key = "|".join(str(d[k]) for k in (
        "scheme", "identity", "host", "port", "security", "net", "sni", "hosthdr", "path", "flow"))
    return hashlib.sha256(key.encode()).hexdigest()


def iran_score(d: dict) -> int:
    sec, net, port = d["security"], d["net"], d["port"]
    domain = not is_ip(d["host"])
    cf = is_cloudflare(d["host"])
    score = {"vless": 10, "trojan": 9, "vmess": 7, "ss": 8}[d["scheme"]]
    score += {"reality": 8, "tls": 9}.get(sec, 0)
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
    return {"uri": uri.split("#", 1)[0].strip(), "d": d, "fp": fingerprint(d), "score": iran_score(d)}


def render(uri: str) -> str:
    return uri.split("#", 1)[0].strip() + "#" + REMARK


# ----------------------------------------------------------------------------
# Selection & Diversity Logic (Repaired & Fully Intact)
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


def family_key(e: dict) -> tuple[str, str, str]:
    d = e["d"]
    return d["scheme"], d["security"], d["net"]


def select_diverse(entries: list[dict], limit: int) -> list[str]:
    max_tier = 3 if FILL_TO_FULL else 1
    hosts, nets, ports, families = Counter(), Counter(), Counter(), Counter()
    result: list[str] = []

    def port_cap(port: int) -> int:
        return max(1, int(limit * PORT_SHARES.get(port, OTHER_PORT_SHARE)))

    family_cap = max(1, int(limit * FAMILY_MAX_SHARE))

    for tier in range(max_tier + 1):
        tier_entries = sorted([e for e in entries if e.get("tier", 1) == tier], key=lambda x: -x["score"])
        for e in tier_entries:
            if len(result) >= limit:
                break
            d = e["d"]
            h_key = host_key(e)
            n_key = net_key(e)
            p = d["port"]
            f_key = family_key(e)

            if hosts[h_key] >= MAX_PER_HOST:
                continue
            if nets[n_key] >= MAX_PER_SUBNET and not is_cloudflare(d["host"]):
                continue
            if ports[p] >= port_cap(p):
                continue
            if families[f_key] >= family_cap:
                continue

            hosts[h_key] += 1
            nets[n_key] += 1
            ports[p] += 1
            families[f_key] += 1
            result.append(render(e["uri"]))

    return result
