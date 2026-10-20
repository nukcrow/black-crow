from pathlib import Path

code = r'''#!/usr/bin/env python3
"""NUKCROW simple public V2Ray config collector.

Fetches public subscription/config lists, decodes Base64 lists, extracts VLESS,
VMess, Trojan and Shadowsocks URIs, deduplicates, checks basic TCP reachability,
and writes sub1.txt..sub20.txt plus bot.txt under sub/general.

Important: TCP reachability is not a full protocol/proxy test and does not prove
that a config works from a particular Iranian ISP. Public configs are untrusted.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import socket
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

OUT = Path("sub/general")
REMARK = "nukcrow"
MAX_BYTES = 12_000_000
FETCH_TIMEOUT = 12
TCP_TIMEOUT = 2.0
FETCH_WORKERS = 24
TEST_WORKERS = 160
MAX_PER_SOURCE = 50000
PER_SUB = 2000
BOT_SIZE = 2000
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
PORT_ORDER = [443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880, 2052, 2082, 2086, 2095, 433]
# First 14 files target the listed real ports. Files 15-20 are general diversity pools.
SUB_PORTS = {i + 1: p for i, p in enumerate(PORT_ORDER)}

GH = "https://raw.githubusercontent.com/"
# 50 public source endpoints. Some may move or return 404; the collector skips failures.
SOURCE_PATHS = [
    "sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt",
    "sakha1370/OpenRay/refs/heads/main/output_iran/mci_top100.txt",
    "sakha1370/OpenRay/refs/heads/main/output_iran/irancell_top100.txt",
    "sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt",
    "sakha1370/OpenRay/refs/heads/main/output/kind/trojan.txt",
    "sakha1370/OpenRay/main/output/all_valid_proxies.txt",
    "iboxz/free-v2ray-collector/main/main/mix.txt",
    "iboxz/free-v2ray-collector/main/main/vless",
    "iboxz/free-v2ray-collector/main/main/vmess",
    "iboxz/free-v2ray-collector/main/main/trojan",
    "youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "MhdiTaheri/V2rayCollector/main/sub/mix",
    "MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "mehrtat/vless-collector/main/vless.txt",
    "Arefgh72/v2ray-proxy-pars-tester/main/output/github_all.txt",
    "Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt",
    "coldwater-10/V2ray-Config/main/Sub7.txt",
    "snaCW/Config/main/config.txt",
    "Danialsamadi/v2go/main/AllConfigsSub.txt",
    "10ium/V2Hub3/main/merged_base64",
    "MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
    "F0rc3Run/F0rc3Run/main/splitted-by-protocol/vmess.txt",
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
    "SoliSpirit/v2ray-configs/main/all_configs.txt",
    "SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_001.txt",
    "Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt",
    "liMilCo/v2r/main/configs.txt",
    "Argh94/Proxy-List/refs/heads/main/All_Config.txt",
    "morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "morpheusadam/v2ray-config/main/subs/bundles/best.txt",
]
SOURCES = [GH + p for p in SOURCE_PATHS]
IRAN_FIRST = set(SOURCES[:3])

URI_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>\"']+", re.I)
def decode64(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    if not s:
        return ""
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:
        return ""

def extract(text: str) -> list[str]:
    text = (text or "").replace("\\/", "/").replace("\\.", ".")
    found = [m.rstrip(",;.)]}") for m in URI_RE.findall(text)]
    if found:
        return found
    decoded = decode64(text)
    if decoded and decoded != text:
        return [m.rstrip(",;.)]}") for m in URI_RE.findall(decoded)]
    return []

def endpoint(uri: str):
    """Return (host, port, fingerprint, scheme) for basic checks."""
    raw = uri.split("#", 1)[0].strip()
    scheme = raw.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            payload = decode64(raw.split("://", 1)[1])
            obj = json.loads(payload)
            host, port = str(obj.get("add", "")), int(obj.get("port", 0))
        elif scheme == "ss":
            body = raw.split("://", 1)[1].split("?", 1)[0].rstrip("/")
            if "@" not in body:
                body = decode64(body)
            address = body.rsplit("@", 1)[-1]
            host, p = address.rsplit(":", 1)
            host, port = host.strip("[]"), int(p)
        else:
            u = urlparse(raw)
            host, port = u.hostname or "", u.port
        if not host or not port or not (1 <= int(port) <= 65535):
            return None
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if not ip.is_global:
                return None
        except ValueError:
            if "." not in host or len(host) > 253 or any(c.isspace() for c in host):
                return None
        fp = hashlib.sha256(raw.encode()).hexdigest()
        return host.strip("[]"), int(port), fp, scheme
    except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError):
        return None

def fetch(url: str) -> tuple[str, list[str]]:
    try:
        req = Request(url, headers={"User-Agent": "nukcrow-collector/3.0", "Accept": "*/*"})
        with urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            if resp.status != 200:
                return url, []
            data = resp.read(MAX_BYTES).decode("utf-8", "replace")
        items = extract(data)
        if not items:
            items = extract(decode64(data))
        print(f"[FETCH] {url} -> {len(items)}")
        return url, items[:MAX_PER_SOURCE]
    except Exception as exc:
        print(f"[SKIP] {url} ({type(exc).__name__})")
        return url, []

def tcp_test(item: dict) -> tuple[str, bool, float]:
    start = time.monotonic()
    try:
        with socket.create_connection((item["host"], item["port"]), timeout=TCP_TIMEOUT):
            return item["fp"], True, (time.monotonic() - start) * 1000
    except OSError:
        return item["fp"], False, 999999.0

def collect() -> list[dict]:
    unique: dict[str, dict] = {}
    votes: dict[str, set[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = [pool.submit(fetch, s) for s in dict.fromkeys(SOURCES)]
        for fut in concurrent.futures.as_completed(futures):
            source, uris = fut.result()
            repo = "/".join(urlparse(source).path.strip("/").split("/")[:2]).lower()
            for uri in uris:
                parsed = endpoint(uri)
                if not parsed:
                    continue
                host, port, fp, scheme = parsed
                item = {"uri": uri.split("#", 1)[0], "host": host, "port": port,
                        "fp": fp, "scheme": scheme, "priority": source in IRAN_FIRST}
                votes.setdefault(fp, set()).add(repo)
                old = unique.get(fp)
                if old is None or (item["priority"] and not old["priority"]):
                    unique[fp] = item
    for item in unique.values():
        item["score"] = (100 if item["priority"] else 0) + min(15, len(votes[item["fp"]]) * 3)
    candidates = sorted(unique.values(), key=lambda x: (-x["score"], x["port"], x["fp"]))
    # Test at most 12,000 best candidates to keep runs practical.
    candidates = candidates[:12000]
    print(f"[COLLECT] unique candidates = {len(candidates)}")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = [pool.submit(tcp_test, item) for item in candidates]
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            fp, ok, ms = fut.result()
            results[fp] = (ok, ms)
            if i % 1000 == 0:
                print(f"[TEST] {i}/{len(futures)}")
    for item in candidates:
        ok, ms = results.get(item["fp"], (False, 999999))
        item["tcp_ok"], item["latency"] = ok, ms
    # Prefer TCP-reachable nodes; keep some untested/unreachable candidates only as last-resort fill.
    candidates.sort(key=lambda x: (not x["tcp_ok"], -x["score"], x["latency"], x["fp"]))
    print(f"[TEST] TCP reachable = {sum(1 for x in candidates if x['tcp_ok'])}/{len(candidates)}")
    return candidates

def render(item: dict) -> str:
    return item["uri"].split("#", 1)[0] + "#" + REMARK

def write_file(name: str, items: list[dict]) -> None:
    path = OUT / name
    path.write_text("".join(render(x) + "\n" for x in items), encoding="utf-8")
    print(f"[WRITE] {name}: {len(items)}")

def choose(items: list[dict], limit: int, used: set[str], port: int | None = None) -> list[dict]:
    pool = [x for x in items if x["fp"] not in used and (port is None or x["port"] == port)]
    # Limit repeated hostnames so one server family does not dominate.
    out, hosts = [], Counter()
    for item in pool:
        host_key = item["host"].lower()
        if hosts[host_key] >= 8:
            continue
        out.append(item)
        used.add(item["fp"])
        hosts[host_key] += 1
        if len(out) >= limit:
            break
    # If a target-port file is short, don't fake ports; keep it short.
    return out

def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    items = collect()
    used: set[str] = set()
    for i in range(1, 21):
        port = SUB_PORTS.get(i) if i <= 14 else None
        picked = choose(items, PER_SUB, used, port)
        write_file(f"sub{i}.txt", picked)
        if port is not None and len(picked) < PER_SUB:
            print(f"[WARN] sub{i}.txt port {port}: only {len(picked)} valid unique configs")
    # Bot pool prioritizes Iran-checked source items, then remaining high-ranked items.
    bot_items = sorted(items, key=lambda x: (not x["priority"], not x["tcp_ok"], -x["score"], x["latency"]))
    bot: list[dict] = []
    bot_hosts = Counter()
    for item in bot_items:
        if bot_hosts[item["host"].lower()] >= 8:
            continue
        bot.append(item)
        bot_hosts[item["host"].lower()] += 1
        if len(bot) >= BOT_SIZE:
            break
    write_file("bot.txt", bot)
    print(f"[DONE] subscriptions written to {OUT.resolve()}")
    print("[NOTE] TCP success is not a full V2Ray protocol test.")

if __name__ == "__main__":
    main()
'''
path = Path("/mnt/data/nukcrow_collector.py")
path.write_text(code, encoding="utf-8")
print(f"Created {path} ({len(code.splitlines())} lines)")
