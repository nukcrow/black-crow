import os
import re
import json
import time
import base64
import socket
import hashlib
import random
import ipaddress
import threading
from urllib.parse import urlparse, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ============================================================
# NukCrow Collector v2
# - No 443-only filtering
# - Large multi-source collection with GitHub-friendly fetching
# - Multi-stage TCP benchmark
# - Quality scoring based on the supplied sample style
# - 10 general subscription files x 1000 configs max
# - Protocol files x 100 configs max
# - Iran / Best Iran / Mix Iran / MCI / Irancell / Rightel x 100
# ============================================================

OUT_DIR = "sub/general"
os.makedirs(OUT_DIR, exist_ok=True)

REMARK = "nukcrow"
SUPPORTED = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")
PROTO_LIST = ("vless", "vmess", "trojan", "ss", "hysteria2")

# General output: 10 files, 1000 configs each.
GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10

# Protocol outputs: 100 each.
PROTOCOL_SUB_SIZE = 100

# Iran/operator outputs: 100 each.
IRAN_SUB_SIZE = 100

# Fetching GitHub/public sources. Keep this conservative; benchmark does not hit GitHub.
FETCH_WORKERS = 8
FETCH_TIMEOUT = 12
FETCH_RETRIES = 2
FETCH_JITTER = (0.05, 0.25)

# Benchmark. 80k candidates is large enough to substantially increase coverage without
# blindly opening hundreds of thousands of sockets. Increase only if the runner permits it.
MAX_TEST = 80000
TCP_WORKERS = 160
CONNECT_TIMEOUT = 1.6

# Second-stage benchmark: only the best candidates from each host/protocol bucket are
# tested again for a tighter ranking. This is deliberately capped.
SECOND_PASS_LIMIT = 18000
SECOND_PASS_WORKERS = 80
SECOND_PASS_TIMEOUT = 1.8

# Keep source diversity: don't let one noisy repository fill the entire result pool.
MAX_PER_SOURCE = 12000
MAX_PER_HOST = 8

# Preferred transports from the user's sample.
PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade", "tcp"}

BAD_HOST_HINTS = (
    "example.com", "localhost", "test", "invalid", "0.0.0.0",
    "127.0.0.1", "::1"
)

IRAN_HINTS = (
    ".ir", "iran", "iranirna", "irancell", "mci", "hamrahe",
    "rightel", "mtn", " همراه", "ایرانسل", "همراه اول", "رایتل"
)

OPERATOR_SOURCE_HINTS = {
    "mci": ("mci", "hamrahe", "mci_", "mci/", " همراه اول"),
    "irancell": ("irancell", "mtn", "mt n", "iran_"),
    "rightel": ("rightel", "ritel", "رایتل"),
}

# Public sources. Sources explicitly discovered as Iranian/operator-oriented are kept in
# separate groups so they can feed the Iran pools without requiring a fragile GeoIP lookup.
SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/top100.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/Joker-funland/V2ray-configs/main/config.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/MahsaFreeConfig/main/app/sub.txt",
]

SOURCES_IRAN = [
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ir/all.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_3.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_4.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
]

# Dedicated operator sources found in current public collector repositories. These are
# used as operator-labelled pools; they are not treated as proof that every node works
# on that operator unless the source itself is operator-specific.
SOURCES_MCI = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/MCI",
    "https://raw.githubusercontent.com/mehrdadmb2/V2ray_Sub/main/Mci.txt",
]
SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/Irancell",
    "https://raw.githubusercontent.com/mehrdadmb2/V2ray_Sub/main/Irancell.txt",
]
SOURCES_RIGHTEL = []

SOURCE_GROUPS = {
    "general": SOURCES_GENERAL,
    "iran": SOURCES_IRAN,
    "mci": SOURCES_MCI,
    "irancell": SOURCES_IRANCELL,
    "rightel": SOURCES_RIGHTEL,
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36 "
        "nukcrow-collector/2"
    ),
    "Accept": "text/plain,text/html;q=0.9,*/*;q=0.8",
    "Cache-Control": "no-cache",
}

_thread_local = threading.local()


def session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update(HEADERS)
        adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=0)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        _thread_local.session = s
    return s


def decode64(value):
    try:
        value = value.strip().replace("-", "+").replace("_", "/")
        value += "=" * (-len(value) % 4)
        raw = base64.b64decode(value, validate=False)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_payload(text):
    """Extract plain URIs from a raw list or base64 subscription."""
    if not text:
        return []

    text = text.replace("\r", "")
    found = []

    # First pass: plain lines.
    for line in text.splitlines():
        line = line.strip().strip('"\' ,')
        if line.startswith(SUPPORTED):
            found.append(line)

    # If the file is mostly base64, decode it as a whole.
    compact = "".join(text.split())
    if compact and len(compact) >= 20:
        decoded = decode64(compact)
        if decoded and decoded != text:
            for line in decoded.splitlines():
                line = line.strip().strip('"\' ,')
                if line.startswith(SUPPORTED):
                    found.append(line)

    # Also decode individual non-URI lines. This catches mixed subscriptions.
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(SUPPORTED):
            continue
        if len(line) < 20 or len(line) > 20000:
            continue
        decoded = decode64(line)
        if decoded:
            for item in decoded.splitlines():
                item = item.strip()
                if item.startswith(SUPPORTED):
                    found.append(item)

    return found


def fetch_source(url):
    for attempt in range(FETCH_RETRIES + 1):
        try:
            r = session().get(url, timeout=FETCH_TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and r.text:
                data = extract_payload(r.text)
                # Small randomized delay keeps concurrent public-source requests polite.
                time.sleep(random.uniform(*FETCH_JITTER))
                return url, data
            if r.status_code in (403, 429, 502, 503, 504):
                time.sleep((attempt + 1) * 0.8 + random.random() * 0.4)
                continue
            return url, []
        except requests.RequestException:
            time.sleep((attempt + 1) * 0.5 + random.random() * 0.3)
    return url, []


def fetch_group(urls):
    results = []
    if not urls:
        return results
    with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, len(urls))) as ex:
        futures = [ex.submit(fetch_source, u) for u in urls]
        for fut in as_completed(futures):
            try:
                url, configs = fut.result()
                if configs:
                    results.append((url, configs))
                    print(f"  + {url.split('/')[-1]}: {len(configs):,}")
            except Exception:
                pass
    return results


def fetch_all():
    by_group = {}
    for group, urls in SOURCE_GROUPS.items():
        print(f"\nFetching {group}: {len(urls)} sources")
        by_group[group] = fetch_group(urls)
    return by_group


def proto(config):
    c = config.lower()
    if c.startswith("hy2://"):
        return "hysteria2"
    for p in PROTO_LIST:
        if c.startswith(p + "://"):
            return p
    return "unknown"


def parsed(config):
    try:
        return urlparse(config)
    except Exception:
        return None


def query(config):
    try:
        return parse_qs(urlparse(config).query, keep_blank_values=True)
    except Exception:
        return {}


def q1(q, key, default=""):
    values = q.get(key)
    return values[0] if values else default


def host_port(config):
    try:
        u = urlparse(config)
        return u.hostname, u.port or 443
    except Exception:
        return None, None


def is_junk_host(host):
    if not host:
        return True
    h = host.lower().strip("[]")
    if any(bad in h for bad in BAD_HOST_HINTS):
        return True
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return True
    except ValueError:
        pass
    return False


def valid_config(config):
    try:
        p = proto(config)
        if p == "unknown":
            return False
        u = urlparse(config)
        if not u.hostname:
            return False
        if not u.port or not (1 <= u.port <= 65535):
            return False
        if is_junk_host(u.hostname):
            return False

        q = query(config)
        security = q1(q, "security")
        typ = q1(q, "type")

        # Sample-oriented sanity checks.
        if security == "reality":
            if not q1(q, "sni") or not q1(q, "pbk"):
                return False
        if security == "tls" and not q1(q, "sni"):
            return False
        if typ in {"ws", "xhttp", "httpupgrade"} and not (q1(q, "path") or q1(q, "host")):
            return False
        if typ == "grpc" and not q1(q, "serviceName"):
            # Some valid links use an empty serviceName, so don't reject them.
            pass
        return True
    except Exception:
        return False


def fingerprint(config):
    try:
        u = urlparse(config)
        q = query(config)
        normalized = {
            "proto": proto(config),
            "host": (u.hostname or "").lower(),
            "port": u.port,
            "security": q1(q, "security").lower(),
            "type": q1(q, "type").lower(),
            "sni": q1(q, "sni").lower(),
            "host_param": q1(q, "host").lower(),
            "path": q1(q, "path"),
            "service": q1(q, "serviceName"),
            "pbk": q1(q, "pbk"),
            "sid": q1(q, "sid"),
        }
        return hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    except Exception:
        return hashlib.sha256(config.encode()).hexdigest()


def dedupe(records):
    """records: list[(config, source_group, source_url)]"""
    seen = set()
    out = []
    for config, group, source_url in records:
        if not valid_config(config):
            continue
        fp = fingerprint(config)
        if fp in seen:
            continue
        seen.add(fp)
        out.append((config, group, source_url))
    return out


def source_labeled_iran(group, source_url):
    if group in {"iran", "mci", "irancell", "rightel"}:
        return True
    s = source_url.lower()
    return any(x in s for x in ("iran", "mci", "irancell", "rightel", "mtn", "mahsa"))


def looks_iran(config, group="", source_url=""):
    if source_labeled_iran(group, source_url):
        return True
    u = parsed(config)
    q = query(config)
    host = (u.hostname or "").lower() if u else ""
    sni = q1(q, "sni").lower()
    remark = unquote(config.split("#", 1)[1]).lower() if "#" in config else ""
    return any(hint in host or hint in sni or hint in remark for hint in IRAN_HINTS)


def operator_of(config, group="", source_url=""):
    source = (source_url or "").lower()
    blob = source + " " + group.lower() + " " + unquote(config.split("#", 1)[1]).lower() if "#" in config else source + " " + group.lower()
    if group == "mci" or any(x in blob for x in OPERATOR_SOURCE_HINTS["mci"]):
        return "mci"
    if group == "irancell" or any(x in blob for x in OPERATOR_SOURCE_HINTS["irancell"]):
        return "irancell"
    if group == "rightel" or any(x in blob for x in OPERATOR_SOURCE_HINTS["rightel"]):
        return "rightel"
    return ""


def quality_score(config, latency_ms):
    """Sample-oriented score. It does not claim that one protocol is universally better."""
    p = proto(config)
    q = query(config)
    u = parsed(config)
    security = q1(q, "security").lower()
    typ = q1(q, "type").lower()
    port = u.port or 443 if u else 443

    score = 1600.0
    score -= min(float(latency_ms), 2000.0) * 1.25

    # Port is NOT a hard filter. 443 is only a modest preference.
    if port == 443:
        score += 70
    elif port in {8443, 2053, 2083, 2087, 2096}:
        score += 45
    elif port in {80, 8080, 8000, 8001, 8002, 8005, 8007, 9873, 2044}:
        score += 25
    else:
        score += 5

    if security == "reality":
        score += 240
        if q1(q, "pbk"):
            score += 40
        if q1(q, "sid"):
            score += 20
        if q1(q, "fp"):
            score += 20
        if q1(q, "sni"):
            score += 20
    elif security == "tls":
        score += 150
        if q1(q, "sni"):
            score += 25
        if q1(q, "alpn"):
            score += 10
    elif security == "none":
        score -= 70

    if typ == "ws":
        score += 100
        if q1(q, "path"):
            score += 15
        if q1(q, "host"):
            score += 15
    elif typ == "grpc":
        score += 125
        if q1(q, "serviceName"):
            score += 20
    elif typ == "xhttp":
        score += 135
        if q1(q, "path"):
            score += 15
        if q1(q, "mode"):
            score += 10
    elif typ == "httpupgrade":
        score += 100
    elif typ == "tcp":
        score += 45
        if security == "reality":
            score += 35

    if p == "hysteria2":
        score += 120
        if q1(q, "obfs"):
            score += 20
    elif p == "trojan":
        score += 75
    elif p == "vless":
        score += 55
    elif p == "vmess":
        score += 25

    # Obvious low-quality indicators.
    if not q1(q, "sni") and security in {"tls", "reality"}:
        score -= 120
    if typ in {"ws", "xhttp", "httpupgrade"} and not q1(q, "path"):
        score -= 80

    return round(score, 2)


def tcp_probe(item, timeout=CONNECT_TIMEOUT):
    config, group, source_url = item
    host, port = host_port(config)
    if not host or not port:
        return None
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.perf_counter() - start) * 1000.0
        return {
            "config": config,
            "group": group,
            "source": source_url,
            "host": host,
            "port": port,
            "lat": latency,
            "score": quality_score(config, latency),
        }
    except (OSError, TimeoutError, socket.timeout):
        return None
    except Exception:
        return None


def benchmark(items):
    if not items:
        return []

    # Source diversity before probing.
    random.shuffle(items)
    trimmed = []
    source_counts = {}
    for item in items:
        source = item[2]
        if source_counts.get(source, 0) >= MAX_PER_SOURCE:
            continue
        source_counts[source] = source_counts.get(source, 0) + 1
        trimmed.append(item)
        if len(trimmed) >= MAX_TEST:
            break

    print(f"TCP pass 1 candidates: {len(trimmed):,}")
    results = []
    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futures = [ex.submit(tcp_probe, item, CONNECT_TIMEOUT) for item in trimmed]
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                result = fut.result()
                if result:
                    results.append(result)
            except Exception:
                pass
            if i % 5000 == 0:
                print(f"  tested {i:,}/{len(futures):,} | alive {len(results):,}")

    results.sort(key=lambda x: x["score"], reverse=True)

    # Second pass: limit concentration by endpoint, then retest the best candidates.
    selected = []
    host_counts = {}
    for r in results:
        key = (r["host"], r["port"])
        if host_counts.get(key, 0) >= MAX_PER_HOST:
            continue
        host_counts[key] = host_counts.get(key, 0) + 1
        selected.append(r)
        if len(selected) >= SECOND_PASS_LIMIT:
            break

    print(f"TCP pass 2 candidates: {len(selected):,}")
    final = []
    with ThreadPoolExecutor(max_workers=SECOND_PASS_WORKERS) as ex:
        futures = [ex.submit(tcp_probe, (r["config"], r["group"], r["source"]), SECOND_PASS_TIMEOUT) for r in selected]
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result:
                    final.append(result)
            except Exception:
                pass

    final.sort(key=lambda x: x["score"], reverse=True)
    return final


def clean_remark(config):
    try:
        base = config.split("#", 1)[0]
        return base + "#" + quote(REMARK, safe="")
    except Exception:
        return None


def diversity_pick(results, limit, predicate=None):
    """Pick high-scoring configs while avoiding one host taking the entire list."""
    chosen = []
    seen_fp = set()
    host_counts = {}
    proto_counts = {}

    for r in results:
        config = r["config"]
        if predicate and not predicate(r):
            continue
        fp = fingerprint(config)
        if fp in seen_fp:
            continue
        host = r["host"]
        p = proto(config)
        if host_counts.get(host, 0) >= 4:
            continue
        # Keep protocol diversity in smaller curated lists.
        if limit <= 500 and proto_counts.get(p, 0) >= max(20, limit // 2):
            continue
        seen_fp.add(fp)
        host_counts[host] = host_counts.get(host, 0) + 1
        proto_counts[p] = proto_counts.get(p, 0) + 1
        chosen.append(clean_remark(config))
        if len(chosen) >= limit:
            break
    return [x for x in chosen if x]


def write_lines(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        if lines:
            f.write("\n".join(lines))
            f.write("\n")


def clear_pattern(prefix, suffix=".txt", start=1, end=50):
    for i in range(start, end + 1):
        path = os.path.join(OUT_DIR, f"{prefix}{i}{suffix}")
        if os.path.exists(path):
            os.remove(path)


def write_general(results):
    all_lines = diversity_pick(results, GENERAL_SUB_SIZE * GENERAL_SUB_COUNT)
    write_lines(os.path.join(OUT_DIR, "all_configs.txt"), all_lines)

    clear_pattern("sub", start=1, end=GENERAL_SUB_COUNT)
    for i in range(GENERAL_SUB_COUNT):
        part = all_lines[i * GENERAL_SUB_SIZE:(i + 1) * GENERAL_SUB_SIZE]
        if not part:
            break
        write_lines(os.path.join(OUT_DIR, f"sub{i + 1}.txt"), part)
    return all_lines


def write_protocols(results):
    protocol_results = {}
    for p in PROTO_LIST:
        pool = [r for r in results if proto(r["config"]) == p]
        lines = diversity_pick(pool, PROTOCOL_SUB_SIZE)
        protocol_results[p] = lines
        write_lines(os.path.join(OUT_DIR, f"{p}.txt"), lines)
    return protocol_results


def write_iran(results):
    iran = [r for r in results if looks_iran(r["config"], r["group"], r["source"])]

    best = diversity_pick(iran, IRAN_SUB_SIZE)
    mix = diversity_pick(iran, IRAN_SUB_SIZE)

    mci = diversity_pick([r for r in iran if operator_of(r["config"], r["group"], r["source"]) == "mci"], IRAN_SUB_SIZE)
    irancell = diversity_pick([r for r in iran if operator_of(r["config"], r["group"], r["source"]) == "irancell"], IRAN_SUB_SIZE)
    rightel = diversity_pick([r for r in iran if operator_of(r["config"], r["group"], r["source"]) == "rightel"], IRAN_SUB_SIZE)

    write_lines(os.path.join(OUT_DIR, "best_iran.txt"), best)
    write_lines(os.path.join(OUT_DIR, "mix_iran.txt"), mix)
    write_lines(os.path.join(OUT_DIR, "mci.txt"), mci)
    write_lines(os.path.join(OUT_DIR, "irancell.txt"), irancell)
    write_lines(os.path.join(OUT_DIR, "rightel.txt"), rightel)

    return {
        "best_iran": best,
        "mix_iran": mix,
        "mci": mci,
        "irancell": irancell,
        "rightel": rightel,
    }


def build_records(fetched):
    records = []
    for group, sources in fetched.items():
        for source_url, configs in sources:
            # Preserve source group on every record so dedicated Iran/operator pools work.
            for config in configs:
                records.append((config.strip(), group, source_url))
    return records


def main():
    started = time.time()
    print("=" * 64)
    print("NukCrow Collector v2")
    print("No 443-only filter | multi-stage benchmark | categorized output")
    print("=" * 64)

    fetched = fetch_all()
    raw_records = build_records(fetched)
    print(f"\nRaw configs: {len(raw_records):,}")

    unique = dedupe(raw_records)
    print(f"Unique + valid: {len(unique):,}")

    ranked = benchmark(unique)
    print(f"Alive after benchmark: {len(ranked):,}")

    # Remove stale outputs before writing the new run.
    for name in ("all_configs.txt", "best_iran.txt", "mix_iran.txt", "mci.txt", "irancell.txt", "rightel.txt"):
        path = os.path.join(OUT_DIR, name)
        if os.path.exists(path):
            os.remove(path)
    for p in PROTO_LIST:
        path = os.path.join(OUT_DIR, f"{p}.txt")
        if os.path.exists(path):
            os.remove(path)

    general = write_general(ranked)
    protocols = write_protocols(ranked)
    iran = write_iran(ranked)

    print("\n" + "=" * 64)
    print(f"General: {len(general):,} total")
    for p, lines in protocols.items():
        print(f"{p:10s}: {len(lines):,}")
    for name, lines in iran.items():
        print(f"{name:10s}: {len(lines):,}")
    print(f"Elapsed: {time.time() - started:.1f}s")
    print("Output: sub/general/")
    print("=" * 64)


if __name__ == "__main__":
    main()
