import os
import ssl
import json
import time
import base64
import socket
import statistics
import hashlib
from urllib.parse import urlparse, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor

import requests

# Keep the existing output tree because the Telegram bot depends on these paths.
os.makedirs("sub/general", exist_ok=True)
os.makedirs("sub/protocols", exist_ok=True)

SOURCES = [
    # Large, actively maintained aggregators
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/Lite-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/static/sub_en",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/Free-Node-Merge/main/o/node.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_servers.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/jafar.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/6.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/22.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/23.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/24.txt",
    # Additional active/community sources
    "https://raw.githubusercontent.com/VP01596/vless-top15/main/All.txt",
    "https://raw.githubusercontent.com/3nerg0n/vless-parser/main/sub_vless_3nerg0n_92sh81",
    "https://raw.githubusercontent.com/Areral/ScarletDevil/main/sub_all.txt",
    "https://raw.githubusercontent.com/Arianlavi/RebeldevConfig/main/RebelLink/all_subscriptions.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_sub.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mehrdadmb2/V2ray_Sub/main/Mix.txt",
    "https://raw.githubusercontent.com/mosapase/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/rasool083/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/amirkma/proxykma/main/mix.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
]
REMARK = "nukcrow"
PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade"}
PROTO_LIST = ["vless", "vmess", "trojan", "ss", "hysteria2"]
PROTOCOL_CAP = 200

# Ranking settings. These are deliberately moderate so GitHub Actions does not
# spend excessive time probing thousands of endpoints.
RANKING_CAP = 100
LATENCY_PROBES = 3
CONNECT_TIMEOUT = 1.8
TLS_TIMEOUT = 2.5
RANK_WORKERS = 80
GOOD_POOL_SIZE = 1200
SUB_SIZE = 100
SUB_COUNT = 5

GEO_BATCH_SIZE = 100
GEO_DELAY = 1.4


def decode_base64_safe(data):
    try:
        data = data.strip()
        # Support both standard and URL-safe base64.
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_base64_payload(text):
    """Decode a subscription if it is base64, otherwise return the original text."""
    text = text.strip()
    if "://" in text:
        return text

    decoded = decode_base64_safe(text)
    if "://" in decoded:
        return decoded

    return text


def fetch_one(url):
    headers = {"User-Agent": "Mozilla/5.0 nukcrow-collector/2.0"}
    found = []
    try:
        res = requests.get(url, headers=headers, timeout=10)
        if res.status_code != 200:
            return found

        content = extract_base64_payload(res.text)
        valid_prefixes = (
            "vless://", "vmess://", "trojan://", "ss://",
            "hysteria2://", "hy2://", "tuic://"
        )

        for line in content.splitlines():
            line = line.strip()
            if line.startswith(valid_prefixes):
                found.append(line)
    except Exception:
        pass
    return found


def fetch_all():
    raw_list = []
    with ThreadPoolExecutor(max_workers=25) as executor:
        for result in executor.map(fetch_one, SOURCES):
            raw_list.extend(result)
    return raw_list


def vmess_data(config):
    if not config.startswith("vmess://"):
        return None
    try:
        return json.loads(decode_base64_safe(config[8:]))
    except Exception:
        return None


def extract_host_port(config):
    """Return endpoint host/port without doing any network operation."""
    try:
        data = vmess_data(config)
        if data is not None:
            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 443))
            return host, port

        parsed = urlparse(config)
        host = parsed.hostname
        if not host:
            return None, None

        if parsed.port:
            port = parsed.port
        else:
            qs = parse_qs(parsed.query)
            security = qs.get("security", [""])[0].lower()
            port = 443 if security in {"tls", "reality"} else 80
        return host, int(port)
    except Exception:
        return None, None


# Backward-compatible name used by the old project.
def extract_ip_port(config):
    return extract_host_port(config)


def config_fingerprint(config):
    """Dedupe by meaningful transport identity, not only host:port.

    This avoids throwing away different SNI/path/transport variants that can
    share one endpoint, while still removing exact duplicates.
    """
    proto = detect_proto(config)
    try:
        data = vmess_data(config)
        if data is not None:
            fields = {
                "proto": "vmess",
                "add": str(data.get("add", "")).lower(),
                "port": str(data.get("port", "")),
                "id": str(data.get("id", "")),
                "net": str(data.get("net", "")).lower(),
                "type": str(data.get("type", "")).lower(),
                "tls": str(data.get("tls", "")).lower(),
                "host": str(data.get("host", "")).lower(),
                "path": str(data.get("path", "")),
                "sni": str(data.get("sni", "")).lower(),
            }
        else:
            parsed = urlparse(config)
            qs = parse_qs(parsed.query)
            fields = {
                "proto": proto,
                "host": (parsed.hostname or "").lower(),
                "port": str(parsed.port or ""),
                "security": qs.get("security", [""])[0].lower(),
                "type": qs.get("type", [""])[0].lower(),
                "sni": qs.get("sni", [""])[0].lower(),
                "host_header": qs.get("host", [""])[0].lower(),
                "path": qs.get("path", [""])[0],
                "service": qs.get("serviceName", [""])[0],
            }
        raw = json.dumps(fields, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception:
        return hashlib.sha256(config.strip().encode()).hexdigest()


def dedupe_configs(configs):
    seen = set()
    unique = []
    for cfg in configs:
        fp = config_fingerprint(cfg)
        if fp not in seen:
            seen.add(fp)
            unique.append(cfg)
    return unique


# Backward-compatible name; behavior is improved to preserve different transports.
def dedupe_by_host_port(configs):
    return dedupe_configs(configs)


def get_query(config):
    try:
        return parse_qs(urlparse(config).query)
    except Exception:
        return {}


def get_sni(config):
    try:
        data = vmess_data(config)
        if data is not None:
            return data.get("sni") or data.get("host") or data.get("add")
        parsed = urlparse(config)
        qs = parse_qs(parsed.query)
        return qs.get("sni", [None])[0] or parsed.hostname
    except Exception:
        return None


def get_security(config):
    try:
        data = vmess_data(config)
        if data is not None:
            return str(data.get("tls", "")).lower()
        return get_query(config).get("security", [""])[0].lower()
    except Exception:
        return ""


def check_endpoint(config, timeout=CONNECT_TIMEOUT):
    """Measure TCP connect latency and optionally TLS handshake latency.

    This is intentionally a network-quality benchmark, not a full VLESS/VMess
    client handshake. Reality is therefore scored using TCP reachability only.
    """
    host, port = extract_host_port(config)
    if not host or not port:
        return None

    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        tcp_ms = (time.perf_counter() - start) * 1000.0

        security = get_security(config)
        tls_ms = None
        if security == "tls":
            sni = get_sni(config) or host
            tls_start = time.perf_counter()
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock.settimeout(TLS_TIMEOUT)
            tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
            tls_sock.do_handshake()
            tls_ms = (time.perf_counter() - tls_start) * 1000.0
            tls_sock.close()
            sock = None

        return {"tcp_ms": tcp_ms, "tls_ms": tls_ms}
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def benchmark_config(config):
    """Run repeated probes and return a stable ranking record."""
    samples = []
    tls_samples = []

    for _ in range(LATENCY_PROBES):
        result = check_endpoint(config)
        if result:
            samples.append(result["tcp_ms"])
            if result["tls_ms"] is not None:
                tls_samples.append(result["tls_ms"])

    if not samples:
        return None

    median_tcp = statistics.median(samples)
    minimum_tcp = min(samples)
    jitter = statistics.pstdev(samples) if len(samples) > 1 else 0.0
    success_rate = len(samples) / LATENCY_PROBES

    median_tls = statistics.median(tls_samples) if tls_samples else None
    transport_penalty = 0.0
    if median_tls is not None:
        # TLS handshake quality matters more than raw TCP when available.
        transport_penalty = min(median_tls, 1000.0) * 0.15

    # Lower is better. Stable, successful and fast endpoints rise to the top.
    quality_score = (
        median_tcp
        + jitter * 0.50
        + (1.0 - success_rate) * 250.0
        + transport_penalty
    )

    return {
        "config": config,
        "tcp_median": median_tcp,
        "tcp_min": minimum_tcp,
        "jitter": jitter,
        "success_rate": success_rate,
        "tls_median": median_tls,
        "quality_score": quality_score,
    }


def rank_configs(configs):
    ranked = []
    if not configs:
        return ranked

    with ThreadPoolExecutor(max_workers=RANK_WORKERS) as executor:
        for result in executor.map(benchmark_config, configs):
            if result:
                ranked.append(result)

    ranked.sort(key=lambda x: (
        x["quality_score"],
        x["tcp_median"],
        -x["success_rate"],
    ))
    return ranked


def filter_alive(raw_configs):
    """Backward-compatible alive filter, now based on the benchmark itself."""
    alive = []
    with ThreadPoolExecutor(max_workers=RANK_WORKERS) as executor:
        for result in executor.map(benchmark_config, raw_configs):
            if result:
                alive.append(result["config"])
    return alive


def detect_proto(config):
    if config.startswith("vless://"):
        return "vless"
    if config.startswith("vmess://"):
        return "vmess"
    if config.startswith("trojan://"):
        return "trojan"
    if config.startswith("ss://"):
        return "ss"
    if config.startswith("hysteria2://") or config.startswith("hy2://"):
        return "hysteria2"
    if config.startswith("tuic://"):
        return "tuic"
    return "unknown"


def is_preferred(config, proto):
    try:
        if proto == "vmess":
            data = vmess_data(config)
            if not data:
                return False
            net = str(data.get("net", "")).lower()
            tls = str(data.get("tls", "")).lower()
            return tls == "tls" and net in {"ws", "grpc", "h2", "httpupgrade"}

        if proto == "hysteria2":
            return True

        qs = get_query(config)
        security = qs.get("security", [""])[0].lower()
        ctype = qs.get("type", [""])[0].lower()

        if security == "reality":
            return True
        if security == "tls":
            return ctype in PREFERRED_TYPES or ctype == ""
        return False
    except Exception:
        return False


def country_to_flag(country_code):
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return ""


def geolocate_hosts(host_list):
    unique_hosts = list(set(host_list))
    result = {}

    for i in range(0, len(unique_hosts), GEO_BATCH_SIZE):
        chunk = unique_hosts[i:i + GEO_BATCH_SIZE]
        payload = [{"query": h, "fields": "query,countryCode,status"} for h in chunk]
        try:
            res = requests.post("http://ip-api.com/batch", json=payload, timeout=15)
            if res.status_code == 200:
                for item in res.json():
                    if item.get("status") == "success":
                        result[item["query"]] = item.get("countryCode", "")
        except Exception:
            pass
        time.sleep(GEO_DELAY)

    return result


def rename_config(config, proto, flag=""):
    label = f"{flag} {REMARK}".strip() if flag else REMARK
    try:
        if proto == "vmess":
            data = vmess_data(config)
            if not data:
                return None
            data["ps"] = label
            encoded = base64.b64encode(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii")
            return "vmess://" + encoded

        base_part = config.split("#", 1)[0]
        return f"{base_part}#{quote(label)}"
    except Exception:
        return None


def write_lines(path, lines):
    """Atomic-ish write: write temp file first, then replace target."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        if lines:
            f.write("\n")
    os.replace(tmp, path)


def write_general_outputs(all_formatted):
    # Preserve the exact five public subscription files expected by the bot.
    chunk_size = 1000
    for i in range(5):
        start = i * chunk_size
        end = start + chunk_size
        write_lines(f"sub/general/sub{i + 1}.txt", all_formatted[start:end])


def write_protocol_outputs(proto_buckets):
    for proto in PROTO_LIST:
        combined = proto_buckets[proto]["preferred"] + proto_buckets[proto]["fallback"]
        write_lines(f"sub/protocols/{proto}.txt", combined[:PROTOCOL_CAP])


def write_random_good_outputs(ranked_records, formatted_by_fp, proto_records):
    """Fill the existing bot files from a quality-filtered pool, randomly.

    No /sub/best directory is created. The bot keeps its current paths and
    continues to use random selection, but every candidate has already passed
    repeated connectivity/latency checks.
    """
    pool = ranked_records[:GOOD_POOL_SIZE]
    rng = __import__("random")
    pool = pool[:]
    rng.shuffle(pool)

    # Prefer disjoint subscriptions when there are enough good configs.
    selected = pool[:SUB_SIZE * SUB_COUNT]
    if len(selected) < SUB_SIZE * SUB_COUNT and pool:
        selected = [pool[i % len(pool)] for i in range(SUB_SIZE * SUB_COUNT)]

    for i in range(SUB_COUNT):
        chunk = selected[i * SUB_SIZE:(i + 1) * SUB_SIZE]
        lines = []
        for record in chunk:
            formatted = formatted_by_fp.get(config_fingerprint(record["config"]))
            if formatted:
                lines.append(formatted)
        write_lines(f"sub/general/sub{i + 1}.txt", lines)

    # Protocol subscriptions also contain only benchmarked configs.
    for proto in PROTO_LIST:
        records = proto_records.get(proto, [])[:PROTOCOL_CAP]
        rng.shuffle(records)
        lines = []
        for record in records[:PROTOCOL_CAP]:
            formatted = formatted_by_fp.get(config_fingerprint(record["config"]))
            if formatted:
                lines.append(formatted)
        write_lines(f"sub/protocols/{proto}.txt", lines)

def main():
    started = time.time()
    print(f"Fetching from {len(SOURCES)} sources (parallel)...")
    raw = fetch_all()
    print(f"Fetched (raw): {len(raw)}")

    raw = dedupe_configs(raw)
    print(f"After transport-aware dedupe: {len(raw)}")
    if not raw:
        raise RuntimeError("No configs were collected from the configured sources")

    print("Benchmarking configs: repeated TCP/TLS probes...")
    ranked = rank_configs(raw)
    print(f"Reachable/benchmarked: {len(ranked)}")
    if not ranked:
        raise RuntimeError("No reachable configs after benchmark")

    # Keep the good pool bounded so GitHub Actions stays fast and the five
    # public subscriptions remain genuinely random among healthy configs.
    ranked = ranked[:GOOD_POOL_SIZE]

    hosts = []
    for record in ranked:
        host, _ = extract_host_port(record["config"])
        if host:
            hosts.append(host)

    print("Geolocating servers (country flags)...")
    geo_map = geolocate_hosts(hosts)
    print(f"Geolocated: {len(geo_map)} / {len(set(hosts))} unique hosts")

    preferred_all = []
    fallback_all = []
    formatted_by_fp = {}
    proto_records = {p: [] for p in PROTO_LIST}

    for record in ranked:
        cfg = record["config"]
        proto = detect_proto(cfg)
        if proto not in proto_records:
            continue

        host, _ = extract_host_port(cfg)
        flag = country_to_flag(geo_map.get(host, ""))
        renamed = rename_config(cfg, proto, flag)
        if not renamed:
            continue

        formatted_by_fp[config_fingerprint(cfg)] = renamed
        proto_records[proto].append(record)

        if is_preferred(cfg, proto):
            preferred_all.append(renamed)
        else:
            fallback_all.append(renamed)

    # Existing Telegram bot paths are preserved exactly.
    write_random_good_outputs(ranked, formatted_by_fp, proto_records)

    print(
        f"Done. Good pool: {len(ranked)} | Preferred: {len(preferred_all)} | "
        f"Fallback: {len(fallback_all)} | Elapsed: {time.time() - started:.1f}s"
    )


if __name__ == "__main__":
    main()
