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
os.makedirs("sub/best", exist_ok=True)

SOURCES = [
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/refs/heads/main/all/vless.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/domain/vless.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/ru/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/jafar.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/MrRabbitson/RabbitProxyz-proxy-list/main/sub.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/VP01596/vless-top15/main/All.txt",
    "https://raw.githubusercontent.com/3nerg0n/vless-parser/refs/heads/main/sub_vless_3nerg0n_92sh81",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub2.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/10.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/sub.txt",
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mehrdadmb2/V2ray_Sub/main/Mix.txt",
    "https://raw.githubusercontent.com/mosapase/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/rasool083/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/amirkma/proxykma/main/mix.txt",
    "https://raw.githubusercontent.com/Areral/ScarletDevil/main/sub_all.txt",
    "https://raw.githubusercontent.com/Arianlavi/RebeldevConfig/main/RebelLink/all_subscriptions.txt",
    "https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/whitelist-vless.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
    "https://raw.githubusercontent.com/vpei/free-node-1/main/o/allnode.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vmess",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
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
    chunk_size = 1000
    total = len(all_formatted)
    # داینامیک: هر چقدر کانفیگ زنده داشتیم همونقدر ساب (حداکثر 10، هیچ فایل خالی نمی‌مونه)
    num_subs = min(10, max(1, (total + chunk_size - 1) // chunk_size))
    for i in range(num_subs):
        start = i * chunk_size
        end = start + chunk_size
        chunk = all_formatted[start:end]
        if chunk:
            write_lines(f"sub/general/sub{i + 1}.txt", chunk)
    # فایل‌های قدیمی‌ای که دیگه پر نمیشن رو پاک کن تا خالی نمونن
    import os
    for i in range(num_subs + 1, 11):
        path = f"sub/general/sub{i}.txt"
        if os.path.exists(path):
            os.remove(path)
    print(f"General subs written: {num_subs} x up to {chunk_size} configs")


def write_protocol_outputs(proto_buckets):
    for proto in PROTO_LIST:
        combined = proto_buckets[proto]["preferred"] + proto_buckets[proto]["fallback"]
        write_lines(f"sub/protocols/{proto}.txt", combined[:PROTOCOL_CAP])


def write_best_outputs(ranked_records, formatted_by_fp, proto_records):
    """Create new best outputs without touching existing bot paths."""
    best = ranked_records[:RANKING_CAP]
    best_lines = []
    for record in best:
        formatted = formatted_by_fp.get(config_fingerprint(record["config"]))
        if formatted:
            best_lines.append(formatted)

    write_lines("sub/best/best100.txt", best_lines)

    for proto in PROTO_LIST:
        records = proto_records.get(proto, [])[:RANKING_CAP]
        lines = []
        for record in records:
            formatted = formatted_by_fp.get(config_fingerprint(record["config"]))
            if formatted:
                lines.append(formatted)
        write_lines(f"sub/best/best-{proto}.txt", lines)


def main():
    started = time.time()
    print(f"Fetching from {len(SOURCES)} sources (parallel)...")
    raw = fetch_all()
    print(f"Fetched (raw): {len(raw)}")

    raw = dedupe_configs(raw)
    print(f"After transport-aware dedupe: {len(raw)}")

    print("Benchmarking endpoints (3 probes each)...")
    ranked = rank_configs(raw)
    print(f"Reachable/benchmarked: {len(ranked)}")

    # Geolocation is performed for every reachable endpoint, as before.
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
    proto_buckets = {p: {"preferred": [], "fallback": []} for p in PROTO_LIST}
    formatted_by_fp = {}

    # Format ranked configs first, retaining their measured order.
    for record in ranked:
        cfg = record["config"]
        proto = detect_proto(cfg)
        if proto == "unknown" or proto not in proto_buckets:
            continue

        host, _ = extract_host_port(cfg)
        flag = country_to_flag(geo_map.get(host, ""))
        renamed = rename_config(cfg, proto, flag)
        if not renamed:
            continue

        formatted_by_fp[config_fingerprint(cfg)] = renamed
        if is_preferred(cfg, proto):
            preferred_all.append(renamed)
            proto_buckets[proto]["preferred"].append(renamed)
        else:
            fallback_all.append(renamed)
            proto_buckets[proto]["fallback"].append(renamed)

    # Existing outputs stay compatible with the current Telegram bot.
    all_formatted = preferred_all + fallback_all
    write_general_outputs(all_formatted)
    write_protocol_outputs(proto_buckets)

    # New ranked outputs for the upcoming Telegram bot change.
    ranked_known = [r for r in ranked if detect_proto(r["config"]) in PROTO_LIST]
    proto_records = {p: [] for p in PROTO_LIST}
    for record in ranked_known:
        proto_records[detect_proto(record["config"])].append(record)

    write_best_outputs(ranked_known, formatted_by_fp, proto_records)

    print("Best 100 created: sub/best/best100.txt")
    for proto in PROTO_LIST:
        count = len(proto_records[proto][:RANKING_CAP])
        print(f"  best-{proto}: {count}")

    print(
        f"Done. Preferred: {len(preferred_all)} | "
        f"Fallback: {len(fallback_all)} | Total: {len(all_formatted)} | "
        f"Elapsed: {time.time() - started:.1f}s"
    )


if __name__ == "__main__":
    main()
