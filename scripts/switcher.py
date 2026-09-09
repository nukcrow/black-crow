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
    # Actively maintained / tested aggregators
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vmess.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/shadowsocks.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/Lite-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/static/sub_en",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_servers.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/jafar.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/6.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/22.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/23.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/24.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
]

REMARK = "nukcrow"
PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade"}
PROTO_LIST = ["vless", "vmess", "trojan", "ss", "hysteria2"]
PROTOCOL_CAP = 1000

# Fast, bounded collection settings. No per-config network probing is performed.
GOOD_POOL_SIZE = 6000
SUB_SIZE = 1000
SUB_COUNT = 5
FETCH_WORKERS = 24
FETCH_TIMEOUT = 8
MAX_SOURCE_BYTES = 8 * 1024 * 1024

GEO_BATCH_SIZE = 100
GEO_DELAY = 0.25


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
    headers = {
        "User-Agent": "Mozilla/5.0 nukcrow-collector/3.0",
        "Accept": "text/plain,text/*;q=0.9,*/*;q=0.1",
        "Connection": "close",
    }
    found = []
    try:
        with requests.get(
            url,
            headers=headers,
            timeout=(4, FETCH_TIMEOUT),
            stream=True,
        ) as res:
            if res.status_code != 200:
                print(f"[skip] HTTP {res.status_code}: {url}")
                return found

            chunks = []
            total = 0
            for chunk in res.iter_content(chunk_size=65536, decode_unicode=False):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    break
                chunks.append(chunk)

            raw = b"".join(chunks)
            content = raw.decode("utf-8", errors="ignore")
            content = extract_base64_payload(content)

            valid_prefixes = (
                "vless://", "vmess://", "trojan://", "ss://",
                "hysteria2://", "hy2://", "tuic://"
            )

            for line in content.splitlines():
                line = line.strip()
                if line.startswith(valid_prefixes):
                    found.append(line)
    except requests.RequestException as exc:
        print(f"[skip] fetch failed: {url} ({type(exc).__name__})")
    except Exception as exc:
        print(f"[skip] parse failed: {url} ({type(exc).__name__})")
    return found


def fetch_all():
    raw_list = []
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        futures = [executor.submit(fetch_one, url) for url in SOURCES]
        for future in futures:
            try:
                raw_list.extend(future.result(timeout=FETCH_TIMEOUT + 5))
            except Exception as exc:
                print(f"[skip] worker failed ({type(exc).__name__})")
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


def write_random_good_outputs(configs, formatted_by_fp, proto_records):
    """Write five random 1000-config subscriptions.

    There is deliberately no per-config TCP/TLS probing here: that was the
    source of the GitHub Actions hangs. Sources are already curated/filtered,
    and malformed/duplicate configs are removed before output.
    """
    import random

    available = []
    seen = set()

    for cfg in configs:
        fp = config_fingerprint(cfg)
        formatted = formatted_by_fp.get(fp)
        if formatted and fp not in seen:
            seen.add(fp)
            available.append(formatted)

    random.shuffle(available)

    needed = SUB_SIZE * SUB_COUNT
    if not available:
        raise RuntimeError("No usable configs available for subscriptions")

    # If fewer than 5000 unique configs exist, recycle the available pool.
    # This guarantees that every public sub file has exactly 1000 lines.
    selected = [available[i % len(available)] for i in range(needed)]

    for i in range(SUB_COUNT):
        chunk = selected[i * SUB_SIZE:(i + 1) * SUB_SIZE]
        write_lines(f"sub/general/sub{i + 1}.txt", chunk)

    for proto in PROTO_LIST:
        records = list(proto_records.get(proto, []))
        random.shuffle(records)
        lines = []
        seen_proto = set()

        for record in records:
            fp = config_fingerprint(record)
            formatted = formatted_by_fp.get(fp)
            if formatted and fp not in seen_proto:
                seen_proto.add(fp)
                lines.append(formatted)
            if len(lines) >= PROTOCOL_CAP:
                break

        write_lines(f"sub/protocols/{proto}.txt", lines)


def main():
    started = time.time()

    print(f"Fetching from {len(SOURCES)} sources (parallel, bounded)...")
    raw = fetch_all()
    print(f"Fetched (raw): {len(raw)}")

    raw = dedupe_configs(raw)
    print(f"After transport-aware dedupe: {len(raw)}")

    if not raw:
        raise RuntimeError("No configs were collected from the configured sources")

    # Randomize before formatting so the public subscriptions stay random.
    import random
    random.shuffle(raw)

    # Keep a large pool so five 1000-line subscriptions have plenty of variety.
    pool = raw[:GOOD_POOL_SIZE]

    hosts = []
    for cfg in pool:
        host, _ = extract_host_port(cfg)
        if host:
            hosts.append(host)

    print(f"Geolocating {len(set(hosts))} unique hosts (best effort)...")
    geo_map = geolocate_hosts(hosts)
    print(f"Geolocated: {len(geo_map)} / {len(set(hosts))} unique hosts")

    formatted_by_fp = {}
    proto_records = {p: [] for p in PROTO_LIST}

    for cfg in pool:
        proto = detect_proto(cfg)
        if proto not in proto_records:
            continue

        host, _ = extract_host_port(cfg)
        flag = country_to_flag(geo_map.get(host, ""))
        renamed = rename_config(cfg, proto, flag)
        if not renamed:
            continue

        fp = config_fingerprint(cfg)
        formatted_by_fp[fp] = renamed
        proto_records[proto].append(cfg)

    usable = list(formatted_by_fp.keys())
    print(f"Usable configs: {len(usable)}")

    if not usable:
        raise RuntimeError("No usable configs after parsing/formatting")

    write_random_good_outputs(pool, formatted_by_fp, proto_records)

    print(
        f"Done. General subs: {SUB_COUNT} x {SUB_SIZE} | "
        f"Pool: {len(pool)} | Elapsed: {time.time() - started:.1f}s"
    )


if __name__ == "__main__":
    main()
