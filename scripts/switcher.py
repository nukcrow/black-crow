```python
import os
import ssl
import json
import time
import base64
import socket
import random
import hashlib
import statistics
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ============================================================
# NUKCROW CONFIG COLLECTOR
# Quality-first / latency-aware / protocol-aware
# ============================================================

os.makedirs("sub/general", exist_ok=True)
os.makedirs("sub/protocols", exist_ok=True)

SOURCES = [
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

PROTO_LIST = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
]

PROTOCOL_CAP = 1000

SUB_SIZE = 1000
SUB_COUNT = 5

FETCH_WORKERS = 24
FETCH_TIMEOUT = 10
MAX_SOURCE_BYTES = 12 * 1024 * 1024

# Large candidate pool before quality testing.
MAX_CANDIDATES = 30000

# Quality engine.
QUALITY_WORKERS = 180
SOCKET_TIMEOUT = 2.2
TLS_TIMEOUT = 3.0

# Minimum requirements.
MAX_TCP_MS = 1500
MAX_TLS_MS = 3000

# Number of independent measurements per endpoint.
PROBE_ROUNDS = 2

# Keep enough good configs to build five 1000-line subs.
TARGET_GOOD_POOL = 9000

GEO_BATCH_SIZE = 100
GEO_DELAY = 0.25


# ============================================================
# BASE64
# ============================================================

def decode_base64_safe(data):
    try:
        data = data.strip()
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data, validate=False).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def extract_base64_payload(text):
    text = text.strip()

    if "://" in text:
        return text

    decoded = decode_base64_safe(text)

    if "://" in decoded:
        return decoded

    return text


# ============================================================
# FETCH
# ============================================================

def fetch_one(url):
    headers = {
        "User-Agent": "Mozilla/5.0 nukcrow-quality-engine/5.0",
        "Accept": "text/plain,text/*,*/*",
        "Connection": "close",
    }

    valid_prefixes = (
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "hysteria2://",
        "hy2://",
    )

    found = []

    try:
        with requests.get(
            url,
            headers=headers,
            timeout=(5, FETCH_TIMEOUT),
            stream=True,
        ) as res:

            if res.status_code != 200:
                return found

            chunks = []
            total = 0

            for chunk in res.iter_content(
                chunk_size=65536,
                decode_unicode=False
            ):
                if not chunk:
                    continue

                total += len(chunk)

                if total > MAX_SOURCE_BYTES:
                    break

                chunks.append(chunk)

            content = b"".join(chunks).decode(
                "utf-8",
                errors="ignore"
            )

            content = extract_base64_payload(content)

            for line in content.splitlines():
                line = line.strip()

                if line.startswith(valid_prefixes):
                    found.append(line)

    except Exception:
        pass

    return found


def fetch_all():
    result = []

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        futures = [
            executor.submit(fetch_one, url)
            for url in SOURCES
        ]

        for future in as_completed(futures):
            try:
                result.extend(future.result())
            except Exception:
                pass

    return result


# ============================================================
# PARSING
# ============================================================

def detect_proto(config):
    if config.startswith("vless://"):
        return "vless"

    if config.startswith("vmess://"):
        return "vmess"

    if config.startswith("trojan://"):
        return "trojan"

    if config.startswith("ss://"):
        return "ss"

    if (
        config.startswith("hysteria2://")
        or config.startswith("hy2://")
    ):
        return "hysteria2"

    return "unknown"


def vmess_data(config):
    if not config.startswith("vmess://"):
        return None

    try:
        data = decode_base64_safe(config[8:])
        return json.loads(data)
    except Exception:
        return None


def get_query(config):
    try:
        return parse_qs(urlparse(config).query)
    except Exception:
        return {}


def extract_host_port(config):
    try:
        data = vmess_data(config)

        if data:
            host = str(
                data.get("add", "")
            ).strip()

            port = int(
                data.get("port", 443)
            )

            return host, port

        parsed = urlparse(config)

        host = parsed.hostname

        if not host:
            return None, None

        if parsed.port:
            return host, parsed.port

        qs = parse_qs(parsed.query)

        security = qs.get(
            "security",
            [""]
        )[0].lower()

        if security in (
            "tls",
            "reality",
            "xtls",
        ):
            port = 443
        else:
            port = 80

        return host, port

    except Exception:
        return None, None


def get_sni(config):
    try:
        data = vmess_data(config)

        if data:
            return (
                data.get("sni")
                or data.get("host")
                or data.get("add")
            )

        parsed = urlparse(config)
        qs = parse_qs(parsed.query)

        return (
            qs.get("sni", [None])[0]
            or qs.get("host", [None])[0]
            or parsed.hostname
        )

    except Exception:
        return None


def get_security(config):
    try:
        data = vmess_data(config)

        if data:
            return str(
                data.get("tls", "")
            ).lower()

        return get_query(config).get(
            "security",
            [""]
        )[0].lower()

    except Exception:
        return ""


def get_transport(config):
    proto = detect_proto(config)

    try:
        if proto == "vmess":
            data = vmess_data(config)

            if not data:
                return ""

            return str(
                data.get("net", "")
            ).lower()

        return get_query(config).get(
            "type",
            [""]
        )[0].lower()

    except Exception:
        return ""


def get_path(config):
    try:
        data = vmess_data(config)

        if data:
            return data.get("path", "")

        return get_query(config).get(
            "path",
            [""]
        )[0]

    except Exception:
        return ""


# ============================================================
# FINGERPRINT / DEDUPE
# ============================================================

def config_fingerprint(config):
    proto = detect_proto(config)

    try:
        data = vmess_data(config)

        if data:
            fields = {
                "proto": "vmess",
                "add": str(
                    data.get("add", "")
                ).lower(),
                "port": str(
                    data.get("port", "")
                ),
                "id": str(
                    data.get("id", "")
                ),
                "aid": str(
                    data.get("aid", "")
                ),
                "net": str(
                    data.get("net", "")
                ).lower(),
                "type": str(
                    data.get("type", "")
                ).lower(),
                "tls": str(
                    data.get("tls", "")
                ).lower(),
                "host": str(
                    data.get("host", "")
                ).lower(),
                "path": str(
                    data.get("path", "")
                ),
                "sni": str(
                    data.get("sni", "")
                ).lower(),
                "alpn": str(
                    data.get("alpn", "")
                ).lower(),
            }

        else:
            parsed = urlparse(config)
            qs = parse_qs(parsed.query)

            fields = {
                "proto": proto,
                "host": (
                    parsed.hostname or ""
                ).lower(),
                "port": str(
                    parsed.port or ""
                ),
                "security": qs.get(
                    "security",
                    [""]
                )[0].lower(),
                "type": qs.get(
                    "type",
                    [""]
                )[0].lower(),
                "sni": qs.get(
                    "sni",
                    [""]
                )[0].lower(),
                "host_header": qs.get(
                    "host",
                    [""]
                )[0].lower(),
                "path": qs.get(
                    "path",
                    [""]
                )[0],
                "service": qs.get(
                    "serviceName",
                    [""]
                )[0],
            }

        raw = json.dumps(
            fields,
            sort_keys=True,
            ensure_ascii=False,
        )

        return hashlib.sha256(
            raw.encode()
        ).hexdigest()

    except Exception:
        return hashlib.sha256(
            config.strip().encode()
        ).hexdigest()


def dedupe_configs(configs):
    seen = set()
    output = []

    for config in configs:
        fp = config_fingerprint(config)

        if fp not in seen:
            seen.add(fp)
            output.append(config)

    return output


# ============================================================
# QUALITY ENGINE
# ============================================================

def tcp_measure(host, port):
    started = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=SOCKET_TIMEOUT,
        ):
            pass

        return (
            time.perf_counter()
            - started
        ) * 1000

    except Exception:
        return None


def tls_measure(host, port, sni):
    started = time.perf_counter()
    sock = None

    try:
        raw = socket.create_connection(
            (host, port),
            timeout=TLS_TIMEOUT,
        )

        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        sock = context.wrap_socket(
            raw,
            server_hostname=sni or host,
        )

        latency = (
            time.perf_counter()
            - started
        ) * 1000

        return latency

    except Exception:
        return None

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def endpoint_key(config):
    host, port = extract_host_port(config)

    if not host or not port:
        return None

    return (
        host.lower(),
        int(port),
    )


def endpoint_probe(endpoint, configs):
    host, port = endpoint

    sample = configs[0]
    proto = detect_proto(sample)

    sni = get_sni(sample)
    security = get_security(sample)

    tcp_samples = []
    tls_samples = []

    for _ in range(PROBE_ROUNDS):
        tcp = tcp_measure(
            host,
            port
        )

        if tcp is None:
            continue

        tcp_samples.append(tcp)

        if security in (
            "tls",
            "reality",
            "xtls",
        ) or proto == "trojan":

            tls = tls_measure(
                host,
                port,
                sni
            )

            if tls is not None:
                tls_samples.append(tls)

    if not tcp_samples:
        return None

    tcp_median = statistics.median(
        tcp_samples
    )

    tcp_min = min(tcp_samples)

    jitter = (
        max(tcp_samples)
        - min(tcp_samples)
        if len(tcp_samples) > 1
        else 0
    )

    tls_median = (
        statistics.median(tls_samples)
        if tls_samples
        else None
    )

    # Hard quality gate.
    if tcp_median > MAX_TCP_MS:
        return None

    if (
        security in (
            "tls",
            "reality",
            "xtls",
        )
        or proto == "trojan"
    ):
        if tls_median is None:
            return None

        if tls_median > MAX_TLS_MS:
            return None

    # Quality score.
    score = 0.0

    # Lower latency = better.
    score += max(
        0,
        1000 - tcp_median
    )

    # Reward stable endpoints.
    score += max(
        0,
        300 - jitter * 3
    )

    # TLS handshake success bonus.
    if tls_median is not None:
        score += max(
            0,
            500 - tls_median
        )

    # Protocol preference.
    if proto == "vless":
        score += 100

    elif proto == "vmess":
        score += 70

    elif proto == "trojan":
        score += 90

    elif proto == "hysteria2":
        score += 120

    transport = get_transport(sample)

    if transport in (
        "ws",
        "grpc",
        "httpupgrade",
        "xhttp",
    ):
        score += 100

    return {
        "tcp": tcp_median,
        "tcp_min": tcp_min,
        "jitter": jitter,
        "tls": tls_median,
        "score": score,
    }


def quality_filter(configs):
    endpoint_configs = {}

    for config in configs:
        endpoint = endpoint_key(config)

        if endpoint:
            endpoint_configs.setdefault(
                endpoint,
                []
            ).append(config)

    endpoints = list(
        endpoint_configs.keys()
    )

    random.shuffle(endpoints)

    print(
        f"Unique endpoints to test: "
        f"{len(endpoints)}"
    )

    results = {}

    with ThreadPoolExecutor(
        max_workers=QUALITY_WORKERS
    ) as executor:

        future_map = {
            executor.submit(
                endpoint_probe,
                endpoint,
                endpoint_configs[endpoint],
            ): endpoint
            for endpoint in endpoints
        }

        for future in as_completed(
            future_map
        ):
            endpoint = future_map[future]

            try:
                result = future.result()

                if result:
                    results[endpoint] = result

            except Exception:
                pass

    good = []

    for endpoint, result in results.items():
        for config in endpoint_configs[
            endpoint
        ]:
            good.append(
                (
                    config,
                    result
                )
            )

    # Sort globally by quality.
    good.sort(
        key=lambda item: (
            -item[1]["score"],
            item[1]["tcp"],
            item[1]["jitter"],
        )
    )

    return good


# ============================================================
# GEO
# ============================================================

def country_to_flag(code):
    if not code or len(code) != 2:
        return ""

    try:
        return "".join(
            chr(
                127397 + ord(c)
            )
            for c in code.upper()
        )
    except Exception:
        return ""


def geolocate_hosts(hosts):
    unique = list(set(hosts))
    result = {}

    for i in range(
        0,
        len(unique),
        GEO_BATCH_SIZE
    ):
        chunk = unique[
            i:i + GEO_BATCH_SIZE
        ]

        payload = [
            {
                "query": host,
                "fields":
                    "query,countryCode,status",
            }
            for host in chunk
        ]

        try:
            response = requests.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=15,
            )

            if response.status_code == 200:
                for item in response.json():
                    if (
                        item.get("status")
                        == "success"
                    ):
                        result[
                            item["query"]
                        ] = item.get(
                            "countryCode",
                            ""
                        )

        except Exception:
            pass

        time.sleep(GEO_DELAY)

    return result


# ============================================================
# FORMAT
# ============================================================

def rename_config(
    config,
    proto,
    flag=""
):
    label = (
        f"{flag} {REMARK}".strip()
        if flag
        else REMARK
    )

    try:
        if proto == "vmess":
            data = vmess_data(config)

            if not data:
                return None

            data["ps"] = label

            encoded = base64.b64encode(
                json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(
                        ",",
                        ":"
                    ),
                ).encode("utf-8")
            ).decode("ascii")

            return (
                "vmess://"
                + encoded
            )

        base = config.split(
            "#",
            1
        )[0]

        return (
            f"{base}#{quote(label)}"
        )

    except Exception:
        return None


# ============================================================
# OUTPUT
# ============================================================

def write_lines(path, lines):
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    tmp = path + ".tmp"

    with open(
        tmp,
        "w",
        encoding="utf-8"
    ) as f:

        if lines:
            f.write(
                "\n".join(lines)
                + "\n"
            )

    os.replace(
        tmp,
        path
    )


def build_diverse_pool(records):
    """
    Build a high-quality pool while preventing
    one server/provider from dominating the subscriptions.
    """

    by_endpoint = {}

    for config, quality in records:
        endpoint = endpoint_key(config)

        if not endpoint:
            continue

        by_endpoint.setdefault(
            endpoint,
            []
        ).append(
            (
                config,
                quality
            )
        )

    endpoint_list = list(
        by_endpoint.items()
    )

    endpoint_list.sort(
        key=lambda item:
            -max(
                x[1]["score"]
                for x in item[1]
            )
    )

    selected = []

    # Maximum configs from one endpoint.
    # This is critical for real-world variety.
    MAX_PER_ENDPOINT = 4

    for endpoint, items in endpoint_list:
        items.sort(
            key=lambda x:
                -x[1]["score"]
        )

        selected.extend(
            items[
                :MAX_PER_ENDPOINT
            ]
        )

        if len(selected) >= TARGET_GOOD_POOL:
            break

    return selected[
        :TARGET_GOOD_POOL
    ]


def make_subscriptions(
    formatted_records
):
    """
    Generate five genuinely different
    1000-line subscriptions.
    """

    rng = random.SystemRandom()

    # Group by protocol.
    protocol_groups = {
        proto: []
        for proto in PROTO_LIST
    }

    for item in formatted_records:
        config = item["config"]
        proto = detect_proto(config)

        if proto in protocol_groups:
            protocol_groups[
                proto
            ].append(item)

    # Protocol output.
    for proto in PROTO_LIST:
        records = protocol_groups[
            proto
        ]

        records.sort(
            key=lambda x:
                -x["quality"]["score"]
        )

        # Add slight variety while keeping
        # the best configs at the top.
        top = records[
            :min(
                len(records),
                PROTOCOL_CAP * 2
            )
        ]

        rng.shuffle(top)

        top.sort(
            key=lambda x:
                (
                    -x["quality"]["score"],
                    x["quality"]["tcp"],
                )
        )

        lines = [
            item["formatted"]
            for item in top[
                :PROTOCOL_CAP
            ]
        ]

        write_lines(
            f"sub/protocols/{proto}.txt",
            lines
        )

    # General pool.
    pool = list(
        formatted_records
    )

    pool.sort(
        key=lambda x:
            -x["quality"]["score"]
    )

    # Keep best ~2500 in a deterministic
    # high-quality core.
    core = pool[
        :min(
            len(pool),
            2500
        )
    ]

    remaining = pool[
        2500:
    ]

    subscriptions = []

    for index in range(
        SUB_COUNT
    ):
        local = list(core)

        rng.shuffle(
            local
        )

        if remaining:
            extra = list(
                remaining
            )

            rng.shuffle(
                extra
            )

            local.extend(
                extra[
                    :SUB_SIZE * 2
                ]
            )

        # Deduplicate inside each sub.
        seen = set()
        lines = []

        for item in local:
            fp = item["fp"]

            if fp in seen:
                continue

            seen.add(fp)
            lines.append(
                item["formatted"]
            )

            if len(lines) >= SUB_SIZE:
                break

        # If not enough unique configs,
        # fill from entire quality pool.
        if len(lines) < SUB_SIZE:
            for item in pool:
                fp = item["fp"]

                if fp in seen:
                    continue

                seen.add(fp)
                lines.append(
                    item["formatted"]
                )

                if len(lines) >= SUB_SIZE:
                    break

        # Last-resort recycling is avoided
        # whenever enough quality configs exist.
        if len(lines) < SUB_SIZE:
            raise RuntimeError(
                f"Only {len(lines)} usable configs "
                f"available for sub{index + 1}"
            )

        subscriptions.append(
            lines[:SUB_SIZE]
        )

    for i, lines in enumerate(
        subscriptions,
        1
    ):
        write_lines(
            f"sub/general/sub{i}.txt",
            lines
        )


# ============================================================
# MAIN
# ============================================================

def main():
    started = time.time()

    print(
        f"Fetching {len(SOURCES)} sources..."
    )

    raw = fetch_all()

    print(
        f"Fetched raw configs: "
        f"{len(raw)}"
    )

    raw = dedupe_configs(raw)

    print(
        f"After dedupe: "
        f"{len(raw)}"
    )

    if not raw:
        raise RuntimeError(
            "No configs collected"
        )

    # Limit huge dumps but retain broad
    # source diversity.
    if len(raw) > MAX_CANDIDATES:
        random.shuffle(raw)
        raw = raw[
            :MAX_CANDIDATES
        ]

    print(
        "Running multi-stage quality tests..."
    )

    quality_records = quality_filter(
        raw
    )

    print(
        f"Quality-passing endpoints: "
        f"{len(quality_records)}"
    )

    if not quality_records:
        raise RuntimeError(
            "No quality configs survived"
        )

    # Build endpoint-diverse quality pool.
    selected = build_diverse_pool(
        quality_records
    )

    print(
        f"Selected quality pool: "
        f"{len(selected)}"
    )

    if len(selected) < SUB_SIZE:
        raise RuntimeError(
            "Not enough quality configs"
        )

    # Geo only selected configs.
    hosts = []

    for config, _quality in selected:
        host, _ = extract_host_port(
            config
        )

        if host:
            hosts.append(host)

    print(
        f"Geolocating "
        f"{len(set(hosts))} hosts..."
    )

    geo = geolocate_hosts(
        hosts
    )

    print(
        f"Geolocated: "
        f"{len(geo)}"
    )

    formatted_records = []

    seen_fp = set()

    for config, quality in selected:
        proto = detect_proto(
            config
        )

        if proto not in PROTO_LIST:
            continue

        fp = config_fingerprint(
            config
        )

        if fp in seen_fp:
            continue

        host, _ = extract_host_port(
            config
        )

        flag = country_to_flag(
            geo.get(
                host,
                ""
            )
        )

        formatted = rename_config(
            config,
            proto,
            flag
        )

        if not formatted:
            continue

        seen_fp.add(fp)

        formatted_records.append(
            {
                "config": config,
                "formatted": formatted,
                "fp": fp,
                "proto": proto,
                "quality": quality,
            }
        )

    if len(formatted_records) < SUB_SIZE:
        raise RuntimeError(
            "Less than 1000 usable high-quality configs"
        )

    print(
        f"Final usable configs: "
        f"{len(formatted_records)}"
    )

    make_subscriptions(
        formatted_records
    )

    elapsed = (
        time.time()
        - started
    )

    print(
        "========================================"
    )
    print(
        "NUKCROW QUALITY BUILD COMPLETE"
    )
    print(
        f"Quality configs: "
        f"{len(formatted_records)}"
    )
    print(
        f"Subscriptions: "
        f"{SUB_COUNT} x {SUB_SIZE}"
    )
    print(
        "Protocol caps: "
        f"{PROTOCOL_CAP}"
    )
    print(
        f"Elapsed: {elapsed:.1f}s"
    )
    print(
        "========================================"
    )


if __name__ == "__main__":
    main()
```
