import os
import re
import json
import time
import base64
import socket
import random
import ipaddress
import threading

from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# =========================================================
# CONFIG
# =========================================================

OUT_DIR = "sub/general"

REMARK = "nukcrow"

SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
}

GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10

PROTOCOL_SUB_SIZE = 200
IRAN_SUB_SIZE = 200

MAX_PER_HOST = 8


# =========================================================
# FETCH
# =========================================================

FETCH_WORKERS = 10
FETCH_TIMEOUT = 15
FETCH_RETRIES = 3

MAX_PER_SOURCE = 20000


# =========================================================
# BENCHMARK
# =========================================================

MAX_TEST = 100000

BENCH_WORKERS = 180
BENCH_TIMEOUT = 1.8

SECOND_PASS = 25000
SECOND_PASS_WORKERS = 100
SECOND_PASS_TIMEOUT = 2.0


# =========================================================
# FALLBACK
# =========================================================

# اگر کانفیگ Alive کمتر از تعداد موردنیاز باشد،
# از کانفیگ‌های valid/unique استفاده می‌شود.
ALLOW_VALID_FALLBACK = True


# =========================================================
# QUALITY
# =========================================================

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
    "tcp",
}


# =========================================================
# GENERAL SOURCES
# =========================================================

SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
]


# =========================================================
# IRAN SOURCES
# =========================================================

SOURCES_IRAN = [
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]


# =========================================================
# MCI
# =========================================================

SOURCES_MCI = []


# =========================================================
# IRANCELL
# =========================================================

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]


# =========================================================
# RIGHTEL
# =========================================================

SOURCES_RIGHTEL = []


# =========================================================
# THREAD LOCAL SESSION
# =========================================================

_thread_local = threading.local()


def session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()

        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/140.0 Safari/537.36"
            )
        })

        _thread_local.session = s

    return _thread_local.session


# =========================================================
# BASE64
# =========================================================

def decode64(value):
    if not value:
        return ""

    value = value.strip()

    try:
        value = value.replace("-", "+")
        value = value.replace("_", "/")

        padding = len(value) % 4

        if padding:
            value += "=" * (4 - padding)

        return base64.b64decode(
            value,
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:
        return ""


# =========================================================
# EXTRACT CONFIGS
# =========================================================

URI_PATTERN = re.compile(
    r"(?:"
    r"vless|"
    r"vmess|"
    r"trojan|"
    r"ss|"
    r"hysteria2|"
    r"hy2"
    r")://[^\s<>\[\]{}\"'`]+",
    re.I
)


def normalize_config(config):
    if not config:
        return ""

    config = (
        config
        .strip()
        .replace("\\/", "/")
    )

    config = unquote(config)

    # حذف remark منبع
    config = config.split("#", 1)[0].strip()

    # حذف فاصله
    config = config.replace(" ", "")

    # حذف punctuation انتهایی
    config = config.rstrip(".,;)]}>")

    return config


def extract_payload(text):
    if not text:
        return []

    text = text.replace("\r", "")

    output = []

    # -----------------------------------------------------
    # DIRECT
    # -----------------------------------------------------

    for match in URI_PATTERN.findall(text):
        config = normalize_config(match)

        if config:
            output.append(config)

    # -----------------------------------------------------
    # BASE64 WHOLE FILE
    # -----------------------------------------------------

    decoded = decode64(text)

    if decoded:
        for match in URI_PATTERN.findall(decoded):
            config = normalize_config(match)

            if config:
                output.append(config)

    # -----------------------------------------------------
    # BASE64 PER LINE
    # -----------------------------------------------------

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if "://" in line:
            continue

        if len(line) < 20:
            continue

        decoded_line = decode64(line)

        if not decoded_line:
            continue

        for match in URI_PATTERN.findall(decoded_line):
            config = normalize_config(match)

            if config:
                output.append(config)

    return output


# =========================================================
# FETCH SOURCE
# =========================================================

def fetch_source(url):
    for attempt in range(FETCH_RETRIES + 1):
        try:
            response = session().get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True
            )

            if response.ok and response.text:
                return extract_payload(
                    response.text
                )[:MAX_PER_SOURCE]

        except Exception:
            pass

        if attempt < FETCH_RETRIES:
            time.sleep(0.5)

    return []


# =========================================================
# FETCH GROUP
# =========================================================

def fetch_group(name, sources):
    if not sources:
        print(f"\n[FETCH] {name} (0 sources)")
        return []

    results = []

    print(
        f"\n[FETCH] {name} "
        f"({len(sources)} sources)"
    )

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                fetch_source,
                url
            ): url
            for url in sources
        }

        for future in as_completed(futures):
            url = futures[future]

            try:
                configs = future.result()

                results.extend(configs)

                print(
                    f"  [+] "
                    f"{len(configs):>6} "
                    f"| {url}"
                )

            except Exception:
                print(
                    f"  [-] "
                    f"{url}"
                )

    return results


# =========================================================
# FETCH ALL
# =========================================================

def fetch_all():
    return {
        "general": fetch_group(
            "GENERAL",
            SOURCES_GENERAL
        ),

        "iran": fetch_group(
            "IRAN",
            SOURCES_IRAN
        ),

        "mci": fetch_group(
            "MCI",
            SOURCES_MCI
        ),

        "irancell": fetch_group(
            "IRANCELL",
            SOURCES_IRANCELL
        ),

        "rightel": fetch_group(
            "RIGHTEL",
            SOURCES_RIGHTEL
        ),
    }


# =========================================================
# PROTOCOL
# =========================================================

def proto(config):
    try:
        return (
            config
            .split("://", 1)[0]
            .lower()
            .strip()
        )
    except Exception:
        return ""


# =========================================================
# PARSE
# =========================================================

def parsed(config):
    try:
        return urlparse(config)
    except Exception:
        return None


def query(config):
    p = parsed(config)

    if not p:
        return {}

    try:
        return parse_qs(
            p.query,
            keep_blank_values=True
        )
    except Exception:
        return {}


def q1(q, key, default=""):
    value = q.get(key)

    if not value:
        return default

    if isinstance(value, list):
        return value[0]

    return str(value)


# =========================================================
# VMESS DATA
# =========================================================

def vmess_data(config):
    if proto(config) != "vmess":
        return {}

    try:
        payload = config.split(
            "://",
            1
        )[1]
    except Exception:
        return {}

    decoded = decode64(payload)

    if not decoded:
        return {}

    try:
        data = json.loads(decoded)

        if not isinstance(data, dict):
            return {}

        return data

    except Exception:
        return {}


# =========================================================
# SS DATA
# =========================================================

def ss_data(config):
    if proto(config) != "ss":
        return {}

    p = parsed(config)

    # -----------------------------------------------------
    # SIP002 / normal SS
    # -----------------------------------------------------

    if p:
        try:
            if p.hostname and p.port:
                return {
                    "host": p.hostname,
                    "port": p.port,
                    "username": p.username or "",
                    "password": p.password or "",
                }
        except Exception:
            pass

    # -----------------------------------------------------
    # BASE64 SS
    # -----------------------------------------------------

    try:
        payload = config.split(
            "://",
            1
        )[1]
    except Exception:
        return {}

    payload = payload.split(
        "#",
        1
    )[0]

    decoded = decode64(payload)

    if not decoded:
        return {}

    decoded = decoded.strip()

    try:
        if "://" not in decoded:
            decoded = "ss://" + decoded

        p2 = urlparse(decoded)

        host = p2.hostname or ""

        try:
            port = p2.port or 0
        except Exception:
            port = 0

        if host and port:
            return {
                "host": host,
                "port": port,
                "username": p2.username or "",
                "password": p2.password or "",
            }

    except Exception:
        pass

    return {}


# =========================================================
# ENDPOINT
# =========================================================

def endpoint(config):
    ptype = proto(config)

    # -----------------------------------------------------
    # VMESS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(config)

        host = (
            data.get("add")
            or data.get("address")
            or ""
        )

        port = data.get("port") or 0

        try:
            port = int(port)
        except Exception:
            port = 0

        return (
            str(host).strip().lower(),
            port
        )

    # -----------------------------------------------------
    # SS
    # -----------------------------------------------------

    if ptype == "ss":
        data = ss_data(config)

        host = str(
            data.get("host", "")
        ).strip().lower()

        try:
            port = int(
                data.get("port", 0)
            )
        except Exception:
            port = 0

        return (
            host,
            port
        )

    # -----------------------------------------------------
    # VLESS / TROJAN / HY2
    # -----------------------------------------------------

    p = parsed(config)

    if not p:
        return "", 0

    host = p.hostname or ""

    try:
        port = p.port or 0
    except Exception:
        port = 0

    return (
        host.lower().strip(),
        port
    )


# =========================================================
# HOST CHECK
# =========================================================

def is_junk_host(host):
    if not host:
        return True

    h = host.lower().strip()

    if h in {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }:
        return True

    try:
        ip = ipaddress.ip_address(h)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        ):
            return True

    except Exception:
        pass

    return h.endswith(".local")


# =========================================================
# VALID CONFIG
# =========================================================

def valid_config(config):
    if not config:
        return False

    ptype = proto(config)

    if ptype not in SUPPORTED_PROTOCOLS:
        return False

    # -----------------------------------------------------
    # VMESS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(config)

        if not data:
            return False

        host = (
            data.get("add")
            or data.get("address")
            or ""
        )

        port = data.get("port") or 0

        try:
            port = int(port)
        except Exception:
            return False

        if not host:
            return False

        if is_junk_host(host):
            return False

        if not 1 <= port <= 65535:
            return False

        vmess_id = (
            data.get("id")
            or data.get("uuid")
            or ""
        )

        if not vmess_id:
            return False

        return True

    # -----------------------------------------------------
    # SS
    # -----------------------------------------------------

    if ptype == "ss":
        data = ss_data(config)

        host = data.get("host", "")
        port = data.get("port", 0)

        if not host:
            return False

        if is_junk_host(host):
            return False

        try:
            port = int(port)
        except Exception:
            return False

        if not 1 <= port <= 65535:
            return False

        return True

    # -----------------------------------------------------
    # OTHER PROTOCOLS
    # -----------------------------------------------------

    p = parsed(config)

    if not p:
        return False

    host, port = endpoint(config)

    if not host:
        return False

    if is_junk_host(host):
        return False

    if not 1 <= port <= 65535:
        return False

    # -----------------------------------------------------
    # VLESS
    # -----------------------------------------------------

    if ptype == "vless":
        if not p.username:
            return False

        if len(p.username) < 8:
            return False

    # -----------------------------------------------------
    # TROJAN
    # -----------------------------------------------------

    elif ptype == "trojan":
        if not p.username:
            return False

    # -----------------------------------------------------
    # HYSTERIA2
    # -----------------------------------------------------

    elif ptype in {
        "hysteria2",
        "hy2",
    }:
        if not p.username:
            return False

    return True


# =========================================================
# IDENTITY
# =========================================================

def config_identity(config):
    ptype = proto(config)

    # VMESS
    if ptype == "vmess":
        data = vmess_data(config)

        return (
            str(
                data.get("id")
                or data.get("uuid")
                or ""
            )
            .strip()
            .lower()
        )

    # SS
    if ptype == "ss":
        data = ss_data(config)

        return (
            str(
                data.get("username")
                or data.get("password")
                or ""
            )
            .strip()
            .lower()
        )

    # Normal URL protocols
    p = parsed(config)

    if not p:
        return ""

    return (
        str(
            p.username
            or ""
        )
        .strip()
        .lower()
    )


# =========================================================
# FINGERPRINT
# =========================================================

def fingerprint(config):
    ptype = proto(config)

    q = query(config)

    host, port = endpoint(config)

    security = q1(
        q,
        "security",
        q1(
            q,
            "tls"
        )
    )

    transport = q1(
        q,
        "type",
        q1(
            q,
            "network"
        )
    )

    sni = q1(
        q,
        "sni",
        q1(
            q,
            "peer"
        )
    )

    host_header = q1(
        q,
        "host"
    )

    path = q1(
        q,
        "path"
    )

    service_name = q1(
        q,
        "serviceName"
    )

    pbk = q1(
        q,
        "pbk"
    )

    sid = q1(
        q,
        "sid"
    )

    identity = config_identity(config)

    # VMESS fields
    if ptype == "vmess":
        data = vmess_data(config)

        transport = (
            data.get("net")
            or data.get("type")
            or transport
            or ""
        )

        security = (
            data.get("tls")
            or security
            or ""
        )

        sni = (
            data.get("sni")
            or data.get("host")
            or sni
            or ""
        )

        path = (
            data.get("path")
            or path
            or ""
        )

    return "|".join(
        str(x)
        .strip()
        .lower()
        for x in (
            ptype,
            host,
            port,
            identity,
            security,
            transport,
            sni,
            host_header,
            path,
            service_name,
            pbk,
            sid,
        )
    )


# =========================================================
# DEDUPE
# =========================================================

def dedupe(configs):
    seen = set()
    output = []

    for config in configs:
        config = normalize_config(config)

        if not valid_config(config):
            continue

        fp = fingerprint(config)

        if fp in seen:
            continue

        seen.add(fp)
        output.append(config)

    return output


# =========================================================
# QUALITY SCORE
# =========================================================

def quality_score(config):
    score = 0

    ptype = proto(config)

    q = query(config)

    host, port = endpoint(config)

    # -----------------------------------------------------
    # Protocol
    # -----------------------------------------------------

    if ptype in {
        "vless",
        "vmess",
        "trojan",
    }:
        score += 20

    elif ptype in {
        "hysteria2",
        "hy2",
    }:
        score += 18

    elif ptype == "ss":
        score += 15

    # -----------------------------------------------------
    # VMESS specific
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(config)

        transport = str(
            data.get("net")
            or data.get("type")
            or ""
        ).lower()

        security = str(
            data.get("tls")
            or ""
        ).lower()

        sni = str(
            data.get("sni")
            or data.get("host")
            or ""
        )

        path = str(
            data.get("path")
            or ""
        )

    else:
        transport = q1(
            q,
            "type",
            q1(
                q,
                "network"
            )
        ).lower()

        security = q1(
            q,
            "security"
        ).lower()

        sni = q1(
            q,
            "sni"
        )

        path = q1(
            q,
            "path"
        )

    # -----------------------------------------------------
    # Transport
    # -----------------------------------------------------

    if transport in PREFERRED_TYPES:
        score += 20

    # -----------------------------------------------------
    # TLS
    # -----------------------------------------------------

    if security in {
        "tls",
        "reality",
    }:
        score += 15

    if sni:
        score += 10

    # -----------------------------------------------------
    # Ports
    # -----------------------------------------------------

    if port == 443:
        score += 12

    elif port in {
        80,
        8443,
        2053,
        2083,
        2087,
        2096,
    }:
        score += 8

    # -----------------------------------------------------
    # Host
    # -----------------------------------------------------

    if host:
        try:
            ipaddress.ip_address(host)
            score += 2

        except Exception:
            if "." in host:
                score += 8

    # -----------------------------------------------------
    # Path
    # -----------------------------------------------------

    if path:
        score += 5

    if q1(q, "serviceName"):
        score += 4

    return score


# =========================================================
# TCP PROBE
# =========================================================

def tcp_probe(item):
    config, timeout = item

    host, port = endpoint(config)

    if not host or not port:
        return None

    start = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout
        ):
            latency = (
                time.perf_counter()
                - start
            )

            return (
                config,
                latency
            )

    except Exception:
        return None


# =========================================================
# BENCHMARK
# =========================================================

def benchmark(configs):
    if not configs:
        return []

    candidates = configs[:MAX_TEST]

    results = []

    print(
        f"\n[BENCH] testing "
        f"{len(candidates)} configs..."
    )

    with ThreadPoolExecutor(
        max_workers=BENCH_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                tcp_probe,
                (
                    config,
                    BENCH_TIMEOUT
                )
            )
            for config in candidates
        ]

        for future in as_completed(futures):
            try:
                result = future.result()

                if result:
                    config, latency = result

                    results.append({
                        "config": config,
                        "latency": latency,
                        "score": quality_score(
                            config
                        ),
                    })

            except Exception:
                pass

    # -----------------------------------------------------
    # SECOND PASS
    # -----------------------------------------------------

    if len(results) < SECOND_PASS:
        remaining = configs[
            MAX_TEST:
            MAX_TEST + SECOND_PASS
        ]

        if remaining:
            print(
                f"[BENCH] second pass: "
                f"{len(remaining)} configs"
            )

            with ThreadPoolExecutor(
                max_workers=SECOND_PASS_WORKERS
            ) as executor:

                futures = [
                    executor.submit(
                        tcp_probe,
                        (
                            config,
                            SECOND_PASS_TIMEOUT
                        )
                    )
                    for config in remaining
                ]

                for future in as_completed(futures):
                    try:
                        result = future.result()

                        if result:
                            config, latency = result

                            results.append({
                                "config": config,
                                "latency": latency,
                                "score": quality_score(
                                    config
                                ),
                            })

                    except Exception:
                        pass

    # -----------------------------------------------------
    # DEDUPE ALIVE
    # -----------------------------------------------------

    unique = {}

    for item in results:
        fp = fingerprint(
            item["config"]
        )

        old = unique.get(fp)

        if old is None:
            unique[fp] = item
            continue

        if (
            item["score"],
            -item["latency"]
        ) > (
            old["score"],
            -old["latency"]
        ):
            unique[fp] = item

    results = list(
        unique.values()
    )

    results.sort(
        key=lambda x: (
            -x["score"],
            x["latency"]
        )
    )

    print(
        f"[BENCH] alive: "
        f"{len(results)}"
    )

    return results


# =========================================================
# RAW CONFIG -> RECORD
# =========================================================

def config_record(config):
    return {
        "config": config,
        "latency": 999.0,
        "score": quality_score(config),
    }


def records_from_configs(configs):
    return [
        config_record(config)
        for config in configs
    ]


# =========================================================
# MERGE ALIVE + VALID FALLBACK
# =========================================================

def merge_records(
    alive_records,
    valid_configs
):
    output = []
    seen = set()

    # -----------------------------------------------------
    # ALIVE FIRST
    # -----------------------------------------------------

    for item in alive_records:
        config = item["config"]

        fp = fingerprint(config)

        if fp in seen:
            continue

        seen.add(fp)
        output.append(item)

    # -----------------------------------------------------
    # VALID FALLBACK
    # -----------------------------------------------------

    if ALLOW_VALID_FALLBACK:
        fallback_records = records_from_configs(
            valid_configs
        )

        fallback_records.sort(
            key=lambda x: -x["score"]
        )

        for item in fallback_records:
            config = item["config"]

            fp = fingerprint(config)

            if fp in seen:
                continue

            seen.add(fp)
            output.append(item)

    return output


# =========================================================
# SELECT
# =========================================================

def select_records(
    results,
    limit,
    predicate=None
):
    if not results or limit <= 0:
        return []

    selected = []
    seen = set()

    # -----------------------------------------------------
    # PASS 1
    # Diverse hosts
    # -----------------------------------------------------

    host_count = {}

    for item in results:
        if len(selected) >= limit:
            break

        config = item["config"]

        if predicate and not predicate(config):
            continue

        fp = fingerprint(config)

        if fp in seen:
            continue

        host, _ = endpoint(config)

        if host_count.get(
            host,
            0
        ) >= MAX_PER_HOST:
            continue

        selected.append(item)
        seen.add(fp)

        host_count[host] = (
            host_count.get(host, 0)
            + 1
        )

    # -----------------------------------------------------
    # PASS 2
    # Fill quantity
    # -----------------------------------------------------

    if len(selected) < limit:
        for item in results:
            if len(selected) >= limit:
                break

            config = item["config"]

            if predicate and not predicate(config):
                continue

            fp = fingerprint(config)

            if fp in seen:
                continue

            selected.append(item)
            seen.add(fp)

    return selected[:limit]


# =========================================================
# SELECT ALIVE + VALID
# =========================================================

def select_subscription(
    alive_records,
    valid_configs,
    limit,
    predicate=None
):
    combined = merge_records(
        alive_records,
        valid_configs
    )

    return select_records(
        combined,
        limit,
        predicate=predicate
    )


# =========================================================
# ONLY NUKCROW REMARK
# =========================================================

def config_line(config):
    config = config.split(
        "#",
        1
    )[0].strip()

    return (
        config
        + "#"
        + REMARK
    )


# =========================================================
# WRITE FILE
# =========================================================

def write_file(
    path,
    records,
    limit=None
):
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    if limit is not None:
        records = records[:limit]

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        written = 0

        for item in records:
            config = item.get(
                "config",
                ""
            )

            if not config:
                continue

            f.write(
                config_line(config)
                + "\n"
            )

            written += 1

            if limit is not None and written >= limit:
                break


# =========================================================
# CLEAR OLD
# =========================================================

def clear_old_subscriptions():
    os.makedirs(
        OUT_DIR,
        exist_ok=True
    )

    for filename in os.listdir(
        OUT_DIR
    ):
        if not filename.endswith(
            ".txt"
        ):
            continue

        path = os.path.join(
            OUT_DIR,
            filename
        )

        try:
            os.remove(path)
        except Exception:
            pass


# =========================================================
# GENERAL
# =========================================================

def write_general(
    alive_all,
    all_unique
):
    total = (
        GENERAL_SUB_SIZE
        * GENERAL_SUB_COUNT
    )

    selected = select_subscription(
        alive_all,
        all_unique,
        total
    )

    # -----------------------------------------------------
    # all_configs.txt
    # -----------------------------------------------------

    write_file(
        os.path.join(
            OUT_DIR,
            "all_configs.txt"
        ),
        selected,
        limit=total
    )

    # -----------------------------------------------------
    # sub1 ... sub10
    # -----------------------------------------------------

    for i in range(
        GENERAL_SUB_COUNT
    ):
        start = (
            i
            * GENERAL_SUB_SIZE
        )

        end = (
            start
            + GENERAL_SUB_SIZE
        )

        write_file(
            os.path.join(
                OUT_DIR,
                f"sub{i + 1}.txt"
            ),
            selected[
                start:end
            ],
            limit=GENERAL_SUB_SIZE
        )

    print(
        f"\n[GENERAL] "
        f"{len(selected)}/{total}"
    )


# =========================================================
# PROTOCOLS
# =========================================================

def write_protocols(
    alive_all,
    all_unique
):
    protocols = (
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    )

    for ptype in protocols:
        selected = select_subscription(
            alive_all,
            all_unique,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype:
                proto(c) == p
        )

        write_file(
            os.path.join(
                OUT_DIR,
                f"{ptype}.txt"
            ),
            selected,
            limit=PROTOCOL_SUB_SIZE
        )

        print(
            f"[{ptype.upper():>9}] "
            f"{len(selected)}/{PROTOCOL_SUB_SIZE}"
        )


# =========================================================
# IRAN
# =========================================================

def write_iran(
    iran_alive,
    iran_unique,
    mci_alive,
    mci_unique,
    irancell_alive,
    irancell_unique,
    rightel_alive,
    rightel_unique,
    all_alive,
    all_unique
):

    # -----------------------------------------------------
    # BEST IRAN
    # -----------------------------------------------------

    best_iran = select_subscription(
        iran_alive,
        iran_unique + all_unique,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "best_iran.txt"
        ),
        best_iran,
        limit=IRAN_SUB_SIZE
    )

    print(
        f"[BEST IRAN] "
        f"{len(best_iran)}/{IRAN_SUB_SIZE}"
    )

    # -----------------------------------------------------
    # MIX IRAN
    # -----------------------------------------------------

    mix_combined = merge_records(
        iran_alive,
        iran_unique
    )

    global_fallback = merge_records(
        all_alive,
        all_unique
    )

    random.shuffle(
        mix_combined
    )

    random.shuffle(
        global_fallback
    )

    mix_records = (
        mix_combined
        + global_fallback
    )

    mix_iran = select_records(
        mix_records,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "mix_iran.txt"
        ),
        mix_iran,
        limit=IRAN_SUB_SIZE
    )

    print(
        f"[MIX IRAN] "
        f"{len(mix_iran)}/{IRAN_SUB_SIZE}"
    )

    # -----------------------------------------------------
    # MCI
    # -----------------------------------------------------

    mci = select_subscription(
        mci_alive,
        mci_unique
        + iran_unique
        + all_unique,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "mci.txt"
        ),
        mci,
        limit=IRAN_SUB_SIZE
    )

    print(
        f"[MCI] "
        f"{len(mci)}/{IRAN_SUB_SIZE}"
    )

    # -----------------------------------------------------
    # IRANCELL
    # -----------------------------------------------------

    irancell = select_subscription(
        irancell_alive,
        irancell_unique
        + iran_unique
        + all_unique,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "irancell.txt"
        ),
        irancell,
        limit=IRAN_SUB_SIZE
    )

    print(
        f"[IRANCELL] "
        f"{len(irancell)}/{IRAN_SUB_SIZE}"
    )

    # -----------------------------------------------------
    # RIGHTEL
    # -----------------------------------------------------

    rightel = select_subscription(
        rightel_alive,
        rightel_unique
        + iran_unique
        + all_unique,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "rightel.txt"
        ),
        rightel,
        limit=IRAN_SUB_SIZE
    )

    print(
        f"[RIGHTEL] "
        f"{len(rightel)}/{IRAN_SUB_SIZE}"
    )


# =========================================================
# SUMMARY
# =========================================================

def print_summary():
    print(
        "\n"
        + "=" * 65
    )

    print(
        "NUKCROW SUBSCRIPTIONS"
    )

    print(
        "=" * 65
    )

    if not os.path.isdir(
        OUT_DIR
    ):
        return

    files = []

    for filename in os.listdir(
        OUT_DIR
    ):
        if filename.endswith(
            ".txt"
        ):
            files.append(filename)

    for filename in sorted(files):
        path = os.path.join(
            OUT_DIR,
            filename
        )

        try:
            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:
                count = sum(
                    1
                    for line in f
                    if line.strip()
                )

            print(
                f"{filename:<25}"
                f"{count:>6}"
            )

        except Exception:
            pass

    print(
        "=" * 65
    )


# =========================================================
# MAIN
# =========================================================

def main():
    started = time.time()

    print(
        "=" * 65
    )

    print(
        "NUKCROW COLLECTOR"
    )

    print(
        "=" * 65
    )

    os.makedirs(
        OUT_DIR,
        exist_ok=True
    )

    # -----------------------------------------------------
    # FETCH
    # -----------------------------------------------------

    raw = fetch_all()

    # -----------------------------------------------------
    # DEDUPE SOURCE POOLS
    # -----------------------------------------------------

    print("\n[DEDUPE]")

    general_unique = dedupe(
        raw["general"]
    )

    iran_unique = dedupe(
        raw["iran"]
    )

    mci_unique = dedupe(
        raw["mci"]
    )

    irancell_unique = dedupe(
        raw["irancell"]
    )

    rightel_unique = dedupe(
        raw["rightel"]
    )

    print(
        f"GENERAL  : {len(general_unique)}"
    )

    print(
        f"IRAN     : {len(iran_unique)}"
    )

    print(
        f"MCI      : {len(mci_unique)}"
    )

    print(
        f"IRANCELL : {len(irancell_unique)}"
    )

    print(
        f"RIGHTEL  : {len(rightel_unique)}"
    )

    # -----------------------------------------------------
    # GLOBAL
    # -----------------------------------------------------

    all_unique = dedupe(
        general_unique
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
    )

    print(
        f"\nGLOBAL UNIQUE: "
        f"{len(all_unique)}"
    )

    # -----------------------------------------------------
    # BENCHMARK GLOBAL
    # -----------------------------------------------------

    alive_all = benchmark(
        all_unique
    )

    # -----------------------------------------------------
    # BENCHMARK IRAN
    # -----------------------------------------------------

    alive_iran = benchmark(
        iran_unique
    )

    # -----------------------------------------------------
    # BENCHMARK MCI
    # -----------------------------------------------------

    alive_mci = benchmark(
        mci_unique
    )

    # -----------------------------------------------------
    # BENCHMARK IRANCELL
    # -----------------------------------------------------

    alive_irancell = benchmark(
        irancell_unique
    )

    # -----------------------------------------------------
    # BENCHMARK RIGHTEL
    # -----------------------------------------------------

    alive_rightel = benchmark(
        rightel_unique
    )

    # -----------------------------------------------------
    # CLEAR OLD
    # -----------------------------------------------------

    clear_old_subscriptions()

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    write_general(
        alive_all,
        all_unique
    )

    # -----------------------------------------------------
    # PROTOCOLS
    # -----------------------------------------------------

    write_protocols(
        alive_all,
        all_unique
    )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    write_iran(
        alive_iran,
        iran_unique,

        alive_mci,
        mci_unique,

        alive_irancell,
        irancell_unique,

        alive_rightel,
        rightel_unique,

        alive_all,
        all_unique
    )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print_summary()

    elapsed = (
        time.time()
        - started
    )

    print(
        f"\nDONE: "
        f"{elapsed:.2f}s"
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    main()
