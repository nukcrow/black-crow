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


# ============================================================
# CONFIG
# ============================================================

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
GENERAL_TOTAL = GENERAL_SUB_SIZE * GENERAL_SUB_COUNT

PROTOCOL_SUB_SIZE = 100
IRAN_SUB_SIZE = 200

MAX_PER_HOST = 8

FETCH_WORKERS = 10
FETCH_TIMEOUT = 15
FETCH_RETRIES = 3
MAX_PER_SOURCE = 20000

MAX_TEST = 30000
BENCH_WORKERS = 100
BENCH_TIMEOUT = 1.8

SECOND_PASS = 8000
SECOND_PASS_WORKERS = 60
SECOND_PASS_TIMEOUT = 1.8

ALLOW_VALID_FALLBACK = True

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
    "tcp",
}


# ============================================================
# SOURCES
# ============================================================

SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
]

SOURCES_IRAN = [
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]

SOURCES_MCI = []

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
]

SOURCES_RIGHTEL = []


# ============================================================
# GLOBAL STATE
# ============================================================

_thread_local = threading.local()

SOURCE_META = {}
SOURCE_META_LOCK = threading.Lock()


# ============================================================
# HTTP SESSION
# ============================================================

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


# ============================================================
# BASE64
# ============================================================

def decode64(value):
    if not value:
        return ""

    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")

    value += "=" * (-len(value) % 4)

    try:
        return base64.b64decode(
            value,
            validate=False,
        ).decode(
            "utf-8",
            errors="ignore",
        )
    except Exception:
        return ""


# ============================================================
# EXTRACTION
# ============================================================

URI_PATTERN = re.compile(
    r"""(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>\[\]{}"'`]+""",
    re.IGNORECASE,
)


def normalize_config(config):
    if not config:
        return ""

    config = config.strip()
    config = unquote(config)

    config = config.replace("\\n", "")
    config = config.replace("\n", "")
    config = config.replace("\r", "")

    if "#" in config:
        config = config.split("#", 1)[0]

    config = config.strip().strip("'\"`")

    return config


def extract_uris(text):
    if not text:
        return []

    found = []

    for match in URI_PATTERN.findall(text):
        config = normalize_config(match)

        if config:
            found.append(config)

    # Whole content as base64
    decoded = decode64(text.strip())

    if decoded:
        for match in URI_PATTERN.findall(decoded):
            config = normalize_config(match)

            if config:
                found.append(config)

    # Base64 per line
    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        decoded_line = decode64(line)

        if not decoded_line:
            continue

        for match in URI_PATTERN.findall(decoded_line):
            config = normalize_config(match)

            if config:
                found.append(config)

    return found


# ============================================================
# SOURCE TRACKING
# ============================================================

def config_key(config):
    return config.strip()


def register_source(config, source):
    key = config_key(config)

    with SOURCE_META_LOCK:
        SOURCE_META.setdefault(
            key,
            set(),
        ).add(source)


def source_names(config):
    key = config_key(config)

    with SOURCE_META_LOCK:
        return sorted(
            SOURCE_META.get(key, set())
        )


# ============================================================
# FETCH
# ============================================================

def fetch_source(url):
    last_error = None

    for attempt in range(FETCH_RETRIES + 1):
        try:
            response = session().get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True,
            )

            response.raise_for_status()

            text = response.text

            configs = extract_uris(text)

            if len(configs) > MAX_PER_SOURCE:
                configs = configs[:MAX_PER_SOURCE]

            for config in configs:
                register_source(
                    config,
                    url,
                )

            return configs

        except Exception as exc:
            last_error = exc

            if attempt < FETCH_RETRIES:
                time.sleep(
                    min(2 ** attempt, 5)
                )

    print(
        f"[FETCH ERROR] {url}: {last_error}"
    )

    return []


def fetch_group(sources, name):
    results = []

    if not sources:
        return results

    print(
        f"\nFetching {name}: "
        f"{len(sources)} sources"
    )

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                fetch_source,
                source,
            ): source
            for source in sources
        }

        for future in as_completed(futures):
            source = futures[future]

            try:
                configs = future.result()

                results.extend(configs)

                print(
                    f"[OK] {len(configs):5d} "
                    f"{source}"
                )

            except Exception as exc:
                print(
                    f"[ERROR] {source}: {exc}"
                )

    return results


def fetch_all():
    return {
        "general": fetch_group(
            SOURCES_GENERAL,
            "GENERAL",
        ),

        "iran": fetch_group(
            SOURCES_IRAN,
            "IRAN",
        ),

        "mci": fetch_group(
            SOURCES_MCI,
            "MCI",
        ),

        "irancell": fetch_group(
            SOURCES_IRANCELL,
            "IRANCELL",
        ),

        "rightel": fetch_group(
            SOURCES_RIGHTEL,
            "RIGHTEL",
        ),
    }


# ============================================================
# PROTOCOL
# ============================================================

def proto(config):
    return config.split("://", 1)[0].lower()


def parsed(config):
    try:
        return urlparse(config)
    except Exception:
        return None


def query(config):
    try:
        parsed_url = parsed(config)

        if not parsed_url:
            return {}

        return parse_qs(
            parsed_url.query,
            keep_blank_values=True,
        )

    except Exception:
        return {}


def q1(data, key, default=""):
    value = data.get(key)

    if not value:
        return default

    if isinstance(value, list):
        return value[0]

    return value


# ============================================================
# VMESS
# ============================================================

def vmess_data(config):
    if not config.lower().startswith("vmess://"):
        return {}

    payload = config.split(
        "://",
        1,
    )[1]

    decoded = decode64(payload)

    if not decoded:
        return {}

    try:
        data = json.loads(decoded)

        if isinstance(data, dict):
            return data

    except Exception:
        pass

    return {}


# ============================================================
# SHADOWSOCKS
# ============================================================

def ss_data(config):
    try:
        parsed_url = urlparse(config)

        if parsed_url.scheme.lower() != "ss":
            return None

        try:
            port = parsed_url.port
        except (ValueError, TypeError):
            return None

        if not port or not (1 <= port <= 65535):
            return None

        host = parsed_url.hostname
        if not host:
            return None

        username = unquote(parsed_url.username or "")
        password = unquote(parsed_url.password or "")

        if username and password:
            method = username
            secret = password
        else:
            raw = parsed_url.netloc
            if "@" not in raw:
                return None

            userinfo, hostpart = raw.rsplit("@", 1)

            if ":" not in userinfo:
                return None

            method, secret = userinfo.split(":", 1)
            method = unquote(method)
            secret = unquote(secret)

        if not method or not secret:
            return None

        return {
            "method": method,
            "password": secret,
            "host": host,
            "port": port,
        }

    except (ValueError, TypeError, UnicodeError):
        return None
    except Exception:
        return None


# ============================================================
# ENDPOINT
# ============================================================

def endpoint(config):
    ptype = proto(config)

    if ptype == "vmess":
        data = vmess_data(config)

        host = (
            data.get("add")
            or data.get("address")
            or ""
        )

        try:
            port = int(
                data.get("port") or 0
            )
        except Exception:
            port = 0

        return host, port

    if ptype == "ss":
        data = ss_data(config)

        return (
            data.get("host", ""),
            int(data.get("port", 0) or 0),
        )

    parsed_url = parsed(config)

    if not parsed_url:
        return "", 0

    return (
        parsed_url.hostname or "",
        parsed_url.port or 0,
    )


# ============================================================
# HOST VALIDATION
# ============================================================

def is_junk_host(host):
    if not host:
        return True

    host = host.strip().lower()

    if host in {
        "localhost",
        "localhost.localdomain",
    }:
        return True

    if host.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(host)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_link_local
        ):
            return True

    except ValueError:
        pass

    return False


# ============================================================
# CONFIG VALIDATION
# ============================================================

def valid_config(config):
    try:
        config = config.strip()

        if not config:
            return False

        p = proto(config)

        if p not in SUPPORTED_PROTOCOLS:
            return False

        host, port = endpoint(config)

        if not host or not port:
            return False

        if not (1 <= int(port) <= 65535):
            return False

        if not valid_host(host):
            return False

        if p == "ss":
            data = ss_data(config)
            if not data:
                return False

        return True

    except (ValueError, TypeError, UnicodeError):
        return False
    except Exception:
        return False


# ============================================================
# NORMALIZATION / DEDUPE
# ============================================================

def dedupe(configs):
    result = []
    seen = set()

    for config in configs:
        config = normalize_config(config)

        if not config:
            continue

        if not valid_config(config):
            continue

        key = config_fingerprint(config)

        if key in seen:
            continue

        seen.add(key)
        result.append(config)

    return result


# ============================================================
# IDENTITY
# ============================================================

def config_identity(config):
    ptype = proto(config)

    if ptype == "vmess":
        data = vmess_data(config)

        return (
            data.get("id")
            or data.get("uuid")
            or ""
        ).lower()

    if ptype == "ss":
        data = ss_data(config)

        return (
            data.get("method", "")
            + ":"
            + data.get("password", "")
        )

    parsed_url = parsed(config)

    if not parsed_url:
        return ""

    return unquote(
        parsed_url.username or ""
    )


# ============================================================
# FINGERPRINT
# ============================================================

def config_fingerprint(config):
    ptype = proto(config)
    host, port = endpoint(config)

    transport = ""
    security = ""
    sni = ""
    host_header = ""
    path = ""
    service_name = ""
    pbk = ""
    sid = ""
    flow = ""
    fp = ""

    if ptype == "vmess":
        data = vmess_data(config)

        transport = str(
            data.get("net")
            or data.get("type")
            or ""
        ).lower()

        security = str(
            data.get("tls")
            or data.get("security")
            or ""
        ).lower()

        sni = str(
            data.get("sni")
            or data.get("host")
            or ""
        ).lower()

        host_header = str(
            data.get("host")
            or ""
        ).lower()

        path = str(
            data.get("path")
            or ""
        )

        service_name = str(
            data.get("path")
            or data.get("serviceName")
            or ""
        )

        pbk = str(
            data.get("pbk")
            or ""
        )

        sid = str(
            data.get("sid")
            or ""
        )

        flow = str(
            data.get("flow")
            or ""
        )

        fp = str(
            data.get("fp")
            or ""
        )

    else:
        q = query(config)

        transport = (
            q1(q, "type")
            or q1(q, "mode")
            or ""
        ).lower()

        security = (
            q1(q, "security")
            or q1(q, "tls")
            or ""
        ).lower()

        sni = (
            q1(q, "sni")
            or q1(q, "serverName")
            or ""
        ).lower()

        host_header = (
            q1(q, "host")
            or q1(q, "hostHeader")
            or ""
        ).lower()

        path = q1(q, "path")

        service_name = (
            q1(q, "serviceName")
        )

        pbk = q1(q, "pbk")
        sid = q1(q, "sid")
        flow = q1(q, "flow")
        fp = q1(q, "fp")

    identity = config_identity(config)

    return "|".join([
        ptype,
        host.lower(),
        str(port),
        identity,
        security,
        transport,
        sni,
        host_header,
        path,
        service_name,
        pbk,
        sid,
        flow,
        fp,
    ])


# ============================================================
# QUALITY SCORE
# ============================================================

def quality_score(config):
    score = 0
    ptype = proto(config)

    if ptype in SUPPORTED_PROTOCOLS:
        score += 10

    host, port = endpoint(config)

    if port == 443:
        score += 8
    elif port in {
        80,
        8443,
        2053,
        2083,
        2087,
        2096,
    }:
        score += 4

    q = query(config)

    transport = (
        q1(q, "type")
        or q1(q, "mode")
        or ""
    ).lower()

    if ptype == "vmess":
        data = vmess_data(config)

        transport = str(
            data.get("net")
            or data.get("type")
            or transport
        ).lower()

        security = str(
            data.get("tls")
            or data.get("security")
            or ""
        ).lower()

        sni = (
            data.get("sni")
            or data.get("host")
            or ""
        )

        path = (
            data.get("path")
            or ""
        )

        service_name = (
            data.get("serviceName")
            or ""
        )

        pbk = data.get("pbk") or ""
        sid = data.get("sid") or ""

    else:
        security = (
            q1(q, "security")
            or q1(q, "tls")
            or ""
        ).lower()

        sni = (
            q1(q, "sni")
            or q1(q, "serverName")
            or ""
        )

        path = q1(q, "path")
        service_name = q1(
            q,
            "serviceName",
        )

        pbk = q1(q, "pbk")
        sid = q1(q, "sid")

    if transport in PREFERRED_TYPES:
        score += 8

    if security in {
        "tls",
        "reality",
    }:
        score += 8

    if sni:
        score += 4

    if path:
        score += 2

    if service_name:
        score += 2

    if pbk:
        score += 5

    if sid:
        score += 2

    if host:
        if not re.match(
            r"^\d{1,3}(?:\.\d{1,3}){3}$",
            host,
        ):
            score += 3

    return score


# ============================================================
# BENCHMARK
# ============================================================

def _benchmark_pass(
    config,
    timeout,
):
    host, port = endpoint(config)

    started = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            latency = (
                time.perf_counter()
                - started
            ) * 1000

            return latency

    except Exception:
        return None


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


def benchmark(configs):
    if not configs:
        return []

    candidates = configs[
        :MAX_TEST
    ]

    alive = []

    print(
        f"\nBenchmarking "
        f"{len(candidates)} configs..."
    )

    with ThreadPoolExecutor(
        max_workers=BENCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                _benchmark_pass,
                config,
                BENCH_TIMEOUT,
            ): config
            for config in candidates
        }

        for future in as_completed(futures):
            config = futures[future]

            try:
                latency = future.result()

                if latency is None:
                    continue

                record = config_record(
                    config
                )

                record["latency"] = latency

                alive.append(record)

            except Exception:
                continue

    # Second pass if needed
    if (
        len(alive) < SECOND_PASS
        and len(configs) > len(candidates)
    ):
        extra = configs[
            len(candidates):
            len(candidates) + SECOND_PASS
        ]

        print(
            f"Second benchmark pass: "
            f"{len(extra)} configs"
        )

        with ThreadPoolExecutor(
            max_workers=SECOND_PASS_WORKERS
        ) as executor:

            futures = {
                executor.submit(
                    _benchmark_pass,
                    config,
                    SECOND_PASS_TIMEOUT,
                ): config
                for config in extra
            }

            for future in as_completed(futures):
                config = futures[future]

                try:
                    latency = future.result()

                    if latency is None:
                        continue

                    record = config_record(
                        config
                    )

                    record["latency"] = latency

                    alive.append(record)

                except Exception:
                    continue

    # Fingerprint dedupe
    unique = {}
    for record in alive:
        fp = config_fingerprint(
            record["config"]
        )

        old = unique.get(fp)

        if old is None:
            unique[fp] = record
            continue

        if (
            record["latency"]
            < old["latency"]
        ):
            unique[fp] = record

    alive = list(unique.values())

    alive.sort(
        key=lambda item: (
            -item["score"],
            item["latency"],
        )
    )

    print(
        f"Alive TCP configs: {len(alive)}"
    )

    return alive


# ============================================================
# RECORD MERGE
# ============================================================

def merge_records(
    alive_records,
    valid_configs,
):
    result = []
    seen = set()

    for record in alive_records:
        config = record["config"]

        fp = config_fingerprint(
            config
        )

        if fp in seen:
            continue

        seen.add(fp)
        result.append(record)

    if ALLOW_VALID_FALLBACK:
        for config in valid_configs:
            fp = config_fingerprint(
                config
            )

            if fp in seen:
                continue

            seen.add(fp)

            result.append(
                config_record(config)
            )

    return result


# ============================================================
# SELECTION
# ============================================================

def select_records(
    results,
    limit,
    predicate=None,
):
    selected = []
    seen = set()
    host_counts = {}

    for record in results:
        config = record["config"]

        if predicate and not predicate(
            config
        ):
            continue

        fp = config_fingerprint(
            config
        )

        if fp in seen:
            continue

        host, _ = endpoint(config)

        host_key = host.lower()

        if (
            host_counts.get(host_key, 0)
            >= MAX_PER_HOST
        ):
            continue

        seen.add(fp)

        host_counts[host_key] = (
            host_counts.get(
                host_key,
                0,
            ) + 1
        )

        selected.append(record)

        if len(selected) >= limit:
            break

    return selected


def select_subscription(
    alive_records,
    valid_configs,
    limit,
    predicate=None,
):
    merged = merge_records(
        alive_records,
        valid_configs,
    )

    return select_records(
        merged,
        limit,
        predicate,
    )


# ============================================================
# RENDER
# ============================================================

def config_line(config):
    config = normalize_config(
        config
    )

    return (
        config
        + "#"
        + REMARK
    )


def render_records(records):
    lines = []

    for record in records:
        lines.append(
            config_line(
                record["config"]
            )
        )

    return lines


# ============================================================
# FILE WRITING
# ============================================================

def atomic_write_lines(
    path,
    lines,
):
    directory = os.path.dirname(path)

    os.makedirs(
        directory,
        exist_ok=True,
    )

    temp_path = (
        path
        + ".tmp"
    )

    with open(
        temp_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:
        for line in lines:
            f.write(
                line.rstrip("\r\n")
                + "\n"
            )

    os.replace(
        temp_path,
        path,
    )


def count_nonempty_lines(path):
    if not os.path.exists(path):
        return 0

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as f:
        return sum(
            1
            for line in f
            if line.strip()
        )


def write_file(
    filename,
    lines,
):
    path = os.path.join(
        OUT_DIR,
        filename,
    )

    atomic_write_lines(
        path,
        lines,
    )

    print(
        f"[WRITE] {filename}: "
        f"{len(lines)}"
    )


# ============================================================
# GENERAL SUBSCRIPTIONS
# ============================================================

def write_general(
    alive_all,
    all_unique,
):
    print("\nWriting general subscriptions...")

    selected = select_subscription(
        alive_all,
        all_unique,
        GENERAL_TOTAL,
    )

    if len(selected) < GENERAL_TOTAL:
        raise RuntimeError(
            "Not enough configs for "
            f"general subscriptions: "
            f"{len(selected)}/"
            f"{GENERAL_TOTAL}"
        )

    selected = selected[
        :GENERAL_TOTAL
    ]

    all_lines = render_records(
        selected
    )

    # --------------------------------------------------------
    # all_configs.txt
    # --------------------------------------------------------

    write_file(
        "all_configs.txt",
        all_lines,
    )

    # --------------------------------------------------------
    # sub1.txt ... sub10.txt
    #
    # دقیقاً از روی all_configs ساخته می‌شوند
    # --------------------------------------------------------

    for index in range(
        GENERAL_SUB_COUNT
    ):
        start = (
            index
            * GENERAL_SUB_SIZE
        )

        end = (
            start
            + GENERAL_SUB_SIZE
        )

        sub_lines = all_lines[
            start:end
        ]

        if len(sub_lines) != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"sub{index + 1}.txt "
                f"must contain "
                f"{GENERAL_SUB_SIZE} configs"
            )

        write_file(
            f"sub{index + 1}.txt",
            sub_lines,
        )

    # --------------------------------------------------------
    # Final order check
    # --------------------------------------------------------

    rebuilt = []

    for index in range(
        GENERAL_SUB_COUNT
    ):
        path = os.path.join(
            OUT_DIR,
            f"sub{index + 1}.txt",
        )

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:
            rebuilt.extend(
                line.strip()
                for line in f
                if line.strip()
            )

    if rebuilt != all_lines:
        raise RuntimeError(
            "sub1..sub10 order does not "
            "match all_configs.txt"
        )


# ============================================================
# PROTOCOL FILES
# ============================================================

def write_protocols(
    alive_all,
    all_unique,
):
    print("\nWriting protocol subscriptions...")

    for ptype in [
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    ]:
        selected = select_subscription(
            alive_all,
            all_unique,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype:
                proto(c) == p,
        )

        if not selected:
            print(
                f"[WARN] No {ptype} configs"
            )
            continue

        lines = render_records(
            selected
        )

        write_file(
            f"{ptype}.txt",
            lines,
        )


# ============================================================
# FILL
# ============================================================

def fill_records(
    primary,
    fallback_groups,
    limit,
):
    combined = []

    for group in [primary] + fallback_groups:
        combined.extend(group)

    selected = select_records(
        combined,
        limit,
    )

    return selected


# ============================================================
# IRAN / OPERATORS
# ============================================================

def write_iran(
    alive_iran,
    iran_unique,

    alive_mci,
    mci_unique,

    alive_irancell,
    irancell_unique,

    alive_rightel,
    rightel_unique,

    alive_all,
    all_unique,
):
    print(
        "\nWriting Iran/operator subscriptions..."
    )

    global_records = merge_records(
        alive_all,
        all_unique,
    )

    iran_records = merge_records(
        alive_iran,
        iran_unique,
    )

    mci_records = merge_records(
        alive_mci,
        mci_unique,
    )

    irancell_records = merge_records(
        alive_irancell,
        irancell_unique,
    )

    rightel_records = merge_records(
        alive_rightel,
        rightel_unique,
    )

    # ========================================================
    # MCI
    # ========================================================

    mci_selected = fill_records(
        mci_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(mci_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create mci.txt"
        )

    write_file(
        "mci.txt",
        render_records(
            mci_selected
        ),
    )

    # ========================================================
    # IRANCELL
    # ========================================================

    irancell_selected = fill_records(
        irancell_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(irancell_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create irancell.txt"
        )

    write_file(
        "irancell.txt",
        render_records(
            irancell_selected
        ),
    )

    # ========================================================
    # RIGHTEL
    # ========================================================

    rightel_selected = fill_records(
        rightel_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(rightel_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create rightel.txt"
        )

    write_file(
        "rightel.txt",
        render_records(
            rightel_selected
        ),
    )

    # ========================================================
    # BEST IRAN
    # ========================================================

    best_iran_selected = fill_records(
        iran_records,
        [
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(best_iran_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create best_iran.txt"
        )

    write_file(
        "best_iran.txt",
        render_records(
            best_iran_selected
        ),
    )

    # ========================================================
    # MIX IRAN
    # ========================================================

    mix_pool = (
        iran_records
        + global_records
    )

    # deterministic-ish randomization per run
    random.shuffle(
        mix_pool
    )

    mix_selected = select_records(
        mix_pool,
        IRAN_SUB_SIZE,
    )

    if len(mix_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create mix_iran.txt"
        )

    write_file(
        "mix_iran.txt",
        render_records(
            mix_selected
        ),
    )


# ============================================================
# SOURCE SUMMARY
# ============================================================

def print_source_summary():
    print("\n" + "=" * 65)
    print("SOURCE SUMMARY")
    print("=" * 65)

    with SOURCE_META_LOCK:
        items = list(
            SOURCE_META.items()
        )

    source_counts = {}

    for _, sources in items:
        for source in sources:
            source_counts[source] = (
                source_counts.get(
                    source,
                    0,
                )
                + 1
            )

    for source, count in sorted(
        source_counts.items(),
        key=lambda x: -x[1],
    ):
        print(
            f"{count:6d}  {source}"
        )


# ============================================================
# OUTPUT VERIFICATION
# ============================================================

EXPECTED_FILES = [
    "all_configs.txt",

    "sub1.txt",
    "sub2.txt",
    "sub3.txt",
    "sub4.txt",
    "sub5.txt",
    "sub6.txt",
    "sub7.txt",
    "sub8.txt",
    "sub9.txt",
    "sub10.txt",

    "mci.txt",
    "irancell.txt",
    "rightel.txt",

    "best_iran.txt",
    "mix_iran.txt",

    "vless.txt",
    "vmess.txt",
    "trojan.txt",
    "ss.txt",
    "hysteria2.txt",
]


def read_lines(path):
    if not os.path.exists(path):
        return []

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as f:
        return [
            line.rstrip("\r\n")
            for line in f
            if line.strip()
        ]


def verify_outputs():
    print(
        "\nVerifying outputs..."
    )

    expected = set(
        EXPECTED_FILES
    )

    actual = {
        name
        for name in os.listdir(OUT_DIR)
        if name.endswith(".txt")
    }

    # --------------------------------------------------------
    # No unexpected files
    # --------------------------------------------------------

    unexpected = actual - expected

    if unexpected:
        raise RuntimeError(
            "Unexpected output files: "
            + ", ".join(
                sorted(unexpected)
            )
        )

    # --------------------------------------------------------
    # random_200.txt must not exist
    # --------------------------------------------------------

    random_200 = os.path.join(
        OUT_DIR,
        "random_200.txt",
    )

    if os.path.exists(random_200):
        raise RuntimeError(
            "random_200.txt must not exist"
        )

    # --------------------------------------------------------
    # Required files
    # --------------------------------------------------------

    missing = expected - actual

    if missing:
        raise RuntimeError(
            "Missing output files: "
            + ", ".join(
                sorted(missing)
            )
        )

    # --------------------------------------------------------
    # all_configs
    # --------------------------------------------------------

    all_path = os.path.join(
        OUT_DIR,
        "all_configs.txt",
    )

    all_lines = read_lines(
        all_path
    )

    if len(all_lines) != GENERAL_TOTAL:
        raise RuntimeError(
            "all_configs.txt must contain "
            f"{GENERAL_TOTAL} configs, got "
            f"{len(all_lines)}"
        )

    # --------------------------------------------------------
    # sub1..sub10
    # --------------------------------------------------------

    rebuilt = []

    for index in range(
        GENERAL_SUB_COUNT
    ):
        filename = (
            f"sub{index + 1}.txt"
        )

        path = os.path.join(
            OUT_DIR,
            filename,
        )

        lines = read_lines(
            path
        )

        if len(lines) != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"{filename} must contain "
                f"{GENERAL_SUB_SIZE} configs, "
                f"got {len(lines)}"
            )

        rebuilt.extend(lines)

    if rebuilt != all_lines:
        raise RuntimeError(
            "sub1.txt to sub10.txt are not "
            "in the exact same order as "
            "all_configs.txt"
        )

    # --------------------------------------------------------
    # No duplicate lines in all configs
    # --------------------------------------------------------

    if len(set(all_lines)) != len(all_lines):
        raise RuntimeError(
            "Duplicate lines found in "
            "all_configs.txt"
        )

    # --------------------------------------------------------
    # Operator / Iran files
    # --------------------------------------------------------

    for filename in [
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
        "best_iran.txt",
        "mix_iran.txt",
    ]:
        path = os.path.join(
            OUT_DIR,
            filename,
        )

        lines = read_lines(
            path
        )

        if len(lines) != IRAN_SUB_SIZE:
            raise RuntimeError(
                f"{filename} must contain "
                f"{IRAN_SUB_SIZE} configs, "
                f"got {len(lines)}"
            )

    # --------------------------------------------------------
    # Protocol files
    # --------------------------------------------------------

    for ptype in [
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    ]:
        filename = (
            f"{ptype}.txt"
        )

        path = os.path.join(
            OUT_DIR,
            filename,
        )

        lines = read_lines(
            path
        )

        if not 1 <= len(lines) <= PROTOCOL_SUB_SIZE:
            raise RuntimeError(
                f"{filename} must contain "
                f"1-{PROTOCOL_SUB_SIZE} configs, "
                f"got {len(lines)}"
            )

        for line in lines:
            config = line.rsplit(
                "#",
                1,
            )[0]

            if proto(config) != ptype:
                raise RuntimeError(
                    f"{filename} contains "
                    f"wrong protocol: {line}"
                )

            if not valid_config(config):
                raise RuntimeError(
                    f"Invalid config in "
                    f"{filename}: {line}"
                )

    # --------------------------------------------------------
    # All files line validation
    # --------------------------------------------------------

    for filename in EXPECTED_FILES:
        path = os.path.join(
            OUT_DIR,
            filename,
        )

        lines = read_lines(
            path
        )

        if not lines:
            raise RuntimeError(
                f"{filename} is empty"
            )

        if len(set(lines)) != len(lines):
            raise RuntimeError(
                f"Duplicate lines found in "
                f"{filename}"
            )

        for line in lines:
            if not line.endswith(
                f"#{REMARK}"
            ):
                raise RuntimeError(
                    f"Invalid remark in "
                    f"{filename}: {line}"
                )

            if line.count("#") != 1:
                raise RuntimeError(
                    f"Invalid # count in "
                    f"{filename}: {line}"
                )

    print(
        "OUTPUT VERIFICATION PASSED"
    )

    print(
        "\nOutput order:"
    )

    for filename in EXPECTED_FILES:
        print(
            f"  {filename}"
        )


# ============================================================
# SUMMARY
# ============================================================

def print_summary():
    print(
        "\n" + "=" * 65
    )
    print(
        "FINAL OUTPUT SUMMARY"
    )
    print(
        "=" * 65
    )

    for filename in EXPECTED_FILES:
        path = os.path.join(
            OUT_DIR,
            filename,
        )

        count = count_nonempty_lines(
            path
        )

        print(
            f"{filename:20s} "
            f"{count:6d}"
        )


# ============================================================
# MAIN
# ============================================================

def main():
    started = time.time()

    print(
        "=" * 65
    )
    print(
        "NUKCROW COLLECTOR"
    )
    print(
        "Telegram Collector: DISABLED"
    )
    print(
        "=" * 65
    )

    os.makedirs(
        OUT_DIR,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # FETCH
    # --------------------------------------------------------

    raw = fetch_all()

    general_raw = raw["general"]
    iran_raw = raw["iran"]

    # --------------------------------------------------------
    # DEDUPE
    # --------------------------------------------------------

    general_unique = dedupe(
        general_raw
    )

    iran_unique = dedupe(
        iran_raw
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

    # --------------------------------------------------------
    # GLOBAL POOL
    # --------------------------------------------------------

    all_unique = dedupe(
        general_unique
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
    )

    print(
        "\nUnique configs:"
    )

    print(
        f"  General:   {len(general_unique)}"
    )

    print(
        f"  Iran:      {len(iran_unique)}"
    )

    print(
        f"  MCI:       {len(mci_unique)}"
    )

    print(
        f"  Irancell:  {len(irancell_unique)}"
    )

    print(
        f"  Rightel:   {len(rightel_unique)}"
    )

    print(
        f"  Global:    {len(all_unique)}"
    )

    if len(all_unique) < GENERAL_TOTAL:
        raise RuntimeError(
            "Not enough unique valid configs "
            f"for all_configs.txt: "
            f"{len(all_unique)}/"
            f"{GENERAL_TOTAL}"
        )

    # --------------------------------------------------------
    # BENCHMARK
    # --------------------------------------------------------

    alive_all = benchmark(
        all_unique
    )

    alive_iran = benchmark(
        iran_unique
    )

    alive_mci = benchmark(
        mci_unique
    )

    alive_irancell = benchmark(
        irancell_unique
    )

    alive_rightel = benchmark(
        rightel_unique
    )

    # --------------------------------------------------------
    # WRITE
    #
    # ترتیب منطقی:
    #
    # all_configs
    # sub1 ... sub10
    # operators
    # best_iran / mix_iran
    # protocols
    #
    # --------------------------------------------------------

    write_general(
        alive_all,
        all_unique,
    )

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
        all_unique,
    )

    write_protocols(
        alive_all,
        all_unique,
    )

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    verify_outputs()

    print_source_summary()

    print_summary()

    elapsed = (
        time.time()
        - started
    )

    print(
        f"\nDONE: {elapsed:.2f}s"
    )


if __name__ == "__main__":
    main()
