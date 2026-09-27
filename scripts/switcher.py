import os
import re
import json
import time
import base64
import socket
import random
import ipaddress
import threading

from urllib.parse import urlparse, parse_qs, quote
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

# =========================================================
# SUBSCRIPTION SIZES
# =========================================================

GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10

PROTOCOL_SUB_SIZE = 200
IRAN_SUB_SIZE = 200

# Reserved for Telegram Bot.
# Collector creates this file EMPTY.
RANDOM_SUB_SIZE = 200

# =========================================================
# FETCH
# =========================================================

FETCH_WORKERS = 8
FETCH_TIMEOUT = 12
FETCH_RETRIES = 2

# =========================================================
# BENCHMARK
# =========================================================

MAX_TEST = 80000
BENCH_WORKERS = 160
BENCH_TIMEOUT = 1.5

SECOND_PASS = 18000
SECOND_PASS_WORKERS = 80
SECOND_PASS_TIMEOUT = 1.8

# =========================================================
# SOURCE LIMITS
# =========================================================

MAX_PER_SOURCE = 12000
MAX_PER_HOST = 8

# =========================================================
# PREFERRED TRANSPORT TYPES
# =========================================================

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
    "tcp",
}


# =========================================================
# SOURCES
# =========================================================

SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/Config/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/sub.txt",
    "https://raw.githubusercontent.com/yebekhe/vpn-fail/main/sub/normal",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/v2ray",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/configs.txt",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/main/sub/vless",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/ConfigTopic/main/config",
    "https://github.com/iboxz/free-v2ray-collector/blob/main/main/mix",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config.txt",
    "https://raw.githubusercontent.com/MahsaFreeConfig/MahsaFreeConfig/main/Config.txt",
]


SOURCES_IRAN = [
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://github.com/iboxz/free-v2ray-collector/blob/main/main/mixt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/iran.txt",

    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn.txt",
]


SOURCES_MCI = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/MCI.txt",
    "https://github.com/iboxz/free-v2ray-collector/blob/main/main/mixt",
]


SOURCES_IRANCELL = [
    "https://github.com/iboxz/free-v2ray-collector/blob/main/main/mix",
]


# فعلاً خالی نگه داشته شده چون URL معتبر raw برای Rightel
# در کد قبلی مشخص نبود.
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

        decoded = base64.b64decode(
            value,
            validate=False
        )

        return decoded.decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:
        return ""


# =========================================================
# EXTRACT CONFIG PAYLOAD
# =========================================================

def extract_payload(text):
    if not text:
        return []

    text = text.replace("\r", "")

    lines = [
        x.strip()
        for x in text.split("\n")
        if x.strip()
    ]

    output = []

    # -----------------------------------------------------
    # Direct URI lines
    # -----------------------------------------------------

    for line in lines:

        if line.startswith((
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hysteria2://",
            "hy2://",
        )):
            output.append(line)
            continue

        # Markdown links containing a config
        match = re.search(
            r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\])]+",
            line,
            re.I
        )

        if match:
            output.append(
                match.group(0).rstrip(")")
            )

    # -----------------------------------------------------
    # Whole file base64
    # -----------------------------------------------------

    decoded = decode64(text)

    if decoded and "://" in decoded:

        for line in decoded.splitlines():

            line = line.strip()

            if line.startswith((
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "hysteria2://",
                "hy2://",
            )):
                output.append(line)

    # -----------------------------------------------------
    # Individual base64 lines
    # -----------------------------------------------------

    for line in lines:

        if "://" in line:
            continue

        if len(line) < 20:
            continue

        decoded_line = decode64(line)

        if decoded_line and "://" in decoded_line:

            for item in decoded_line.splitlines():

                item = item.strip()

                if item.startswith((
                    "vless://",
                    "vmess://",
                    "trojan://",
                    "ss://",
                    "hysteria2://",
                    "hy2://",
                )):
                    output.append(item)

    return output


# =========================================================
# FETCH SOURCE
# =========================================================

def fetch_source(url):

    for attempt in range(FETCH_RETRIES + 1):

        try:

            r = session().get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True,
            )

            if r.ok and r.text:

                return extract_payload(
                    r.text
                )[:MAX_PER_SOURCE]

        except Exception:
            pass

        if attempt < FETCH_RETRIES:
            time.sleep(0.3)

    return []


# =========================================================
# FETCH GROUP
# =========================================================

def fetch_group(name, sources):

    results = []

    if not sources:
        return results

    print(
        f"\n[FETCH] {name}: {len(sources)} sources"
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

                items = future.result()

                if items:
                    results.extend(items)

                print(
                    f"  [+] {len(items):>6} | {url}"
                )

            except Exception as e:

                print(
                    f"  [-] failed | {url} | {e}"
                )

    return results


# =========================================================
# FETCH ALL
# =========================================================

def fetch_all():

    general = fetch_group(
        "GENERAL",
        SOURCES_GENERAL
    )

    iran = fetch_group(
        "IRAN",
        SOURCES_IRAN
    )

    mci = fetch_group(
        "MCI",
        SOURCES_MCI
    )

    irancell = fetch_group(
        "IRANCELL",
        SOURCES_IRANCELL
    )

    rightel = fetch_group(
        "RIGHTEL",
        SOURCES_RIGHTEL
    )

    return {
        "general": general,
        "iran": iran,
        "mci": mci,
        "irancell": irancell,
        "rightel": rightel,
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


def host_port(config):

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
# HOST VALIDATION
# =========================================================

def is_junk_host(host):

    if not host:
        return True

    h = host.lower().strip()

    junk = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }

    if h in junk:
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

    if h.endswith(".local"):
        return True

    return False


# =========================================================
# CONFIG VALIDATION
# =========================================================

def valid_config(config):

    if not config:
        return False

    config = config.strip()

    ptype = proto(config)

    if ptype not in SUPPORTED_PROTOCOLS:
        return False

    p = parsed(config)

    if not p:
        return False

    host, port = host_port(config)

    if not host:
        return False

    if is_junk_host(host):
        return False

    if not port or not (
        1 <= port <= 65535
    ):
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
    # VMESS
    # -----------------------------------------------------

    elif ptype == "vmess":

        raw = config[8:]

        decoded = decode64(raw)

        if not decoded:
            return False

        try:

            data = json.loads(decoded)

            address = (
                data.get("add")
                or data.get("address")
                or ""
            )

            port_value = (
                data.get("port")
                or ""
            )

            if not address:
                return False

            if not port_value:
                return False

        except Exception:
            return False

    # -----------------------------------------------------
    # TROJAN
    # -----------------------------------------------------

    elif ptype == "trojan":

        if not p.username:
            return False

    # -----------------------------------------------------
    # SS
    # -----------------------------------------------------

    elif ptype == "ss":

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
# FINGERPRINT
# =========================================================

def fingerprint(config):

    ptype = proto(config)
    q = query(config)

    host, port = host_port(config)

    security = q1(
        q,
        "security",
        q1(q, "tls")
    )

    transport = q1(
        q,
        "type",
        q1(q, "network")
    )

    sni = q1(
        q,
        "sni",
        q1(q, "peer")
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

    values = [
        ptype,
        host,
        str(port),
        security,
        transport,
        sni,
        host_header,
        path,
        service_name,
        pbk,
        sid,
    ]

    return "|".join(
        x.strip().lower()
        for x in values
    )


# =========================================================
# DEDUPE
# =========================================================

def dedupe(configs):

    seen = set()
    output = []

    for config in configs:

        config = config.strip()

        if not valid_config(config):
            continue

        fp = fingerprint(config)

        if not fp:
            continue

        if fp in seen:
            continue

        seen.add(fp)
        output.append(config)

    return output


# =========================================================
# IRAN DETECTION
# =========================================================

def looks_iran(config):

    text = config.lower()

    iran_terms = (
        "iran",
        "irancell",
        "mci",
        "hamrah",
        "rightel",
        "همراه",
        "ایران",
    )

    return any(
        term in text
        for term in iran_terms
    )


def operator_of(config):

    text = config.lower()

    if (
        "mci" in text
        or "hamrah" in text
        or "همراه" in text
    ):
        return "mci"

    if (
        "irancell" in text
        or "mtn" in text
    ):
        return "irancell"

    if "rightel" in text:
        return "rightel"

    return ""


# =========================================================
# QUALITY SCORE
# =========================================================

def quality_score(config):

    score = 0

    ptype = proto(config)
    q = query(config)

    host, port = host_port(config)

    # Protocol

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

    # Transport

    transport = q1(
        q,
        "type",
        q1(q, "network")
    ).lower()

    if transport in PREFERRED_TYPES:
        score += 20

    # TLS

    security = q1(
        q,
        "security"
    ).lower()

    if security == "tls":
        score += 15

    # SNI

    sni = q1(
        q,
        "sni"
    )

    if sni:
        score += 10

    # Port

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

    # Domain

    if host:

        try:

            ipaddress.ip_address(host)

            score += 2

        except Exception:

            if "." in host:
                score += 8

    # Path

    path = q1(
        q,
        "path"
    )

    if path:
        score += 5

    # Service

    service = q1(
        q,
        "serviceName"
    )

    if service:
        score += 4

    return score


# =========================================================
# TCP PROBE
# =========================================================

def tcp_probe(item):

    config, timeout = item

    host, port = host_port(config)

    if not host or not port:
        return None

    start = time.perf_counter()

    try:

        with socket.create_connection(
            (host, port),
            timeout=timeout
        ):

            elapsed = (
                time.perf_counter()
                - start
            )

            return config, elapsed

    except Exception:
        return None


# =========================================================
# BENCHMARK
# =========================================================

def benchmark(configs):

    if not configs:
        return []

    print(
        f"\n[BENCHMARK] Testing "
        f"{min(len(configs), MAX_TEST)} configs..."
    )

    candidates = configs[:MAX_TEST]

    results = []

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

        for future in as_completed(
            futures
        ):

            try:

                result = future.result()

                if result:

                    config, latency = result

                    results.append({
                        "config": config,
                        "latency": latency,
                        "score": quality_score(config),
                    })

            except Exception:
                pass

    # -----------------------------------------------------
    # Second pass
    # -----------------------------------------------------

    if len(results) < SECOND_PASS:

        remaining = configs[
            MAX_TEST:
        ]

        remaining = remaining[
            :SECOND_PASS
        ]

        print(
            f"[BENCHMARK] Second pass: "
            f"{len(remaining)} configs..."
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

            for future in as_completed(
                futures
            ):

                try:

                    result = future.result()

                    if result:

                        config, latency = result

                        results.append({
                            "config": config,
                            "latency": latency,
                            "score": quality_score(config),
                        })

                except Exception:
                    pass

    # -----------------------------------------------------
    # Sort
    # -----------------------------------------------------

    results.sort(
        key=lambda x: (
            -x["score"],
            x["latency"]
        )
    )

    print(
        f"[BENCHMARK] Alive: {len(results)}"
    )

    return results


# =========================================================
# REMARK
# =========================================================

def clean_remark(config, index):

    ptype = proto(config)

    return (
        f"{REMARK}-{ptype}-{index}"
    )


def config_line(config, index):

    return (
        f"{config}"
        f"#{quote(clean_remark(config, index))}"
    )


# =========================================================
# SELECT RECORDS
# =========================================================

def select_records(
    results,
    limit,
    predicate=None,
    used_fps=None,
):

    if not results or limit <= 0:
        return []

    used_fps = (
        used_fps
        if used_fps is not None
        else set()
    )

    candidates = []

    for item in results:

        config = item.get(
            "config",
            ""
        )

        if not config:
            continue

        if predicate and not predicate(
            config
        ):
            continue

        fp = fingerprint(config)

        if not fp:
            continue

        candidates.append(
            (
                item,
                fp
            )
        )

    selected = []
    selected_fps = set()

    # =====================================================
    # PASS 1
    # Strong diversity
    # =====================================================

    host_count = {}
    proto_count = {}

    proto_limit = max(
        20,
        limit // 2
    )

    for item, fp in candidates:

        if len(selected) >= limit:
            break

        if fp in selected_fps:
            continue

        if fp in used_fps:
            continue

        config = item["config"]

        host, _ = host_port(
            config
        )

        ptype = proto(config)

        if host_count.get(
            host,
            0
        ) >= 4:
            continue

        if proto_count.get(
            ptype,
            0
        ) >= proto_limit:
            continue

        selected.append(item)
        selected_fps.add(fp)

        host_count[host] = (
            host_count.get(host, 0)
            + 1
        )

        proto_count[ptype] = (
            proto_count.get(ptype, 0)
            + 1
        )

    # =====================================================
    # PASS 2
    # Relax host limit
    # =====================================================

    if len(selected) < limit:

        host_count = {}
        proto_count = {}

        for item, fp in candidates:

            if len(selected) >= limit:
                break

            if fp in selected_fps:
                continue

            if fp in used_fps:
                continue

            config = item["config"]

            host, _ = host_port(
                config
            )

            ptype = proto(config)

            if host_count.get(
                host,
                0
            ) >= 8:
                continue

            if proto_count.get(
                ptype,
                0
            ) >= max(30, limit):
                continue

            selected.append(item)
            selected_fps.add(fp)

            host_count[host] = (
                host_count.get(host, 0)
                + 1
            )

            proto_count[ptype] = (
                proto_count.get(ptype, 0)
                + 1
            )

    # =====================================================
    # PASS 3
    # Relax host limit further
    # =====================================================

    if len(selected) < limit:

        host_count = {}

        for item, fp in candidates:

            if len(selected) >= limit:
                break

            if fp in selected_fps:
                continue

            if fp in used_fps:
                continue

            config = item["config"]

            host, _ = host_port(
                config
            )

            if host_count.get(
                host,
                0
            ) >= 20:
                continue

            selected.append(item)
            selected_fps.add(fp)

            host_count[host] = (
                host_count.get(host, 0)
                + 1
            )

    # =====================================================
    # PASS 4
    # Quantity fallback
    # =====================================================

    if len(selected) < limit:

        for item, fp in candidates:

            if len(selected) >= limit:
                break

            if fp in selected_fps:
                continue

            if fp in used_fps:
                continue

            selected.append(item)
            selected_fps.add(fp)

    return selected[:limit]


# =========================================================
# MIX SELECTOR
# =========================================================

def select_mix(
    results,
    limit,
    predicate=None,
):

    if not results:
        return []

    pool = list(results)

    block_size = 100

    blocks = [
        pool[i:i + block_size]

        for i in range(
            0,
            len(pool),
            block_size
        )
    ]

    rng = random.Random()

    rng.shuffle(blocks)

    mixed = []

    for block in blocks:

        rng.shuffle(block)

        mixed.extend(block)

    return select_records(
        mixed,
        limit,
        predicate=predicate
    )


# =========================================================
# WRITE FILE
# =========================================================

def write_file(
    path,
    records
):

    directory = os.path.dirname(
        path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        for index, item in enumerate(
            records,
            start=1
        ):

            config = item["config"]

            f.write(
                config_line(
                    config,
                    index
                )
                + "\n"
            )


# =========================================================
# CREATE EMPTY FILE
# =========================================================

def create_empty_file(path):

    directory = os.path.dirname(
        path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        path,
        "w",
        encoding="utf-8"
    ):
        pass


# =========================================================
# REMOVE OLD SUBSCRIPTIONS
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
# WRITE GENERAL
# =========================================================

def write_general(results):

    print(
        "\n[WRITE] GENERAL"
    )

    total_needed = (
        GENERAL_SUB_SIZE
        * GENERAL_SUB_COUNT
    )

    selected = select_records(
        results,
        total_needed
    )

    # -----------------------------------------------------
    # all_configs.txt
    # -----------------------------------------------------

    all_path = os.path.join(
        OUT_DIR,
        "all_configs.txt"
    )

    write_file(
        all_path,
        selected
    )

    print(
        f"  all_configs.txt = "
        f"{len(selected)}"
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

        part = selected[
            start:end
        ]

        path = os.path.join(
            OUT_DIR,
            f"sub{i + 1}.txt"
        )

        write_file(
            path,
            part
        )

        print(
            f"  sub{i + 1}.txt = "
            f"{len(part)}"
        )


# =========================================================
# WRITE PROTOCOLS
# =========================================================

def write_protocols(results):

    print(
        "\n[WRITE] PROTOCOLS"
    )

    protocols = (
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    )

    for ptype in protocols:

        selected = select_records(
            results,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype:
                proto(c) == p
        )

        path = os.path.join(
            OUT_DIR,
            f"{ptype}.txt"
        )

        write_file(
            path,
            selected
        )

        print(
            f"  {ptype}.txt = "
            f"{len(selected)}"
        )


# =========================================================
# WRITE IRAN
# =========================================================

def write_iran(
    all_results,
    iran_results,
):

    print(
        "\n[WRITE] IRAN"
    )

    # -----------------------------------------------------
    # BEST IRAN
    # -----------------------------------------------------

    best_iran = select_records(
        iran_results,
        IRAN_SUB_SIZE
    )

    path = os.path.join(
        OUT_DIR,
        "best_iran.txt"
    )

    write_file(
        path,
        best_iran
    )

    print(
        f"  best_iran.txt = "
        f"{len(best_iran)}"
    )

    # -----------------------------------------------------
    # MIX IRAN
    # -----------------------------------------------------

    mix_iran = select_mix(
        iran_results,
        IRAN_SUB_SIZE
    )

    path = os.path.join(
        OUT_DIR,
        "mix_iran.txt"
    )

    write_file(
        path,
        mix_iran
    )

    print(
        f"  mix_iran.txt = "
        f"{len(mix_iran)}"
    )

    # -----------------------------------------------------
    # MCI
    # -----------------------------------------------------

    mci = select_records(
        all_results.get(
            "mci",
            []
        ),
        IRAN_SUB_SIZE
    )

    path = os.path.join(
        OUT_DIR,
        "mci.txt"
    )

    write_file(
        path,
        mci
    )

    print(
        f"  mci.txt = "
        f"{len(mci)}"
    )

    # -----------------------------------------------------
    # IRANCELL
    # -----------------------------------------------------

    irancell = select_records(
        all_results.get(
            "irancell",
            []
        ),
        IRAN_SUB_SIZE
    )

    path = os.path.join(
        OUT_DIR,
        "irancell.txt"
    )

    write_file(
        path,
        irancell
    )

    print(
        f"  irancell.txt = "
        f"{len(irancell)}"
    )

    # -----------------------------------------------------
    # RIGHTEL
    # -----------------------------------------------------

    rightel = select_records(
        all_results.get(
            "rightel",
            []
        ),
        IRAN_SUB_SIZE
    )

    path = os.path.join(
        OUT_DIR,
        "rightel.txt"
    )

    write_file(
        path,
        rightel
    )

    print(
        f"  rightel.txt = "
        f"{len(rightel)}"
    )


# =========================================================
# RANDOM 200
# =========================================================

def create_random_subscription():

    path = os.path.join(
        OUT_DIR,
        "random_200.txt"
    )

    # Intentionally EMPTY.
    # Telegram Bot handles Random 200 itself.

    create_empty_file(
        path
    )

    print(
        f"  random_200.txt = "
        f"0 (reserved for Telegram Bot)"
    )


# =========================================================
# SUMMARY
# =========================================================

def print_summary():

    print(
        "\n"
        + "=" * 60
    )

    print(
        "SUBSCRIPTION SUMMARY"
    )

    print(
        "=" * 60
    )

    if not os.path.isdir(
        OUT_DIR
    ):
        return

    files = sorted(
        f
        for f in os.listdir(
            OUT_DIR
        )
        if f.endswith(".txt")
    )

    for filename in files:

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
        "=" * 60
    )


# =========================================================
# MAIN
# =========================================================

def main():

    started = time.time()

    print(
        "=" * 60
    )

    print(
        "NUKCROW COLLECTOR"
    )

    print(
        "=" * 60
    )

    # -----------------------------------------------------
    # Output directory
    # -----------------------------------------------------

    os.makedirs(
        OUT_DIR,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Fetch
    # -----------------------------------------------------

    raw = fetch_all()

    general_raw = raw.get(
        "general",
        []
    )

    iran_raw = raw.get(
        "iran",
        []
    )

    mci_raw = raw.get(
        "mci",
        []
    )

    irancell_raw = raw.get(
        "irancell",
        []
    )

    rightel_raw = raw.get(
        "rightel",
        []
    )

    print(
        "\n"
        + "-" * 60
    )

    print(
        f"RAW GENERAL   : "
        f"{len(general_raw)}"
    )

    print(
        f"RAW IRAN      : "
        f"{len(iran_raw)}"
    )

    print(
        f"RAW MCI       : "
        f"{len(mci_raw)}"
    )

    print(
        f"RAW IRANCELL  : "
        f"{len(irancell_raw)}"
    )

    print(
        f"RAW RIGHTEL   : "
        f"{len(rightel_raw)}"
    )

    # -----------------------------------------------------
    # Combine
    # -----------------------------------------------------

    combined = (
        general_raw
        + iran_raw
        + mci_raw
        + irancell_raw
        + rightel_raw
    )

    print(
        f"\nRAW TOTAL     : "
        f"{len(combined)}"
    )

    # -----------------------------------------------------
    # Dedupe
    # -----------------------------------------------------

    unique = dedupe(
        combined
    )

    print(
        f"UNIQUE        : "
        f"{len(unique)}"
    )

    # -----------------------------------------------------
    # Benchmark
    # -----------------------------------------------------

    benchmarked = benchmark(
        unique
    )

    if not benchmarked:

        print(
            "\n[ERROR] "
            "No alive configs found."
        )

        clear_old_subscriptions()

        # Even when benchmark fails,
        # create the reserved empty Random file.
        create_random_subscription()

        print_summary()

        return

    # -----------------------------------------------------
    # Sort
    # -----------------------------------------------------

    benchmarked.sort(
        key=lambda x: (
            -x["score"],
            x["latency"]
        )
    )

    # -----------------------------------------------------
    # Pools
    # -----------------------------------------------------

    general_results = benchmarked

    iran_results = [
        item
        for item in benchmarked
        if looks_iran(
            item["config"]
        )
    ]

    mci_results = [
        item
        for item in benchmarked
        if operator_of(
            item["config"]
        ) == "mci"
    ]

    irancell_results = [
        item
        for item in benchmarked
        if operator_of(
            item["config"]
        ) == "irancell"
    ]

    rightel_results = [
        item
        for item in benchmarked
        if operator_of(
            item["config"]
        ) == "rightel"
    ]

    print(
        "\n"
        + "-" * 60
    )

    print(
        f"ALIVE TOTAL    : "
        f"{len(general_results)}"
    )

    print(
        f"ALIVE IRAN     : "
        f"{len(iran_results)}"
    )

    print(
        f"ALIVE MCI      : "
        f"{len(mci_results)}"
    )

    print(
        f"ALIVE IRANCELL : "
        f"{len(irancell_results)}"
    )

    print(
        f"ALIVE RIGHTEL  : "
        f"{len(rightel_results)}"
    )

    # -----------------------------------------------------
    # Clear previous subscriptions
    # -----------------------------------------------------

    print(
        "\n[CLEAN] "
        "Removing old subscription files..."
    )

    clear_old_subscriptions()

    # -----------------------------------------------------
    # General
    # -----------------------------------------------------

    write_general(
        general_results
    )

    # -----------------------------------------------------
    # Protocols
    # -----------------------------------------------------

    write_protocols(
        general_results
    )

    # -----------------------------------------------------
    # Iran / Operators
    # -----------------------------------------------------

    write_iran(
        {
            "mci": mci_results,
            "irancell": irancell_results,
            "rightel": rightel_results,
        },
        iran_results
    )

    # -----------------------------------------------------
    # Random 200
    # -----------------------------------------------------

    create_random_subscription()

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print_summary()

    elapsed = (
        time.time()
        - started
    )

    print(
        f"\nDONE in "
        f"{elapsed:.1f}s"
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    main()
