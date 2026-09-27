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

GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10

PROTOCOL_SUB_SIZE = 200
IRAN_SUB_SIZE = 200
RANDOM_SUB_SIZE = 200

FETCH_WORKERS = 10
FETCH_TIMEOUT = 15
FETCH_RETRIES = 3

MAX_TEST = 100000
BENCH_WORKERS = 180
BENCH_TIMEOUT = 1.8

SECOND_PASS = 25000
SECOND_PASS_WORKERS = 100
SECOND_PASS_TIMEOUT = 2.0

MAX_PER_SOURCE = 20000

MAX_PER_HOST = 8

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
    "tcp",
}


# =========================================================
# SOURCES - GENERAL
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
    "https://raw.githubusercontent.com/Joker-funland/V2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config.txt",
    "https://raw.githubusercontent.com/MahsaFreeConfig/MahsaFreeConfig/main/Config.txt",
]


# =========================================================
# SOURCES - IRAN
# =========================================================

SOURCES_IRAN = [
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/iran.txt",

    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn.txt",

    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]


# =========================================================
# SOURCES - MCI
# =========================================================

SOURCES_MCI = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/MCI.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mixt",
]


# =========================================================
# SOURCES - IRANCELL
# =========================================================

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/Irancell.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]


# =========================================================
# SOURCES - RIGHTEL
# =========================================================

SOURCES_RIGHTEL = []


# =========================================================
# THREAD SESSION
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

    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\]\[<>)\"']+",
        re.I
    )

    for line in lines:

        matches = pattern.findall(line)

        for item in matches:

            item = item.rstrip(
                ".,;:)"
            )

            if item:
                output.append(item)

    decoded_whole = decode64(text)

    if decoded_whole:

        for line in decoded_whole.splitlines():

            line = line.strip()

            matches = pattern.findall(line)

            for item in matches:

                item = item.rstrip(
                    ".,;:)"
                )

                if item:
                    output.append(item)

    for line in lines:

        if "://" in line:
            continue

        if len(line) < 20:
            continue

        decoded_line = decode64(line)

        if not decoded_line:
            continue

        for item in decoded_line.splitlines():

            item = item.strip()

            matches = pattern.findall(item)

            for config in matches:

                config = config.rstrip(
                    ".,;:)"
                )

                if config:
                    output.append(config)

    return output


# =========================================================
# FETCH SOURCE
# =========================================================

def fetch_source(url):

    for attempt in range(
        FETCH_RETRIES + 1
    ):

        try:

            response = session().get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True,
            )

            if (
                response.ok
                and response.text
            ):

                configs = extract_payload(
                    response.text
                )

                return configs[
                    :MAX_PER_SOURCE
                ]

        except Exception:
            pass

        if attempt < FETCH_RETRIES:
            time.sleep(
                0.5
            )

    return []


# =========================================================
# FETCH GROUP
# =========================================================

def fetch_group(
    name,
    sources
):

    if not sources:
        return []

    results = []

    print(
        f"\n[FETCH] {name}: "
        f"{len(sources)} sources"
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

        for future in as_completed(
            futures
        ):

            url = futures[future]

            try:

                configs = future.result()

                results.extend(
                    configs
                )

                print(
                    f"  [+] "
                    f"{len(configs):>6} "
                    f"| {url}"
                )

            except Exception as e:

                print(
                    f"  [-] "
                    f"{url} "
                    f"| {e}"
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
# URL PARSE
# =========================================================

def parsed(config):

    try:
        return urlparse(
            config
        )
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


def q1(
    q,
    key,
    default=""
):

    value = q.get(key)

    if not value:
        return default

    if isinstance(
        value,
        list
    ):
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

    if h.endswith(
        ".local"
    ):
        return True

    return False


# =========================================================
# VALID CONFIG
# =========================================================

def valid_config(config):

    if not config:
        return False

    config = config.strip()

    ptype = proto(
        config
    )

    if ptype not in SUPPORTED_PROTOCOLS:
        return False

    p = parsed(
        config
    )

    if not p:
        return False

    host, port = host_port(
        config
    )

    if not host:
        return False

    if is_junk_host(
        host
    ):
        return False

    if not (
        1 <= port <= 65535
    ):
        return False

    if ptype == "vless":

        if not p.username:
            return False

        if len(
            p.username
        ) < 8:
            return False

    elif ptype == "vmess":

        raw = config[
            8:
        ]

        decoded = decode64(
            raw
        )

        if not decoded:
            return False

        try:

            data = json.loads(
                decoded
            )

            address = (
                data.get("add")
                or data.get("address")
                or ""
            )

            vmess_port = (
                data.get("port")
                or ""
            )

            if not address:
                return False

            if not vmess_port:
                return False

        except Exception:
            return False

    elif ptype == "trojan":

        if not p.username:
            return False

    elif ptype == "ss":

        if not p.username:
            return False

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

    ptype = proto(
        config
    )

    q = query(
        config
    )

    host, port = host_port(
        config
    )

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

    return "|".join(
        str(x).strip().lower()
        for x in [
            ptype,
            host,
            port,
            security,
            transport,
            sni,
            host_header,
            path,
            service_name,
            pbk,
            sid,
        ]
    )


# =========================================================
# DEDUPE
# =========================================================

def dedupe(configs):

    seen = set()
    output = []

    for config in configs:

        config = config.strip()

        if not valid_config(
            config
        ):
            continue

        fp = fingerprint(
            config
        )

        if fp in seen:
            continue

        seen.add(
            fp
        )

        output.append(
            config
        )

    return output


# =========================================================
# IRAN DETECTION
# =========================================================

def looks_iran(config):

    text = config.lower()

    return any(
        term in text
        for term in (
            "iran",
            "irancell",
            "mci",
            "hamrah",
            "rightel",
            " همراه",
            "ایران",
        )
    )


def operator_of(config):

    text = config.lower()

    if any(
        x in text
        for x in (
            "mci",
            "hamrah",
            "همراه",
        )
    ):
        return "mci"

    if any(
        x in text
        for x in (
            "irancell",
            "mtn",
        )
    ):
        return "irancell"

    if "rightel" in text:
        return "rightel"

    return ""


# =========================================================
# QUALITY
# =========================================================

def quality_score(config):

    score = 0

    ptype = proto(
        config
    )

    q = query(
        config
    )

    host, port = host_port(
        config
    )

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

    transport = q1(
        q,
        "type",
        q1(
            q,
            "network"
        )
    ).lower()

    if transport in PREFERRED_TYPES:
        score += 20

    security = q1(
        q,
        "security"
    ).lower()

    if security == "tls":
        score += 15

    if q1(
        q,
        "sni"
    ):
        score += 10

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

    if host:

        try:

            ipaddress.ip_address(
                host
            )

            score += 2

        except Exception:

            if "." in host:
                score += 8

    if q1(
        q,
        "path"
    ):
        score += 5

    if q1(
        q,
        "serviceName"
    ):
        score += 4

    return score


# =========================================================
# TCP PROBE
# =========================================================

def tcp_probe(item):

    config, timeout = item

    host, port = host_port(
        config
    )

    if not host or not port:
        return None

    start = time.perf_counter()

    try:

        with socket.create_connection(
            (
                host,
                port
            ),
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

    candidates = configs[
        :MAX_TEST
    ]

    results = []

    print(
        f"\n[BENCHMARK] "
        f"Testing {len(candidates)} configs..."
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
                        "score": quality_score(
                            config
                        ),
                    })

            except Exception:
                pass

    if len(results) < SECOND_PASS:

        remaining = configs[
            MAX_TEST:
            MAX_TEST + SECOND_PASS
        ]

        print(
            f"[BENCHMARK] "
            f"Second pass: "
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
                            "score": quality_score(
                                config
                            ),
                        })

                except Exception:
                    pass

    results.sort(
        key=lambda x: (
            -x["score"],
            x["latency"]
        )
    )

    print(
        f"[BENCHMARK] "
        f"Alive: {len(results)}"
    )

    return results


# =========================================================
# REMARK
# =========================================================

def clean_remark(
    config,
    index
):

    return (
        f"{REMARK}-"
        f"{proto(config)}-"
        f"{index}"
    )


def config_line(
    config,
    index
):

    return (
        config
        + "#"
        + quote(
            clean_remark(
                config,
                index
            )
        )
    )


# =========================================================
# SELECT RECORDS
# =========================================================

def select_records(
    results,
    limit,
    predicate=None,
):

    if not results or limit <= 0:
        return []

    candidates = []

    seen = set()

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

        fp = fingerprint(
            config
        )

        if fp in seen:
            continue

        seen.add(
            fp
        )

        candidates.append(
            item
        )

    selected = []

    selected_fps = set()

    host_count = {}
    proto_count = {}

    # -----------------------------------------------------
    # PASS 1
    # -----------------------------------------------------

    for item in candidates:

        if len(selected) >= limit:
            break

        config = item[
            "config"
        ]

        fp = fingerprint(
            config
        )

        host, _ = host_port(
            config
        )

        ptype = proto(
            config
        )

        if host_count.get(
            host,
            0
        ) >= 4:
            continue

        if proto_count.get(
            ptype,
            0
        ) >= max(
            20,
            limit // 2
        ):
            continue

        selected.append(
            item
        )

        selected_fps.add(
            fp
        )

        host_count[host] = (
            host_count.get(
                host,
                0
            ) + 1
        )

        proto_count[ptype] = (
            proto_count.get(
                ptype,
                0
            ) + 1
        )

    # -----------------------------------------------------
    # PASS 2
    # -----------------------------------------------------

    if len(selected) < limit:

        for item in candidates:

            if len(selected) >= limit:
                break

            config = item[
                "config"
            ]

            fp = fingerprint(
                config
            )

            if fp in selected_fps:
                continue

            host, _ = host_port(
                config
            )

            if host_count.get(
                host,
                0
            ) >= 8:
                continue

            selected.append(
                item
            )

            selected_fps.add(
                fp
            )

            host_count[host] = (
                host_count.get(
                    host,
                    0
                ) + 1
            )

    # -----------------------------------------------------
    # PASS 3 - NO DIVERSITY LIMIT
    # -----------------------------------------------------

    if len(selected) < limit:

        for item in candidates:

            if len(selected) >= limit:
                break

            config = item[
                "config"
            ]

            fp = fingerprint(
                config
            )

            if fp in selected_fps:
                continue

            selected.append(
                item
            )

            selected_fps.add(
                fp
            )

    return selected[
        :limit
    ]


# =========================================================
# SOURCE-FIRST SELECTOR
# =========================================================

def fill_from_pools(
    primary,
    fallback,
    limit
):

    selected = []
    seen = set()

    def add_pool(pool):

        for item in pool:

            if len(selected) >= limit:
                return

            config = item[
                "config"
            ]

            fp = fingerprint(
                config
            )

            if fp in seen:
                continue

            seen.add(
                fp
            )

            selected.append(
                item
            )

    add_pool(
        primary
    )

    if len(selected) < limit:
        add_pool(
            fallback
        )

    return selected[
        :limit
    ]


# =========================================================
# MIX
# =========================================================

def select_mix(
    results,
    limit
):

    if not results:
        return []

    pool = list(
        results
    )

    random.shuffle(
        pool
    )

    return select_records(
        pool,
        limit
    )


# =========================================================
# WRITE
# =========================================================

def write_file(
    path,
    records
):

    os.makedirs(
        os.path.dirname(path),
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

            f.write(
                config_line(
                    item["config"],
                    index
                )
                + "\n"
            )


# =========================================================
# EMPTY FILE
# =========================================================

def create_empty_file(
    path
):

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ):
        pass


# =========================================================
# CLEAR
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
            os.remove(
                path
            )
        except Exception:
            pass


# =========================================================
# GENERAL
# =========================================================

def write_general(
    results
):

    total = (
        GENERAL_SUB_SIZE
        * GENERAL_SUB_COUNT
    )

    selected = select_records(
        results,
        total
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "all_configs.txt"
        ),
        selected
    )

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
            ]
        )

    print(
        f"[GENERAL] "
        f"{len(selected)}/{total}"
    )


# =========================================================
# PROTOCOLS
# =========================================================

def write_protocols(
    results
):

    protocols = [
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    ]

    for ptype in protocols:

        selected = select_records(
            results,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype:
                proto(c) == p
        )

        write_file(
            os.path.join(
                OUT_DIR,
                f"{ptype}.txt"
            ),
            selected
        )

        print(
            f"[{ptype.upper():8}] "
            f"{len(selected)}/{PROTOCOL_SUB_SIZE}"
        )


# =========================================================
# IRAN / OPERATOR
# =========================================================

def write_iran(
    iran_results,
    mci_results,
    irancell_results,
    rightel_results,
    all_results,
):

    # -----------------------------------------------------
    # BEST IRAN
    # First use dedicated Iran sources,
    # then fallback to ALL alive configs.
    # -----------------------------------------------------

    best_iran = fill_from_pools(
        select_records(
            iran_results,
            IRAN_SUB_SIZE
        ),
        select_records(
            all_results,
            IRAN_SUB_SIZE
        ),
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "best_iran.txt"
        ),
        best_iran
    )

    # -----------------------------------------------------
    # MIX IRAN
    # -----------------------------------------------------

    mix_pool = list(
        iran_results
    )

    if len(mix_pool) < IRAN_SUB_SIZE:

        mix_pool.extend(
            all_results
        )

    mix_iran = select_mix(
        mix_pool,
        IRAN_SUB_SIZE
    )

    write_file(
        os.path.join(
            OUT_DIR,
            "mix_iran.txt"
        ),
        mix_iran
    )

    # -----------------------------------------------------
    # MCI
    # -----------------------------------------------------

    mci = fill_from_pools(
        select_records(
            mci_results,
            IRAN_SUB_SIZE
        ),
        select_records(
            iran_results,
            IRAN_SUB_SIZE
        ),
        IRAN_SUB_SIZE
    )

    if len(mci) < IRAN_SUB_SIZE:

        mci = fill_from_pools(
            mci,
            select_records(
                all_results,
                IRAN_SUB_SIZE
            ),
            IRAN_SUB_SIZE
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "mci.txt"
        ),
        mci
    )

    # -----------------------------------------------------
    # IRANCELL
    # -----------------------------------------------------

    irancell = fill_from_pools(
        select_records(
            irancell_results,
            IRAN_SUB_SIZE
        ),
        select_records(
            iran_results,
            IRAN_SUB_SIZE
        ),
        IRAN_SUB_SIZE
    )

    if len(irancell) < IRAN_SUB_SIZE:

        irancell = fill_from_pools(
            irancell,
            select_records(
                all_results,
                IRAN_SUB_SIZE
            ),
            IRAN_SUB_SIZE
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "irancell.txt"
        ),
        irancell
    )

    # -----------------------------------------------------
    # RIGHTEL
    # -----------------------------------------------------

    rightel = fill_from_pools(
        select_records(
            rightel_results,
            IRAN_SUB_SIZE
        ),
        select_records(
            iran_results,
            IRAN_SUB_SIZE
        ),
        IRAN_SUB_SIZE
    )

    if len(rightel) < IRAN_SUB_SIZE:

        rightel = fill_from_pools(
            rightel,
            select_records(
                all_results,
                IRAN_SUB_SIZE
            ),
            IRAN_SUB_SIZE
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "rightel.txt"
        ),
        rightel
    )

    print(
        f"[BEST IRAN] "
        f"{len(best_iran)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"[MIX IRAN]  "
        f"{len(mix_iran)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"[MCI]       "
        f"{len(mci)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"[IRANCELL]  "
        f"{len(irancell)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"[RIGHTEL]   "
        f"{len(rightel)}/{IRAN_SUB_SIZE}"
    )


# =========================================================
# RANDOM 200
# =========================================================

def create_random_subscription():

    path = os.path.join(
        OUT_DIR,
        "random_200.txt"
    )

    create_empty_file(
        path
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
        "NUKCROW SUBSCRIPTION SUMMARY"
    )

    print(
        "=" * 65
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
                f"{filename:<30}"
                f"{count:>7}"
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

    start_time = time.time()

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

    general_raw = raw[
        "general"
    ]

    iran_raw = raw[
        "iran"
    ]

    mci_raw = raw[
        "mci"
    ]

    irancell_raw = raw[
        "irancell"
    ]

    rightel_raw = raw[
        "rightel"
    ]

    # -----------------------------------------------------
    # DEDUPE EACH POOL
    # -----------------------------------------------------

    general_unique = dedupe(
        general_raw
    )

    iran_unique = dedupe(
        iran_raw
    )

    mci_unique = dedupe(
        mci_raw
    )

    irancell_unique = dedupe(
        irancell_raw
    )

    rightel_unique = dedupe(
        rightel_raw
    )

    # -----------------------------------------------------
    # GLOBAL POOL
    # -----------------------------------------------------

    all_unique = dedupe(
        general_unique
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
    )

    print(
        "\n"
        + "-" * 65
    )

    print(
        f"GENERAL UNIQUE : "
        f"{len(general_unique)}"
    )

    print(
        f"IRAN UNIQUE    : "
        f"{len(iran_unique)}"
    )

    print(
        f"MCI UNIQUE     : "
        f"{len(mci_unique)}"
    )

    print(
        f"IRANCELL UNIQUE: "
        f"{len(irancell_unique)}"
    )

    print(
        f"RIGHTEL UNIQUE : "
        f"{len(rightel_unique)}"
    )

    print(
        f"GLOBAL UNIQUE  : "
        f"{len(all_unique)}"
    )

    # -----------------------------------------------------
    # BENCHMARK GLOBAL
    # -----------------------------------------------------

    alive_global = benchmark(
        all_unique
    )

    # -----------------------------------------------------
    # BENCHMARK DEDICATED POOLS
    # -----------------------------------------------------

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

    if not alive_global:

        clear_old_subscriptions()

        create_random_subscription()

        print_summary()

        return

    # -----------------------------------------------------
    # CLEAN OLD
    # -----------------------------------------------------

    clear_old_subscriptions()

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    write_general(
        alive_global
    )

    # -----------------------------------------------------
    # PROTOCOLS
    # -----------------------------------------------------

    write_protocols(
        alive_global
    )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    write_iran(
        alive_iran,
        alive_mci,
        alive_irancell,
        alive_rightel,
        alive_global
    )

    # -----------------------------------------------------
    # RANDOM 200
    # MUST REMAIN EMPTY
    # -----------------------------------------------------

    create_random_subscription()

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print_summary()

    elapsed = (
        time.time()
        - start_time
    )

    print(
        f"\nCompleted in "
        f"{elapsed:.2f} seconds"
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    main()
