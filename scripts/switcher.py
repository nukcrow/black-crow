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

# فقط همین تگ روی همه کانفیگ‌ها
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
# RANDOM 200 SOURCES
# =========================================================

RANDOM_200_SOURCES = [
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mixt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/all",
]

# =========================================================
RANDOM_200_SOURCES = []

RANDOM_200_LIMIT = 200


# =========================================================
# FETCH CONFIG
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
# IRAN SOURCES
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
# MCI
# =========================================================

SOURCES_MCI = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/MCI.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mci.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mixt",
]


# =========================================================
# IRANCELL
# =========================================================

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/Bllare/V2ray-Configs/main/Irancell.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
]


# =========================================================
# RIGHTEL
# =========================================================

SOURCES_RIGHTEL = []


# =========================================================
# SESSION
# =========================================================

_thread_local = threading.local()


def session():

    if not hasattr(
        _thread_local,
        "session"
    ):

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

        value = value.replace(
            "-",
            "+"
        )

        value = value.replace(
            "_",
            "/"
        )

        padding = (
            len(value) % 4
        )

        if padding:
            value += "=" * (
                4 - padding
            )

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
    r")://[^\s\]\[<>)\"'`]+",
    re.I
)


def normalize_config(
    config
):

    if not config:
        return ""

    config = (
        config
        .strip()
        .replace(
            "\\/",
            "/"
        )
    )

    config = unquote(
        config
    )

    # حذف تگ قبلی اگر منبع روی کانفیگ
    # remark گذاشته باشد
    config = config.split(
        "#",
        1
    )[0].strip()

    # حذف فاصله‌های اضافی
    config = config.replace(
        " ",
        ""
    )

    return config


def extract_payload(
    text
):

    if not text:
        return []

    text = text.replace(
        "\r",
        ""
    )

    output = []

    # -----------------------------------------------------
    # مستقیم
    # -----------------------------------------------------

    for match in URI_PATTERN.findall(
        text
    ):

        config = normalize_config(
            match
        )

        if config:
            output.append(
                config
            )

    # -----------------------------------------------------
    # Base64 کل فایل
    # -----------------------------------------------------

    decoded = decode64(
        text
    )

    if decoded:

        for match in URI_PATTERN.findall(
            decoded
        ):

            config = normalize_config(
                match
            )

            if config:
                output.append(
                    config
                )

    # -----------------------------------------------------
    # Base64 هر خط
    # -----------------------------------------------------

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        if "://" in line:
            continue

        if len(line) < 20:
            continue

        decoded_line = decode64(
            line
        )

        if not decoded_line:
            continue

        for match in URI_PATTERN.findall(
            decoded_line
        ):

            config = normalize_config(
                match
            )

            if config:
                output.append(
                    config
                )

    return output


# =========================================================
# FETCH SOURCE
# =========================================================

def fetch_source(
    url
):

    for attempt in range(
        FETCH_RETRIES + 1
    ):

        try:

            response = session().get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True
            )

            if (
                response.ok
                and response.text
            ):

                return extract_payload(
                    response.text
                )[
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

        for future in as_completed(
            futures
        ):

            url = futures[
                future
            ]

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

def proto(
    config
):

    try:

        return (
            config
            .split(
                "://",
                1
            )[0]
            .lower()
            .strip()
        )

    except Exception:
        return ""


# =========================================================
# PARSE
# =========================================================

def parsed(
    config
):

    try:
        return urlparse(
            config
        )
    except Exception:
        return None


def query(
    config
):

    p = parsed(
        config
    )

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

    value = q.get(
        key
    )

    if not value:
        return default

    if isinstance(
        value,
        list
    ):
        return value[0]

    return str(value)


def host_port(
    config
):

    p = parsed(
        config
    )

    if not p:
        return "", 0

    host = (
        p.hostname
        or ""
    )

    try:
        port = (
            p.port
            or 0
        )
    except Exception:
        port = 0

    return (
        host.lower().strip(),
        port
    )


# =========================================================
# HOST CHECK
# =========================================================

def is_junk_host(
    host
):

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

        ip = ipaddress.ip_address(
            h
        )

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

    return h.endswith(
        ".local"
    )


# =========================================================
# VALID CONFIG
# =========================================================

def valid_config(
    config
):

    if not config:
        return False

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

        decoded = decode64(
            config[8:]
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

def fingerprint(
    config
):

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
        str(x)
        .strip()
        .lower()
        for x in (
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
        )
    )


# =========================================================
# DEDUPE
# =========================================================

def dedupe(
    configs
):

    seen = set()
    output = []

    for config in configs:

        config = normalize_config(
            config
        )

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
# QUALITY SCORE
# =========================================================

def quality_score(
    config
):

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

def tcp_probe(
    item
):

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

def benchmark(
    configs
):

    if not configs:
        return []

    candidates = configs[
        :MAX_TEST
    ]

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
                        "score": quality_score(
                            config
                        ),
                    })

            except Exception:
                pass

    # -----------------------------------------------------
    # Second pass
    # -----------------------------------------------------

    if len(results) < SECOND_PASS:

        remaining = configs[
            MAX_TEST:
            MAX_TEST + SECOND_PASS
        ]

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

    return results


# =========================================================
# ONLY NUKCROW REMARK
# =========================================================

def config_line(
    config
):

    # هر چیزی بعد # از منبع حذف شده
    config = config.split(
        "#",
        1
    )[0].strip()

    # فقط #nukcrow
    return (
        config
        + "#nukcrow"
    )


# =========================================================
# SELECT
# =========================================================

def select_records(
    results,
    limit,
    predicate=None
):

    if not results:
        return []

    selected = []
    seen = set()

    # -----------------------------------------------------
    # PASS 1
    # Diverse hosts
    # -----------------------------------------------------

    host_count = {}

    for item in results:

        if len(
            selected
        ) >= limit:
            break

        config = item[
            "config"
        ]

        if predicate and not predicate(
            config
        ):
            continue

        fp = fingerprint(
            config
        )

        if fp in seen:
            continue

        host, _ = host_port(
            config
        )

        if host_count.get(
            host,
            0
        ) >= MAX_PER_HOST:
            continue

        selected.append(
            item
        )

        seen.add(
            fp
        )

        host_count[host] = (
            host_count.get(
                host,
                0
            ) + 1
        )

    # -----------------------------------------------------
    # PASS 2
    # Fill quantity
    # -----------------------------------------------------

    if len(
        selected
    ) < limit:

        for item in results:

            if len(
                selected
            ) >= limit:
                break

            config = item[
                "config"
            ]

            if predicate and not predicate(
                config
            ):
                continue

            fp = fingerprint(
                config
            )

            if fp in seen:
                continue

            selected.append(
                item
            )

            seen.add(
                fp
            )

    return selected[
        :limit
    ]


# =========================================================
# FILL SUB
# =========================================================

def fill_subscription(
    primary,
    fallback,
    limit
):

    selected = select_records(
        primary,
        limit
    )

    if len(
        selected
    ) >= limit:

        return selected[
            :limit
        ]

    used = {
        fingerprint(
            x["config"]
        )
        for x in selected
    }

    for item in fallback:

        if len(
            selected
        ) >= limit:
            break

        fp = fingerprint(
            item["config"]
        )

        if fp in used:
            continue

        selected.append(
            item
        )

        used.add(
            fp
        )

    return selected[
        :limit
    ]


# =========================================================
# WRITE FILE
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

        for item in records:

            f.write(
                config_line(
                    item["config"]
                )
                + "\n"
            )


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

        try:

            os.remove(
                os.path.join(
                    OUT_DIR,
                    filename
                )
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


# =========================================================
# PROTOCOLS
# =========================================================

def write_protocols(
    results
):

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

        write_file(
            os.path.join(
                OUT_DIR,
                f"{ptype}.txt"
            ),
            selected
        )


# =========================================================
# IRAN SUBS
# =========================================================

def write_iran(
    iran_results,
    mci_results,
    irancell_results,
    rightel_results,
    all_results
):

    # -----------------------------------------------------
    # BEST IRAN
    # -----------------------------------------------------

    best_iran = fill_subscription(
        iran_results,
        all_results,
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

    if len(
        mix_pool
    ) < IRAN_SUB_SIZE:

        mix_pool.extend(
            all_results
        )

    random.shuffle(
        mix_pool
    )

    mix_iran = select_records(
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

    mci = fill_subscription(
        mci_results,
        iran_results,
        IRAN_SUB_SIZE
    )

    if len(mci) < IRAN_SUB_SIZE:

        mci = fill_subscription(
            mci,
            all_results,
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

    irancell = fill_subscription(
        irancell_results,
        iran_results,
        IRAN_SUB_SIZE
    )

    if len(
        irancell
    ) < IRAN_SUB_SIZE:

        irancell = fill_subscription(
            irancell,
            all_results,
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

    rightel = fill_subscription(
        rightel_results,
        iran_results,
        IRAN_SUB_SIZE
    )

    if len(
        rightel
    ) < IRAN_SUB_SIZE:

        rightel = fill_subscription(
            rightel,
            all_results,
            IRAN_SUB_SIZE
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "rightel.txt"
        ),
        rightel
    )


# =========================================================
# RANDOM 200 PLACEHOLDER
# =========================================================

def create_random_200_placeholder():

    path = os.path.join(
        OUT_DIR,
        "random_200.txt"
    )

    # فعلاً عمداً خالی
    # ربات بعداً Repositoryهای بخش
    # RANDOM_200_SOURCES را می‌خواند.

    with open(
        path,
        "w",
        encoding="utf-8"
    ):
        pass


# =========================================================
# SUMMARY
# =========================================================

def print_summary():

    print(
        "\n"
        + "=" * 60
    )

    print(
        "NUKCROW SUBSCRIPTIONS"
    )

    print(
        "=" * 60
    )

    if not os.path.isdir(
        OUT_DIR
    ):
        return

    for filename in sorted(
        os.listdir(
            OUT_DIR
        )
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
    # BENCHMARK
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # CLEAR
    # -----------------------------------------------------

    clear_old_subscriptions()

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    write_general(
        alive_all
    )

    # -----------------------------------------------------
    # PROTOCOL
    # -----------------------------------------------------

    write_protocols(
        alive_all
    )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    write_iran(
        alive_iran,
        alive_mci,
        alive_irancell,
        alive_rightel,
        alive_all
    )

    # -----------------------------------------------------
    # RANDOM 200
    # -----------------------------------------------------

    create_random_200_placeholder()

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
