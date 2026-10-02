import os
import re
import ssl
import json
import time
import base64
import socket
import hashlib
import threading
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ============================================================
# CONFIG
# ============================================================

OUT_DIR = "sub/general"

REMARK = "nukcrow"

TOTAL_CONFIGS = 20000

SUB_COUNT = 10
SUB_SIZE = 2000

PROTOCOL_SIZE = 1000
IRAN_SIZE = 1000
BOT_SIZE = 1000

FETCH_TIMEOUT = 15

TEST_TIMEOUT = 2.0

FETCH_WORKERS = 40
TEST_WORKERS = 180

SOURCE_LIMIT = 50000

SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
}


# ============================================================
# MAIN SOURCES
# ============================================================

SOURCES_PRIORITY = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/servers/vless_servers.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/refs/heads/main/public/Top500.txt",
    "https://raw.githubusercontent.com/snaCW/Config/main/config.txt",
    "https://raw.githubusercontent.com/snaCW/Config/main/proxy.txt",
]


# ============================================================
# BOT SOURCES
# ============================================================

BOT_SOURCES = [
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no10.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/mix.txt",
    "",
    "",
    "",
]


# ============================================================
# HTTP SESSION
# ============================================================

_thread_local = threading.local()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)


def get_session():
    session = getattr(_thread_local, "session", None)

    if session is None:
        session = requests.Session()

        session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "keep-alive",
        })

        _thread_local.session = session

    return session


# ============================================================
# BASE64
# ============================================================

def decode64(value):
    if not value:
        return ""

    value = value.strip()

    value = value.replace("-", "+")
    value = value.replace("_", "/")

    value += "=" * (-len(value) % 4)

    try:
        return base64.b64decode(
            value,
            validate=False
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ============================================================
# NORMALIZE INPUT
# ============================================================

def normalize_text(text):
    if not text:
        return ""

    text = text.replace("\r", "\n")

    text = text.replace("\\/", "/")
    text = text.replace("\\.", ".")
    text = text.replace("\\_", "_")

    text = text.replace("&#x20;", " ")

    return text


# ============================================================
# URI EXTRACTION
# ============================================================

URI_PATTERN = re.compile(
    r"(?:vless|vmess|trojan|ss)://[^\s<>'\"]+",
    re.IGNORECASE
)


def extract_uris(text):
    if not text:
        return []

    text = normalize_text(text)

    found = URI_PATTERN.findall(text)

    result = []

    for item in found:
        item = item.strip()

        while item.endswith(
            (
                ",",
                ";",
                ".",
                ")",
                "]",
                "}",
            )
        ):
            item = item[:-1]

        if item:
            result.append(item)

    return result


# ============================================================
# VMESS
# ============================================================

def parse_vmess(uri):
    try:
        raw = uri.split("://", 1)[1]

        decoded = decode64(raw)

        if not decoded:
            return None

        data = json.loads(decoded)

        return data

    except Exception:
        return None


# ============================================================
# SS
# ============================================================

def parse_ss(uri):
    try:
        body = uri.split("://", 1)[1]

        body = body.split("#", 1)[0]

        if "@" in body:
            userinfo, address = body.rsplit("@", 1)

            if ":" in address:
                host, port = address.rsplit(":", 1)

                try:
                    port = int(port)
                except Exception:
                    return None

                return {
                    "host": host,
                    "port": port,
                    "userinfo": userinfo,
                }

        decoded = decode64(body)

        if not decoded:
            return None

        if "@" not in decoded:
            return None

        userinfo, address = decoded.rsplit("@", 1)

        if ":" not in address:
            return None

        host, port = address.rsplit(":", 1)

        try:
            port = int(port)
        except Exception:
            return None

        return {
            "host": host,
            "port": port,
            "userinfo": userinfo,
        }

    except Exception:
        return None


# ============================================================
# ENDPOINT
# ============================================================

def endpoint(uri):
    try:
        scheme = uri.split("://", 1)[0].lower()

        if scheme == "vmess":
            data = parse_vmess(uri)

            if not data:
                return None

            host = (
                data.get("add")
                or data.get("address")
                or ""
            )

            port = data.get("port")

            try:
                port = int(str(port))
            except Exception:
                return None

            return {
                "scheme": "vmess",
                "host": host,
                "port": port,
                "data": data,
            }

        if scheme == "ss":
            data = parse_ss(uri)

            if not data:
                return None

            return {
                "scheme": "ss",
                "host": data["host"],
                "port": data["port"],
                "data": data,
            }

        parsed = urlparse(uri)

        host = parsed.hostname

        port = parsed.port

        if not host or not port:
            return None

        params = parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "params": params,
            "parsed": parsed,
        }

    except Exception:
        return None


# ============================================================
# VALID CONFIG
# ============================================================

def valid_config(uri):
    if not uri:
        return False

    uri = uri.strip()

    if not uri.lower().startswith(
        (
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
        )
    ):
        return False

    info = endpoint(uri)

    if not info:
        return False

    host = str(info.get("host", "")).strip()

    port = info.get("port")

    if not host:
        return False

    if not isinstance(port, int):
        return False

    if port < 1 or port > 65535:
        return False

    return True


# ============================================================
# FINGERPRINT
# ============================================================

def fingerprint(uri):
    info = endpoint(uri)

    if not info:
        return hashlib.sha256(
            uri.encode()
        ).hexdigest()

    scheme = info.get("scheme", "")

    host = info.get("host", "")

    port = info.get("port", "")

    if scheme == "vmess":
        data = info.get("data", {})

        key = "|".join([
            "vmess",
            str(data.get("id", "")),
            str(data.get("add", "")),
            str(data.get("port", "")),
            str(data.get("net", "")),
            str(data.get("path", "")),
            str(data.get("host", "")),
            str(data.get("tls", "")),
            str(data.get("sni", "")),
        ])

    elif scheme == "ss":
        data = info.get("data", {})

        key = "|".join([
            "ss",
            str(data.get("userinfo", "")),
            str(host),
            str(port),
        ])

    else:
        parsed = info.get("parsed")

        username = ""

        if parsed:
            username = parsed.username or ""

        params = info.get("params", {})

        key = "|".join([
            str(scheme),
            str(username),
            str(host),
            str(port),
            str(params.get("security", [""])[0]),
            str(params.get("type", [""])[0]),
            str(params.get("sni", [""])[0]),
            str(params.get("host", [""])[0]),
            str(params.get("path", [""])[0]),
            str(params.get("flow", [""])[0]),
        ])

    return hashlib.sha256(
        key.encode(
            "utf-8",
            errors="ignore"
        )
    ).hexdigest()


# ============================================================
# PATTERN SCORING
# ============================================================

def pattern_score(uri):
    """
    این امتیازدهی از نمونه‌هایی که فرستادی ساخته شده.

    هدف:
    پیدا کردن کانفیگ‌هایی که از نظر ساختار شبیه
    نمونه‌های موردنظر هستند.

    امتیاز بالا به معنی Ping پایین تضمین‌شده نیست.
    بعد از این مرحله تست اتصال انجام می‌شود.
    """

    info = endpoint(uri)

    if not info:
        return -999

    scheme = info.get("scheme", "").lower()

    score = 0

    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    if scheme == "vless":
        score += 12

    elif scheme == "trojan":
        score += 10

    elif scheme == "vmess":
        score += 8

    elif scheme == "ss":
        score += 7


    # --------------------------------------------------------
    # VMESS
    # --------------------------------------------------------

    if scheme == "vmess":
        data = info.get("data", {})

        network = str(
            data.get("net", "")
        ).lower()

        tls = str(
            data.get("tls", "")
        ).lower()

        if network == "ws":
            score += 8

        elif network == "grpc":
            score += 6

        elif network == "tcp":
            score += 6

        if tls in {
            "tls",
            "reality",
        }:
            score += 6

        if data.get("path"):
            score += 3

        if data.get("host"):
            score += 3

        if data.get("sni"):
            score += 3

        return score


    # --------------------------------------------------------
    # SS
    # --------------------------------------------------------

    if scheme == "ss":
        score += 5

        return score


    # --------------------------------------------------------
    # URI PARAMETERS
    # --------------------------------------------------------

    params = info.get("params", {})

    transport = str(
        params.get(
            "type",
            [""]
        )[0]
    ).lower()

    security = str(
        params.get(
            "security",
            [""]
        )[0]
    ).lower()

    host = str(
        params.get(
            "host",
            [""]
        )[0]
    )

    sni = str(
        params.get(
            "sni",
            [""]
        )[0]
    )

    path = str(
        params.get(
            "path",
            [""]
        )[0]
    )

    flow = str(
        params.get(
            "flow",
            [""]
        )[0]
    ).lower()

    alpn = str(
        params.get(
            "alpn",
            [""]
        )[0]
    ).lower()


    # --------------------------------------------------------
    # TRANSPORT
    # --------------------------------------------------------

    if transport == "ws":
        score += 12

    elif transport == "xhttp":
        score += 12

    elif transport == "tcp":
        score += 9

    elif transport == "grpc":
        score += 9

    elif transport == "httpupgrade":
        score += 8


    # --------------------------------------------------------
    # SECURITY
    # --------------------------------------------------------

    if security == "tls":
        score += 10

    elif security == "reality":
        score += 12

    elif security == "none":
        score += 5


    # --------------------------------------------------------
    # HOST
    # --------------------------------------------------------

    if host:
        score += 6


    # --------------------------------------------------------
    # SNI
    # --------------------------------------------------------

    if sni:
        score += 6


    # --------------------------------------------------------
    # PATH
    # --------------------------------------------------------

    if path:
        score += 5


    # --------------------------------------------------------
    # ALPN
    # --------------------------------------------------------

    if alpn:
        score += 3


    # --------------------------------------------------------
    # REALITY FLOW
    # --------------------------------------------------------

    if flow == "xtls-rprx-vision":
        score += 10


    # --------------------------------------------------------
    # ADDRESS DIFFERENT FROM HOST
    # --------------------------------------------------------

    endpoint_host = str(
        info.get(
            "host",
            ""
        )
    ).lower()

    config_host = host.lower()

    if (
        endpoint_host
        and config_host
        and endpoint_host != config_host
    ):
        score += 8


    # --------------------------------------------------------
    # NON-443 PORTS ARE VALID
    # --------------------------------------------------------

    port = int(
        info.get(
            "port",
            0
        )
    )

    # deliberately do NOT prefer 443 only
    if port in {
        80,
        2095,
        2082,
        2086,
        8080,
        8443,
        1001,
        18901,
        59924,
    }:
        score += 2


    return score


# ============================================================
# CLEAN REMARK
# ============================================================

def clean_config(uri):
    """
    هر Remark قبلی را حذف می‌کند.
    Remark نهایی فقط در render() اضافه می‌شود.
    """

    if not uri:
        return ""

    uri = uri.strip()

    if "#" in uri:
        uri = uri.split("#", 1)[0]

    return uri.strip()


# ============================================================
# RENDER
# ============================================================

def render(uri):
    uri = clean_config(uri)

    if not uri:
        return ""

    return f"{uri}#{REMARK}"


# ============================================================
# FETCH SOURCE
# ============================================================

def fetch_source(url):
    if not url:
        return []

    session = get_session()

    for attempt in range(3):

        try:
            response = session.get(
                url,
                timeout=FETCH_TIMEOUT,
                allow_redirects=True,
            )

            if response.status_code != 200:
                continue

            text = response.text

            text = normalize_text(text)

            # Direct URI extraction
            configs = extract_uris(text)

            # Sometimes source is base64 subscription
            if not configs:
                decoded = decode64(
                    text.strip()
                )

                if decoded:
                    configs = extract_uris(
                        decoded
                    )

            valid = []

            for item in configs:

                if valid_config(item):
                    valid.append(item)

                if len(valid) >= SOURCE_LIMIT:
                    break

            print(
                f"[FETCH] {url} -> {len(valid)}"
            )

            return valid

        except Exception as exc:
            if attempt == 2:
                print(
                    f"[FETCH-ERROR] {url} -> {exc}"
                )

            time.sleep(0.5)

    return []


# ============================================================
# UNIQUE
# ============================================================

def unique(configs):
    seen = set()

    result = []

    for uri in configs:

        if not valid_config(uri):
            continue

        fp = fingerprint(uri)

        if fp in seen:
            continue

        seen.add(fp)

        result.append(uri)

    return result


# ============================================================
# COLLECT SOURCES
# ============================================================

def collect_sources(sources):
    all_configs = []

    sources = [
        x.strip()
        for x in sources
        if x and x.strip()
    ]

    print(
        f"[SOURCE] total sources = {len(sources)}"
    )

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                fetch_source,
                source
            ): source
            for source in sources
        }

        for future in as_completed(futures):

            try:
                configs = future.result()

                all_configs.extend(
                    configs
                )

            except Exception as exc:
                source = futures[future]

                print(
                    f"[SOURCE-ERROR] {source} -> {exc}"
                )

    all_configs = unique(
        all_configs
    )

    print(
        f"[COLLECT] unique = {len(all_configs)}"
    )

    return all_configs


# ============================================================
# TCP TEST
# ============================================================

def tcp_test(uri):
    info = endpoint(uri)

    if not info:
        return None

    host = info.get("host")

    port = info.get("port")

    if not host or not port:
        return None

    start = time.perf_counter()

    sock = None

    try:
        sock = socket.create_connection(
            (
                host,
                int(port)
            ),
            timeout=TEST_TIMEOUT
        )

        elapsed = (
            time.perf_counter()
            - start
        ) * 1000.0

        return elapsed

    except Exception:
        return None

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# BENCHMARK
# ============================================================

def benchmark(configs):
    """
    TCP reachability benchmark.

    توجه:
    این تست TCP latency است، نه handshake کامل
    VLESS/VMess/Trojan/SS.
    """

    print(
        f"[BENCH] testing {len(configs)} configs..."
    )

    results = []

    total = len(configs)

    done = 0

    with ThreadPoolExecutor(
        max_workers=TEST_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                tcp_test,
                uri
            ): uri
            for uri in configs
        }

        for future in as_completed(futures):

            uri = futures[future]

            try:
                latency = future.result()

            except Exception:
                latency = None

            done += 1

            if latency is not None:
                results.append(
                    (
                        latency,
                        pattern_score(uri),
                        uri,
                    )
                )

            if done % 500 == 0:
                print(
                    f"[BENCH] {done}/{total} "
                    f"alive={len(results)}"
                )

    # --------------------------------------------------------
    # Sort:
    # First latency
    # Then pattern score
    # --------------------------------------------------------

    results.sort(
        key=lambda x: (
            x[0],
            -x[1],
        )
    )

    print(
        f"[BENCH] alive = {len(results)}"
    )

    return results


# ============================================================
# PROTOCOL
# ============================================================

def protocol_name(uri):
    if not uri:
        return ""

    return uri.split(
        "://",
        1
    )[0].lower()


# ============================================================
# MIXED POOL
# ============================================================

def build_mixed_pool(
    benchmarked,
    limit=TOTAL_CONFIGS
):
    """
    نتیجه نهایی بر اساس latency.

    Pattern score فقط tie-breaker است
    تا کانفیگ‌های شبیه نمونه‌های کاربر
    در Latency مشابه اولویت بگیرند.
    """

    selected = []

    seen = set()

    for latency, score, uri in benchmarked:

        fp = fingerprint(uri)

        if fp in seen:
            continue

        seen.add(fp)

        selected.append(uri)

        if len(selected) >= limit:
            break

    return selected


# ============================================================
# FILE HELPERS
# ============================================================

def ensure_out_dir():
    os.makedirs(
        OUT_DIR,
        exist_ok=True
    )


def write_file(
    filename,
    configs
):
    ensure_out_dir()

    path = os.path.join(
        OUT_DIR,
        filename
    )

    rendered = []

    for uri in configs:

        value = render(uri)

        if value:
            rendered.append(value)

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        if rendered:
            f.write(
                "\n".join(rendered)
            )

            f.write("\n")

    print(
        f"[WRITE] {filename} = {len(rendered)}"
    )

    return len(rendered)


# ============================================================
# SUBSCRIPTIONS
# ============================================================

def write_subscriptions(
    selected
):
    if len(selected) < TOTAL_CONFIGS:
        raise RuntimeError(
            f"Need {TOTAL_CONFIGS} configs, "
            f"got {len(selected)}"
        )

    for index in range(
        SUB_COUNT
    ):
        start = index * SUB_SIZE

        end = start + SUB_SIZE

        chunk = selected[
            start:end
        ]

        if len(chunk) != SUB_SIZE:
            raise RuntimeError(
                f"sub{index + 1}.txt "
                f"requires {SUB_SIZE}, "
                f"got {len(chunk)}"
            )

        write_file(
            f"sub{index + 1}.txt",
            chunk
        )


# ============================================================
# PROTOCOL FILES
# ============================================================

def write_protocols(
    selected
):
    buckets = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
    }

    for uri in selected:

        protocol = protocol_name(
            uri
        )

        if protocol in buckets:

            if len(
                buckets[protocol]
            ) < PROTOCOL_SIZE:

                buckets[protocol].append(
                    uri
                )

    for protocol in (
        "vless",
        "vmess",
        "trojan",
        "ss",
    ):

        configs = buckets[
            protocol
        ]

        write_file(
            f"{protocol}.txt",
            configs
        )


# ============================================================
# IRAN SOURCES
# ============================================================

IRAN_SOURCES = [
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
]


# ============================================================
# IRAN COLLECTION
# ============================================================

def collect_iran():
    configs = collect_sources(
        IRAN_SOURCES
    )

    if not configs:
        return []

    tested = benchmark(
        configs
    )

    return build_mixed_pool(
        tested,
        IRAN_SIZE
    )


# ============================================================
# IRAN OUTPUTS
# ============================================================

def write_iran(
    selected
):
    """
    این فایل‌ها در این نسخه از همان
    مجموعه‌ی تست‌شده‌ی Iran پر می‌شوند.

    اگر بعداً بخواهی MCI / Irancell / Rightel
    واقعاً بر اساس اپراتور جدا شوند،
    باید برای هر اپراتور منبع یا تست جداگانه داشته باشیم.
    """

    selected = selected[
        :IRAN_SIZE
    ]

    write_file(
        "best_iran.txt",
        selected
    )

    write_file(
        "mix_iran.txt",
        selected
    )

    write_file(
        "mci.txt",
        selected
    )

    write_file(
        "irancell.txt",
        selected
    )

    write_file(
        "rightel.txt",
        selected
    )


# ============================================================
# BOT
# ============================================================

def write_bot():
    sources = [
        x.strip()
        for x in BOT_SOURCES
        if x and x.strip()
    ]

    if not sources:
        write_file(
            "bot.txt",
            []
        )

        return

    configs = collect_sources(
        sources
    )

    if not configs:
        write_file(
            "bot.txt",
            []
        )

        return

    tested = benchmark(
        configs
    )

    selected = build_mixed_pool(
        tested,
        BOT_SIZE
    )

    write_file(
        "bot.txt",
        selected
    )


# ============================================================
# HYSTERIA2 REMOVAL
# ============================================================

def remove_hysteria2():
    path = os.path.join(
        OUT_DIR,
        "hysteria2.txt"
    )

    if os.path.exists(path):

        try:
            os.remove(path)

            print(
                "[REMOVE] hysteria2.txt"
            )

        except Exception as exc:

            print(
                f"[REMOVE-ERROR] {exc}"
            )


# ============================================================
# READ FILE
# ============================================================

def read_lines(
    filename
):
    path = os.path.join(
        OUT_DIR,
        filename
    )

    if not os.path.exists(path):
        return []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        return [
            x.strip()
            for x in f
            if x.strip()
        ]


# ============================================================
# VERIFY EXACT
# ============================================================

def verify_exact_file(
    filename,
    expected
):
    lines = read_lines(
        filename
    )

    if len(lines) != expected:
        raise RuntimeError(
            f"{filename} requires "
            f"{expected}, got {len(lines)}"
        )

    return True


# ============================================================
# VERIFY OPTIONAL
# ============================================================

def verify_optional_file(
    filename,
    maximum
):
    lines = read_lines(
        filename
    )

    if len(lines) > maximum:
        raise RuntimeError(
            f"{filename} exceeds "
            f"{maximum}: {len(lines)}"
        )

    return True


# ============================================================
# VERIFY SUBSCRIPTIONS
# ============================================================

def verify_subscriptions():
    all_seen = set()

    for index in range(
        1,
        SUB_COUNT + 1
    ):

        filename = (
            f"sub{index}.txt"
        )

        lines = read_lines(
            filename
        )

        if len(lines) != SUB_SIZE:
            raise RuntimeError(
                f"{filename} requires "
                f"{SUB_SIZE}, got {len(lines)}"
            )

        for line in lines:

            if line in all_seen:
                raise RuntimeError(
                    f"Duplicate config "
                    f"between subscriptions: "
                    f"{line}"
                )

            all_seen.add(line)

    if len(all_seen) != TOTAL_CONFIGS:
        raise RuntimeError(
            f"Subscriptions total "
            f"must be {TOTAL_CONFIGS}, "
            f"got {len(all_seen)}"
        )

    print(
        f"[VERIFY] subscriptions = "
        f"{len(all_seen)} unique"
    )


# ============================================================
# VERIFY PROTOCOLS
# ============================================================

def verify_protocols():
    for protocol in (
        "vless",
        "vmess",
        "trojan",
        "ss",
    ):

        verify_optional_file(
            f"{protocol}.txt",
            PROTOCOL_SIZE
        )

    print(
        "[VERIFY] protocol files OK"
    )


# ============================================================
# VERIFY IRAN
# ============================================================

def verify_iran():
    for filename in (
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
    ):

        verify_optional_file(
            filename,
            IRAN_SIZE
        )

    print(
        "[VERIFY] Iran files OK"
    )


# ============================================================
# VERIFY BOT
# ============================================================

def verify_bot():
    verify_optional_file(
        "bot.txt",
        BOT_SIZE
    )

    print(
        "[VERIFY] bot.txt OK"
    )


# ============================================================
# VERIFY NO HYSTERIA
# ============================================================

def verify_no_hysteria():
    path = os.path.join(
        OUT_DIR,
        "hysteria2.txt"
    )

    if os.path.exists(path):
        raise RuntimeError(
            "hysteria2.txt must not exist"
        )

    print(
        "[VERIFY] hysteria2.txt removed"
    )


# ============================================================
# VERIFY REMARK
# ============================================================

def verify_remark():
    files = [
        "all_configs.txt",
    ]

    for index in range(
        1,
        SUB_COUNT + 1
    ):
        files.append(
            f"sub{index}.txt"
        )

    for protocol in (
        "vless",
        "vmess",
        "trojan",
        "ss",
    ):
        files.append(
            f"{protocol}.txt"
        )

    for filename in (
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
        "bot.txt",
    ):
        files.append(filename)

    expected = f"#{REMARK}"

    for filename in files:

        path = os.path.join(
            OUT_DIR,
            filename
        )

        if not os.path.exists(path):
            continue

        lines = read_lines(
            filename
        )

        for line in lines:

            if not line.endswith(
                expected
            ):
                raise RuntimeError(
                    f"Wrong remark in "
                    f"{filename}: {line}"
                )

    print(
        f"[VERIFY] remark = #{REMARK}"
    )


# ============================================================
# ALL CONFIGS
# ============================================================

def write_all_configs(
    selected
):
    if len(selected) < TOTAL_CONFIGS:
        raise RuntimeError(
            f"all_configs requires "
            f"{TOTAL_CONFIGS}, "
            f"got {len(selected)}"
        )

    selected = selected[
        :TOTAL_CONFIGS
    ]

    write_file(
        "all_configs.txt",
        selected
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("NUKCROW CONFIG COLLECTOR")
    print("=" * 70)

    print(
        f"[CONFIG] target = {TOTAL_CONFIGS}"
    )

    print(
        f"[CONFIG] sub size = {SUB_SIZE}"
    )

    print(
        f"[CONFIG] protocol max = "
        f"{PROTOCOL_SIZE}"
    )

    print(
        f"[CONFIG] remark = #{REMARK}"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # PREPARE
    # --------------------------------------------------------

    ensure_out_dir()

    remove_hysteria2()


    # --------------------------------------------------------
    # COLLECT GENERAL
    # --------------------------------------------------------

    general_configs = collect_sources(
        SOURCES_PRIORITY
    )

    if not general_configs:
        raise RuntimeError(
            "No general configs found"
        )


    # --------------------------------------------------------
    # PATTERN SCORE
    # --------------------------------------------------------

    scored = []

    for uri in general_configs:

        score = pattern_score(
            uri
        )

        scored.append(
            (
                score,
                uri,
            )
        )

    scored.sort(
        key=lambda x: -x[0]
    )

    print(
        "[PATTERN] top scores:"
    )

    for score, uri in scored[:10]:

        info = endpoint(uri)

        if info:
            print(
                f"[PATTERN] "
                f"score={score} "
                f"{info.get('scheme')}://"
                f"{info.get('host')}:"
                f"{info.get('port')}"
            )


    # --------------------------------------------------------
    # BENCHMARK ALL
    # --------------------------------------------------------

    benchmarked = benchmark(
        general_configs
    )


    # --------------------------------------------------------
    # FINAL 20K
    # --------------------------------------------------------

    selected = build_mixed_pool(
        benchmarked,
        TOTAL_CONFIGS
    )

    print(
        f"[FINAL] selected = "
        f"{len(selected)}"
    )


    if len(selected) < TOTAL_CONFIGS:
        raise RuntimeError(
            f"Not enough tested configs. "
            f"Need {TOTAL_CONFIGS}, "
            f"got {len(selected)}"
        )


    # --------------------------------------------------------
    # SUB1 - SUB10
    # --------------------------------------------------------

    write_subscriptions(
        selected
    )


    # --------------------------------------------------------
    # PROTOCOL FILES
    # --------------------------------------------------------

    write_protocols(
        selected
    )


    # --------------------------------------------------------
    # IRAN
    # --------------------------------------------------------

    iran_configs = collect_iran()

    write_iran(
        iran_configs
    )


    # --------------------------------------------------------
    # BOT
    # --------------------------------------------------------

    write_bot()


    # --------------------------------------------------------
    # ALL CONFIGS
    # --------------------------------------------------------

    write_all_configs(
        selected
    )


    # --------------------------------------------------------
    # REMOVE HYSTERIA
    # --------------------------------------------------------

    remove_hysteria2()


    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    verify_subscriptions()

    verify_protocols()

    verify_iran()

    verify_bot()

    verify_no_hysteria()

    verify_remark()


    # --------------------------------------------------------
    # DONE
    # --------------------------------------------------------

    print("=" * 70)
    print("DONE")
    print("=" * 70)

    print(
        f"[DONE] {TOTAL_CONFIGS} configs"
    )

    print(
        "[DONE] sub1.txt ... sub10.txt"
    )

    print(
        "[DONE] protocol files"
    )

    print(
        "[DONE] Iran files"
    )

    print(
        "[DONE] bot.txt"
    )

    print(
        "[DONE] all_configs.txt"
    )

    print(
        "[DONE] hysteria2.txt removed"
    )

    print("=" * 70)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()
