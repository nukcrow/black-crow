import base64
import hashlib
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests


# =========================================================
# NUKCROW COLLECTOR
# =========================================================

OUT_DIR = "sub/general"
REMARK = "nukcrow"


# =========================================================
# GENERAL SETTINGS
# =========================================================

TOTAL_CONFIGS = 20000

SUB_COUNT = 10
SUB_SIZE = 2000


# =========================================================
# PROTOCOL SETTINGS
# =========================================================

PROTOCOL_SIZE = 1000


# =========================================================
# IRAN SETTINGS
# =========================================================

IRAN_SIZE = 1000


# =========================================================
# BOT SETTINGS
# =========================================================

BOT_SIZE = 1000


# =========================================================
# NETWORK SETTINGS
# =========================================================

FETCH_TIMEOUT = 15
TEST_TIMEOUT = 2.0

FETCH_WORKERS = 40
TEST_WORKERS = 180

SOURCE_LIMIT = 50000


# =========================================================
# SUPPORTED PROTOCOLS
# =========================================================

SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
}


# =========================================================
# BOT SOURCES
# =========================================================
#
# پنج جای خالی برای منابع خودت
#
# =========================================================

BOT_SOURCES = [

    # BOT SOURCE 1
    "",

    # BOT SOURCE 2
    "",

    # BOT SOURCE 3
    "",

    # BOT SOURCE 4
    "",

    # BOT SOURCE 5
    "",

]


# =========================================================
# MAIN SOURCES
# =========================================================

SOURCES_PRIORITY = [

    # =====================================================
    # 0xRadikal
    # =====================================================

    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",

    # =====================================================
    # FastNodes
    # =====================================================

    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt",

    # =====================================================
    # morpheusadam
    # =====================================================

    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vless.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vmess.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/trojan.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/shadowsocks.txt",

    # =====================================================
    # Iranian collectors
    # =====================================================

    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",

    # =====================================================
    # Config Collector
    # =====================================================

    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",

    # =====================================================
    # snaCW
    # =====================================================

    "https://raw.githubusercontent.com/snaCW/Config/main/config.txt",
    "https://raw.githubusercontent.com/snaCW/Config/main/proxy.txt",

]


# =========================================================
# SESSION
# =========================================================

def make_session():

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/140.0 Safari/537.36"
            )
        }
    )

    return session


# =========================================================
# BASE64
# =========================================================

def decode64(value):

    try:

        if not value:
            return ""

        value = re.sub(
            r"\s+",
            "",
            value,
        )

        value += "=" * (
            -len(value) % 4
        )

        decoded = base64.urlsafe_b64decode(
            value
        )

        return decoded.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:

        return ""


# =========================================================
# PROTOCOL
# =========================================================

def protocol(config):

    try:

        return (
            config
            .split(
                "://",
                1,
            )[0]
            .strip()
            .lower()
        )

    except Exception:

        return ""


# =========================================================
# CLEAN
# =========================================================

def clean_config(config):

    if not config:
        return ""

    config = config.strip()

    config = (
        config
        .replace("\r", "")
        .replace("\n", "")
        .strip()
    )

    # فقط remark قبلی را حذف می‌کنیم
    if "#nukcrow" in config:

        config = config.split(
            "#nukcrow",
            1,
        )[0]

    return config.strip()


# =========================================================
# URI PATTERN
# =========================================================

URI_PATTERN = re.compile(
    r"(?i)"
    r"(?:"
    r"vless|"
    r"vmess|"
    r"trojan|"
    r"ss"
    r")://"
    r"[^\s<>'\"`]+"
)


# =========================================================
# ADD EXTRACTED CONFIG
# =========================================================

def add_extracted(
    config,
    found,
    seen,
):

    config = clean_config(
        config
    )

    if not config:
        return

    p = protocol(
        config
    )

    if p not in SUPPORTED_PROTOCOLS:
        return

    if not valid_config(
        config
    ):
        return

    key = fingerprint(
        config
    )

    if key in seen:
        return

    seen.add(
        key
    )

    found.append(
        config
    )


# =========================================================
# EXTRACT URIS
# =========================================================

def extract_uris(text):

    if not text:
        return []

    found = []
    seen = set()

    # =====================================================
    # DIRECT URI SEARCH
    # =====================================================

    for match in URI_PATTERN.finditer(
        text
    ):

        add_extracted(
            match.group(0),
            found,
            seen,
        )

    # =====================================================
    # LINE BY LINE
    # =====================================================

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        line = line.strip(
            "\"'` ,;"
        )

        # -------------------------------------------------
        # Direct URI
        # -------------------------------------------------

        if re.match(
            r"(?i)^(vless|vmess|trojan|ss)://",
            line,
        ):

            add_extracted(
                line,
                found,
                seen,
            )

            continue

        # -------------------------------------------------
        # Multiple URIs
        # -------------------------------------------------

        for item in URI_PATTERN.findall(
            line
        ):

            add_extracted(
                item,
                found,
                seen,
            )

        # -------------------------------------------------
        # Base64 subscription
        # -------------------------------------------------

        decoded = decode64(
            line
        )

        if decoded:

            for item in URI_PATTERN.findall(
                decoded
            ):

                add_extracted(
                    item,
                    found,
                    seen,
                )

            for decoded_line in decoded.splitlines():

                decoded_line = decoded_line.strip()

                if not decoded_line:
                    continue

                if re.match(
                    r"(?i)^(vless|vmess|trojan|ss)://",
                    decoded_line,
                ):

                    add_extracted(
                        decoded_line,
                        found,
                        seen,
                    )

    return found


# =========================================================
# VMESS
# =========================================================

def parse_vmess(config):

    try:

        payload = config.split(
            "://",
            1,
        )[1]

        decoded = decode64(
            payload
        )

        if not decoded:
            return None

        data = json.loads(
            decoded
        )

        host = (
            data.get("add")
            or data.get("address")
            or data.get("host")
        )

        port = data.get(
            "port"
        )

        if not host or not port:
            return None

        port = int(
            str(port)
        )

        if not 1 <= port <= 65535:
            return None

        return host, port

    except Exception:

        return None


# =========================================================
# SHADOWSOCKS
# =========================================================

def parse_ss(config):

    try:

        config = clean_config(
            config
        )

        if not config.lower().startswith(
            "ss://"
        ):
            return None

        value = config[5:]

        # Remove remark
        value = value.split(
            "#",
            1,
        )[0]

        # Remove plugin/query
        value = value.split(
            "?",
            1,
        )[0]

        value = value.rstrip(
            "/"
        )

        if not value:
            return None

        # =================================================
        # SIP002
        #
        # ss://userinfo@host:port
        # =================================================

        if "@" in value:

            userinfo, address = value.rsplit(
                "@",
                1,
            )

            decoded_userinfo = decode64(
                userinfo
            )

            if (
                decoded_userinfo
                and ":"
                in decoded_userinfo
            ):

                userinfo = decoded_userinfo

            if ":" not in userinfo:
                return None

            # IPv6
            if address.startswith("["):

                closing = address.find(
                    "]"
                )

                if closing == -1:
                    return None

                host = address[
                    1:closing
                ]

                remainder = address[
                    closing + 1:
                ]

                if not remainder.startswith(
                    ":"
                ):
                    return None

                port_text = remainder[1:]

            else:

                if ":" not in address:
                    return None

                host, port_text = address.rsplit(
                    ":",
                    1,
                )

            host = host.strip()

            port_text = port_text.strip()

            if not host or not port_text:
                return None

            try:

                port = int(
                    port_text
                )

            except ValueError:

                return None

            if not 1 <= port <= 65535:
                return None

            return host, port

        # =================================================
        # LEGACY BASE64
        #
        # ss://BASE64(method:password@host:port)
        # =================================================

        decoded = decode64(
            value
        )

        if not decoded:
            return None

        decoded = decoded.strip()

        if "@" not in decoded:
            return None

        userinfo, address = decoded.rsplit(
            "@",
            1,
        )

        if ":" not in userinfo:
            return None

        if address.startswith("["):

            closing = address.find(
                "]"
            )

            if closing == -1:
                return None

            host = address[
                1:closing
            ]

            remainder = address[
                closing + 1:
            ]

            if not remainder.startswith(
                ":"
            ):
                return None

            port_text = remainder[1:]

        else:

            if ":" not in address:
                return None

            host, port_text = address.rsplit(
                ":",
                1,
            )

        host = host.strip()

        port_text = port_text.strip()

        if not host or not port_text:
            return None

        try:

            port = int(
                port_text
            )

        except ValueError:

            return None

        if not 1 <= port <= 65535:
            return None

        return host, port

    except Exception:

        return None


# =========================================================
# ENDPOINT
# =========================================================

def endpoint(config):

    try:

        p = protocol(
            config
        )

        if p == "vmess":

            return parse_vmess(
                config
            )

        if p == "ss":

            return parse_ss(
                config
            )

        parsed = urlparse(
            config
        )

        host = parsed.hostname

        if not host:
            return None

        try:

            port = parsed.port

        except ValueError:

            return None

        if not port:
            return None

        if not 1 <= port <= 65535:
            return None

        return host, port

    except Exception:

        return None


# =========================================================
# VALID CONFIG
# =========================================================

def valid_config(config):

    try:

        config = clean_config(
            config
        )

        if not config:
            return False

        if protocol(config) not in SUPPORTED_PROTOCOLS:
            return False

        if any(
            ord(c) < 32
            for c in config
        ):
            return False

        target = endpoint(
            config
        )

        if not target:
            return False

        host, port = target

        if not host:
            return False

        if host.lower() in {
            "localhost",
            "0.0.0.0",
            "::",
        }:
            return False

        return True

    except Exception:

        return False


# =========================================================
# FINGERPRINT
# =========================================================

def fingerprint(config):

    return hashlib.sha256(
        clean_config(
            config
        ).encode(
            "utf-8",
            errors="ignore",
        )
    ).hexdigest()


# =========================================================
# FETCH
# =========================================================

def fetch_source(url):

    session = make_session()

    try:

        response = session.get(
            url,
            timeout=FETCH_TIMEOUT,
        )

        if response.status_code != 200:

            print(
                f"[HTTP {response.status_code}] "
                f"{url}"
            )

            return []

        configs = extract_uris(
            response.text
        )

        if len(configs) > SOURCE_LIMIT:

            configs = configs[
                :SOURCE_LIMIT
            ]

        print(
            f"[SOURCE] "
            f"{len(configs):5d} "
            f"{url}"
        )

        return configs

    except Exception as exc:

        print(
            f"[FAILED] "
            f"{url} -> {exc}"
        )

        return []

    finally:

        session.close()


# =========================================================
# UNIQUE
# =========================================================

def unique(configs):

    result = []

    seen = set()

    for config in configs:

        config = clean_config(
            config
        )

        if not config:
            continue

        key = fingerprint(
            config
        )

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            config
        )

    return result


# =========================================================
# COLLECT
# =========================================================

def collect_sources():

    all_configs = []

    sources = list(
        SOURCES_PRIORITY
    )

    for url in BOT_SOURCES:

        url = url.strip()

        if url:

            sources.append(
                url
            )

    sources = list(
        dict.fromkeys(
            sources
        )
    )

    print(
        f"[SOURCES] {len(sources)}"
    )

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                fetch_source,
                url,
            ): url
            for url in sources
        }

        for job in as_completed(
            jobs
        ):

            try:

                all_configs.extend(
                    job.result()
                )

            except Exception:

                pass

    return unique(
        all_configs
    )


# =========================================================
# TCP TEST
# =========================================================

def tcp_test(config):

    target = endpoint(
        config
    )

    if not target:
        return False

    host, port = target

    try:

        with socket.create_connection(
            (
                host,
                port,
            ),
            timeout=TEST_TIMEOUT,
        ):

            return True

    except Exception:

        return False


# =========================================================
# BENCHMARK
# =========================================================

def benchmark(configs):

    alive = []

    if not configs:
        return alive

    print(
        f"[TEST] {len(configs)} configs"
    )

    with ThreadPoolExecutor(
        max_workers=TEST_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                tcp_test,
                config,
            ): config
            for config in configs
        }

        for job in as_completed(
            jobs
        ):

            config = jobs[job]

            try:

                if job.result():

                    alive.append(
                        config
                    )

            except Exception:

                pass

    return unique(
        alive
    )


# =========================================================
# PROTOCOL NAME
# =========================================================

def protocol_name(config):

    p = protocol(
        config
    )

    if p in SUPPORTED_PROTOCOLS:

        return p

    return ""


# =========================================================
# MIXED POOL
# =========================================================

def build_mixed_pool(configs):

    pools = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
    }

    for config in configs:

        p = protocol_name(
            config
        )

        if p in pools:

            pools[p].append(
                config
            )

    mixed = []

    indexes = {
        "vless": 0,
        "vmess": 0,
        "trojan": 0,
        "ss": 0,
    }

    order = [
        "vless",
        "vmess",
        "trojan",
        "ss",
    ]

    while len(mixed) < TOTAL_CONFIGS:

        added = False

        for p in order:

            index = indexes[p]

            if index >= len(
                pools[p]
            ):
                continue

            mixed.append(
                pools[p][index]
            )

            indexes[p] += 1

            added = True

            if len(mixed) >= TOTAL_CONFIGS:
                break

        if not added:
            break

    # اگر pool متوازن نبود،
    # بقیه کانفیگ‌های موجود را هم اضافه کن.

    if len(mixed) < TOTAL_CONFIGS:

        used = {
            fingerprint(x)
            for x in mixed
        }

        for config in configs:

            key = fingerprint(
                config
            )

            if key in used:
                continue

            mixed.append(
                config
            )

            used.add(
                key
            )

            if len(mixed) >= TOTAL_CONFIGS:
                break

    return unique(
        mixed
    )


# =========================================================
# RENDER
# =========================================================

def render(configs):

    if not configs:
        return ""

    lines = []

    for config in configs:

        config = clean_config(
            config
        )

        if config:

            lines.append(
                f"{config}#{REMARK}"
            )

    if not lines:
        return ""

    return (
        "\n".join(lines)
        + "\n"
    )


# =========================================================
# WRITE
# =========================================================

def write_file(
    name,
    configs,
):

    os.makedirs(
        OUT_DIR,
        exist_ok=True,
    )

    path = os.path.join(
        OUT_DIR,
        name,
    )

    temp = (
        path
        + ".tmp"
    )

    with open(
        temp,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:

        file.write(
            render(
                configs
            )
        )

    os.replace(
        temp,
        path
    )


# =========================================================
# WRITE PROTOCOLS
# =========================================================
#
# IMPORTANT:
# کمتر از 1000 بودن خطا نیست.
# همان تعداد موجود نوشته می‌شود.
#
# =========================================================

def write_protocols(configs):

    protocols = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
    }

    for config in configs:

        p = protocol_name(
            config
        )

        if p in protocols:

            protocols[p].append(
                config
            )

    for name, pool in protocols.items():

        pool = unique(
            pool
        )

        selected = pool[
            :PROTOCOL_SIZE
        ]

        write_file(
            f"{name}.txt",
            selected,
        )

        print(
            f"[WRITE] "
            f"{name}.txt = "
            f"{len(selected)}"
        )


# =========================================================
# IRAN SOURCES
# =========================================================

IRAN_SOURCE_KEYS = [
    "iran",
    "GO_V2rayCollector",
    "Config-Collector",
    "snaCW",
]


def get_iran_sources():

    return [
        url
        for url in SOURCES_PRIORITY
        if any(
            key in url
            for key in IRAN_SOURCE_KEYS
        )
    ]


# =========================================================
# COLLECT IRAN
# =========================================================

def collect_iran():

    urls = get_iran_sources()

    configs = []

    if not urls:
        return []

    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        jobs = [
            executor.submit(
                fetch_source,
                url,
            )
            for url in urls
        ]

        for job in as_completed(
            jobs
        ):

            try:

                configs.extend(
                    job.result()
                )

            except Exception:

                pass

    return unique(
        configs
    )


# =========================================================
# WRITE IRAN
# =========================================================
#
# کمتر از 1000 بودن خطا نیست.
# هر مقدار موجود نوشته می‌شود.
#
# =========================================================

def write_iran(
    iran_configs,
    global_configs,
):

    iran_alive = benchmark(
        iran_configs
    )

    iran_alive = unique(
        iran_alive
    )

    combined = unique(
        iran_alive
        + global_configs
    )

    selected = combined[
        :IRAN_SIZE
    ]

    for name in [
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
    ]:

        write_file(
            name,
            selected,
        )

        print(
            f"[WRITE] "
            f"{name} = "
            f"{len(selected)}"
        )


# =========================================================
# BOT
# =========================================================

def write_bot():

    bot_configs = []

    for url in BOT_SOURCES:

        url = url.strip()

        if not url:
            continue

        try:

            bot_configs.extend(
                fetch_source(
                    url
                )
            )

        except Exception:

            pass

    bot_configs = unique(
        bot_configs
    )

    if not bot_configs:

        write_file(
            "bot.txt",
            [],
        )

        print(
            "[WRITE] bot.txt = 0"
        )

        return

    bot_alive = benchmark(
        bot_configs
    )

    bot_alive = unique(
        bot_alive
    )

    selected = bot_alive[
        :BOT_SIZE
    ]

    write_file(
        "bot.txt",
        selected,
    )

    print(
        f"[WRITE] "
        f"bot.txt = "
        f"{len(selected)}"
    )


# =========================================================
# REMOVE HYSTERIA2
# =========================================================

def remove_hysteria2():

    path = os.path.join(
        OUT_DIR,
        "hysteria2.txt",
    )

    if os.path.exists(
        path
    ):

        os.remove(
            path
        )

        print(
            "[REMOVE] hysteria2.txt"
        )


# =========================================================
# READ
# =========================================================

def read_lines(name):

    path = os.path.join(
        OUT_DIR,
        name,
    )

    if not os.path.exists(
        path
    ):

        raise RuntimeError(
            f"Missing file: {name}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        return [
            line.strip()
            for line in file
            if line.strip()
        ]


# =========================================================
# VERIFY EXACT FILE
# =========================================================

def verify_exact_file(
    name,
    expected,
):

    lines = read_lines(
        name
    )

    if len(lines) != expected:

        raise RuntimeError(
            f"{name}: expected "
            f"{expected}, got "
            f"{len(lines)}"
        )

    for line in lines:

        if not line.endswith(
            f"#{REMARK}"
        ):

            raise RuntimeError(
                f"{name}: invalid remark"
            )

    print(
        f"[OK] {name} = {len(lines)}"
    )


# =========================================================
# VERIFY OPTIONAL FILE
# =========================================================
#
# 0 تا 1000 قابل قبول است.
#
# =========================================================

def verify_optional_file(
    name,
    maximum,
):

    path = os.path.join(
        OUT_DIR,
        name,
    )

    if not os.path.exists(
        path
    ):

        raise RuntimeError(
            f"Missing file: {name}"
        )

    lines = read_lines(
        name
    )

    if len(lines) > maximum:

        raise RuntimeError(
            f"{name}: maximum "
            f"{maximum}, got "
            f"{len(lines)}"
        )

    for line in lines:

        if not line.endswith(
            f"#{REMARK}"
        ):

            raise RuntimeError(
                f"{name}: invalid remark"
            )

    print(
        f"[OK] {name} = {len(lines)}"
    )


# =========================================================
# VERIFY SUBSCRIPTIONS
# =========================================================

def verify_subscriptions():

    all_seen = set()

    for index in range(
        1,
        SUB_COUNT + 1,
    ):

        name = (
            f"sub{index}.txt"
        )

        verify_exact_file(
            name,
            SUB_SIZE,
        )

        for line in read_lines(
            name
        ):

            config = clean_config(
                line
            )

            key = fingerprint(
                config
            )

            if key in all_seen:

                raise RuntimeError(
                    f"Duplicate config "
                    f"between subscriptions: "
                    f"{name}"
                )

            all_seen.add(
                key
            )

    if len(all_seen) != TOTAL_CONFIGS:

        raise RuntimeError(
            "Subscriptions are not "
            "exactly unique."
        )


# =========================================================
# VERIFY PROTOCOLS
# =========================================================

def verify_protocols():

    for name in [
        "vless.txt",
        "vmess.txt",
        "trojan.txt",
        "ss.txt",
    ]:

        verify_optional_file(
            name,
            PROTOCOL_SIZE,
        )


# =========================================================
# VERIFY IRAN
# =========================================================

def verify_iran():

    for name in [
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
    ]:

        verify_optional_file(
            name,
            IRAN_SIZE,
        )


# =========================================================
# VERIFY BOT
# =========================================================

def verify_bot():

    verify_optional_file(
        "bot.txt",
        BOT_SIZE,
    )


# =========================================================
# VERIFY NO HYSTERIA2
# =========================================================

def verify_no_hysteria():

    path = os.path.join(
        OUT_DIR,
        "hysteria2.txt",
    )

    if os.path.exists(
        path
    ):

        raise RuntimeError(
            "hysteria2.txt must not exist."
        )


# =========================================================
# MAIN
# =========================================================

def main():

    started = time.time()

    print(
        "=" * 70
    )

    print(
        "NUKCROW COLLECTOR"
    )

    print(
        "SUBSCRIPTIONS : 10 x 2000"
    )

    print(
        "TOTAL         : 20000"
    )

    print(
        "PROTOCOLS     : up to 1000 each"
    )

    print(
        "IRAN          : up to 1000 each"
    )

    print(
        "HYSTERIA2     : DISABLED"
    )

    print(
        "=" * 70
    )

    # =====================================================
    # REMOVE OLD HYSTERIA2
    # =====================================================

    remove_hysteria2()

    # =====================================================
    # COLLECT
    # =====================================================

    collected = collect_sources()

    collected = unique(
        collected
    )

    print(
        f"[COLLECTED] {len(collected)}"
    )

    if not collected:

        raise RuntimeError(
            "No valid configs collected."
        )

    # =====================================================
    # TEST
    # =====================================================

    alive = benchmark(
        collected
    )

    alive = unique(
        alive
    )

    print(
        f"[ALIVE] {len(alive)}"
    )

    # =====================================================
    # MAIN 20000
    # =====================================================

    if len(alive) < TOTAL_CONFIGS:

        raise RuntimeError(
            "Not enough alive configs "
            "for the 20000 subscription pool. "
            f"Required: {TOTAL_CONFIGS}, "
            f"Available: {len(alive)}"
        )

    mixed = build_mixed_pool(
        alive
    )

    mixed = unique(
        mixed
    )

    if len(mixed) < TOTAL_CONFIGS:

        raise RuntimeError(
            "Unable to create "
            "20000 unique configs."
        )

    all_configs = mixed[
        :TOTAL_CONFIGS
    ]

    # =====================================================
    # SUB 1 - 10
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "SUBSCRIPTIONS"
    )

    print(
        "=" * 70
    )

    for index in range(
        SUB_COUNT
    ):

        start = (
            index
            * SUB_SIZE
        )

        end = (
            start
            + SUB_SIZE
        )

        chunk = all_configs[
            start:end
        ]

        write_file(
            f"sub{index + 1}.txt",
            chunk,
        )

        print(
            f"[WRITE] "
            f"sub{index + 1}.txt = "
            f"{len(chunk)}"
        )

    # =====================================================
    # PROTOCOLS
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "PROTOCOLS"
    )

    print(
        "=" * 70
    )

    write_protocols(
        alive
    )

    # =====================================================
    # IRAN
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "IRAN"
    )

    print(
        "=" * 70
    )

    iran_configs = collect_iran()

    write_iran(
        iran_configs,
        all_configs,
    )

    # =====================================================
    # BOT
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "BOT"
    )

    print(
        "=" * 70
    )

    write_bot()

    # =====================================================
    # ALL CONFIGS
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "ALL CONFIGS"
    )

    print(
        "=" * 70
    )

    write_file(
        "all_configs.txt",
        all_configs,
    )

    # =====================================================
    # VERIFY
    # =====================================================

    print(
        "=" * 70
    )

    print(
        "VERIFY"
    )

    print(
        "=" * 70
    )

    # Subs must be exactly 2000 each
    verify_subscriptions()

    # Protocols can be 0..1000
    verify_protocols()

    # Iran can be 0..1000
    verify_iran()

    # Bot can be 0..1000
    verify_bot()

    # all_configs must be exactly 20000
    verify_exact_file(
        "all_configs.txt",
        TOTAL_CONFIGS,
    )

    # hysteria2 must not exist
    verify_no_hysteria()

    # =====================================================
    # DONE
    # =====================================================

    elapsed = (
        time.time()
        - started
    )

    print(
        "=" * 70
    )

    print(
        "NUKCROW UPDATE COMPLETE"
    )

    print(
        f"Collected : {len(collected)}"
    )

    print(
        f"Alive     : {len(alive)}"
    )

    print(
        f"Subs      : {SUB_COUNT} x {SUB_SIZE}"
    )

    print(
        f"All       : {TOTAL_CONFIGS}"
    )

    print(
        f"Protocols : up to {PROTOCOL_SIZE} each"
    )

    print(
        f"Time      : {elapsed:.1f}s"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":

    main()
