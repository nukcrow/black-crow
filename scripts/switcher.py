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

TOTAL_CONFIGS = 10000
SUB_COUNT = 5
SUB_SIZE = 2000

PROTOCOL_SIZE = 100
IRAN_SIZE = 200

FETCH_TIMEOUT = 15
TEST_TIMEOUT = 2.0

FETCH_WORKERS = 30
TEST_WORKERS = 150

# Maximum configs taken from each source.
# Large verified sources are allowed to contribute more.
SOURCE_LIMIT = 5000

SUPPORTED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
}


# =========================================================
# SOURCES
# =========================================================

# High-quality / heavily tested public aggregators.
# 0xRadikal publishes a verified tier based on real HTTP
# requests performed in multiple rounds.
#
# morpheusadam publishes measured bundles and an Iran bundle.

SOURCES_PRIORITY = [

    # -----------------------------------------------------
    # 0xRadikal
    # -----------------------------------------------------

    (
        "https://raw.githubusercontent.com/"
        "0xRadikal/Free-v2ray-Configs/main/"
        "verified/configs.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "0xRadikal/Free-v2ray-Configs/main/"
        "fast/configs.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "0xRadikal/Free-v2ray-Configs/main/"
        "all/configs.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "0xRadikal/Free-v2ray-Configs/main/"
        "heavy/configs.txt"
    ),

    # -----------------------------------------------------
    # morpheusadam
    # -----------------------------------------------------

    (
        "https://raw.githubusercontent.com/"
        "morpheusadam/v2ray-config/main/"
        "subs/bundles/best.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "morpheusadam/v2ray-config/main/"
        "subs/bundles/iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "morpheusadam/v2ray-config/main/"
        "subs/bundles/lite.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "morpheusadam/v2ray-config/main/"
        "subs/bundles/all.txt"
    ),

    # -----------------------------------------------------
    # Iranian collectors
    # -----------------------------------------------------

    (
        "https://raw.githubusercontent.com/"
        "HosseinKoofi/GO_V2rayCollector/main/"
        "mixed_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "HosseinKoofi/GO_V2rayCollector/main/"
        "vless_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "HosseinKoofi/GO_V2rayCollector/main/"
        "vmess_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "HosseinKoofi/GO_V2rayCollector/main/"
        "trojan_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "HosseinKoofi/GO_V2rayCollector/main/"
        "ss_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "youfoundamin/V2rayCollector/main/"
        "vless_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "youfoundamin/V2rayCollector/main/"
        "ss_iran.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "iboxz/free-v2ray-collector/main/"
        "main/mix"
    ),

    # -----------------------------------------------------
    # General public sources
    # -----------------------------------------------------

    (
        "https://raw.githubusercontent.com/"
        "Epodonios/v2ray-configs/main/"
        "All_Configs_Sub.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "barry-far/V2ray-Config/main/"
        "All_Configs_Sub.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "SoliSpirit/v2ray-configs/main/"
        "all_configs.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "mahdibland/ShadowsocksAggregator/master/"
        "sub/sub_merge.txt"
    ),

    (
        "https://raw.githubusercontent.com/"
        "awesome-vpn/awesome-vpn/master/"
        "all"
    ),
]


# =========================================================
# HTTP SESSION
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
        scheme = (
            config
            .split("://", 1)[0]
            .strip()
            .lower()
        )

        if scheme == "hy2":
            return "hysteria2"

        return scheme

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

    # Remove existing remark.
    if "#" in config:
        config = config.split(
            "#",
            1,
        )[0]

    return config.strip()


# =========================================================
# URI EXTRACTION
# =========================================================

URI_PATTERN = re.compile(
    r"(?i)"
    r"(?:"
    r"vless|"
    r"vmess|"
    r"trojan|"
    r"ss|"
    r"hysteria2|"
    r"hy2"
    r")://"
    r"[^\s<>'\"`]+"
)


def extract_uris(text):
    if not text:
        return []

    found = []

    def extract_from(value):
        if not value:
            return

        for item in URI_PATTERN.findall(
            value
        ):
            item = clean_config(
                item.rstrip(
                    ".,;)]}>\"'`"
                )
            )

            if not item:
                continue

            if protocol(item) in SUPPORTED_PROTOCOLS:
                found.append(item)

    # Plain text.
    extract_from(text)

    # Base64.
    decoded = decode64(text)

    if decoded:
        extract_from(decoded)

        # Some sources are encoded twice.
        decoded2 = decode64(decoded)

        if decoded2:
            extract_from(decoded2)

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
# SS
# =========================================================

def parse_ss(config):
    try:
        value = config.split(
            "://",
            1,
        )[1]

        value = value.split(
            "#",
            1,
        )[0]

        # ss://BASE64
        if "@" not in value:

            decoded = decode64(
                value
            )

            if not decoded:
                return None

            value = decoded

        if "@" not in value:
            return None

        userinfo, address = value.rsplit(
            "@",
            1,
        )

        if ":" not in address:
            return None

        host, port_text = address.rsplit(
            ":",
            1,
        )

        host = host.strip(
            "[] "
        )

        port = int(
            port_text
        )

        if not host:
            return None

        if not 1 <= port <= 65535:
            return None

        if ":" not in userinfo:
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

        if host in {
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
# FETCH SOURCE
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

        result = []
        seen = set()

        for config in configs:

            config = clean_config(
                config
            )

            if not valid_config(
                config
            ):
                continue

            key = fingerprint(
                config
            )

            if key in seen:
                continue

            seen.add(key)

            result.append(
                config
            )

            if len(result) >= SOURCE_LIMIT:
                break

        print(
            f"[SOURCE] "
            f"{len(result):5d} "
            f"{url}"
        )

        return result

    except Exception as exc:
        print(
            f"[FAILED] "
            f"{url} -> {exc}"
        )

        return []

    finally:
        session.close()


# =========================================================
# COLLECT
# =========================================================

def collect_sources():
    all_configs = []

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                fetch_source,
                url,
            ): url
            for url in SOURCES_PRIORITY
        }

        for job in as_completed(
            jobs
        ):

            try:
                configs = job.result()

                all_configs.extend(
                    configs
                )

            except Exception:
                pass

    # Global dedupe.
    result = []
    seen = set()

    for config in all_configs:

        key = fingerprint(
            config
        )

        if key in seen:
            continue

        seen.add(key)

        result.append(
            config
        )

    return result


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


def benchmark(configs):
    alive = []

    print(
        f"Testing {len(configs)} configs..."
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

    alive.sort(
        key=lambda x: fingerprint(x)
    )

    return alive


# =========================================================
# DEDUPE
# =========================================================

def unique(configs):
    result = []
    seen = set()

    for config in configs:

        key = fingerprint(
            config
        )

        if key in seen:
            continue

        seen.add(key)

        result.append(
            config
        )

    return result


# =========================================================
# PRIORITY ORDER
# =========================================================

def prioritize(configs):
    """
    Put preferred protocols and configs first.
    No protocol is removed.
    """

    def score(config):
        p = protocol(
            config
        )

        value = 0

        if p == "vless":
            value += 5

        elif p == "trojan":
            value += 4

        elif p == "vmess":
            value += 3

        elif p == "hysteria2":
            value += 3

        elif p == "ss":
            value += 2

        return -value

    return sorted(
        configs,
        key=score,
    )


# =========================================================
# SELECT
# =========================================================

def select_exact(
    configs,
    count,
    name,
):
    configs = unique(
        configs
    )

    if len(configs) < count:
        raise RuntimeError(
            f"{name}: need "
            f"{count}, got "
            f"{len(configs)}"
        )

    return configs[:count]


# =========================================================
# RENDER
# =========================================================

def render(configs):
    lines = []

    for config in configs:

        config = clean_config(
            config
        )

        lines.append(
            f"{config}#{REMARK}"
        )

    return (
        "\n".join(lines)
        + "\n"
    )


# =========================================================
# ATOMIC WRITE
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
            render(configs)
        )

    os.replace(
        temp,
        path,
    )


# =========================================================
# PROTOCOL FILES
# =========================================================

def write_protocols(
    configs
):
    protocols = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
        "hysteria2": [],
    }

    for config in configs:

        p = protocol(
            config
        )

        if p in protocols:
            protocols[p].append(
                config
            )

    for name, pool in protocols.items():

        if not pool:
            print(
                f"[SKIP] {name}: no configs"
            )
            continue

        selected = pool[
            :PROTOCOL_SIZE
        ]

        write_file(
            f"{name}.txt",
            selected,
        )

        print(
            f"[WRITE] "
            f"{name}.txt -> "
            f"{len(selected)}"
        )


# =========================================================
# IRAN FILES
# =========================================================

def write_iran(
    iran_pool,
    all_pool,
):
    iran_pool = unique(
        iran_pool
    )

    all_pool = unique(
        all_pool
    )

    # Use Iran pool first,
    # then global verified/alive pool.
    combined = unique(
        iran_pool
        + all_pool
    )

    if not combined:
        return

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
            f"{name} -> "
            f"{len(selected)}"
        )


# =========================================================
# VERIFY OUTPUT
# =========================================================

def verify_file(
    name,
    expected,
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

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:

        lines = [
            x.strip()
            for x in file
            if x.strip()
        ]

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

    return len(lines)


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
        "5 subscriptions x 2000"
    )

    print(
        "=" * 70
    )

    # -----------------------------------------------------
    # COLLECT
    # -----------------------------------------------------

    collected = collect_sources()

    collected = unique(
        collected
    )

    print(
        f"Collected unique: "
        f"{len(collected)}"
    )

    if not collected:
        raise RuntimeError(
            "No valid configs collected."
        )

    # -----------------------------------------------------
    # TEST
    # -----------------------------------------------------

    alive = benchmark(
        collected
    )

    alive = unique(
        alive
    )

    print(
        f"TCP alive: "
        f"{len(alive)}"
    )

    if len(alive) < TOTAL_CONFIGS:
        raise RuntimeError(
            "Not enough alive configs. "
            f"Required {TOTAL_CONFIGS}, "
            f"got {len(alive)}."
        )

    # -----------------------------------------------------
    # PRIORITIZE
    # -----------------------------------------------------

    alive = prioritize(
        alive
    )

    # -----------------------------------------------------
    # GENERAL 10000
    # -----------------------------------------------------

    all_configs = select_exact(
        alive,
        TOTAL_CONFIGS,
        "all_configs.txt",
    )

    write_file(
        "all_configs.txt",
        all_configs,
    )

    # -----------------------------------------------------
    # SUB 1-5
    # -----------------------------------------------------

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

        if len(chunk) != SUB_SIZE:
            raise RuntimeError(
                f"sub{index + 1}.txt "
                f"does not contain "
                f"{SUB_SIZE} configs."
            )

        write_file(
            f"sub{index + 1}.txt",
            chunk,
        )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    iran_configs = []

    for config in alive:

        # Prefer endpoints that are commonly
        # found in Iran-oriented pools.
        #
        # The actual network location is NOT inferred here.
        # We simply preserve configs originating from
        # Iran-oriented sources separately below.
        pass

    # Re-fetch Iran-oriented sources separately.
    iran_urls = [
        x
        for x in SOURCES_PRIORITY
        if any(
            key in x
            for key in [
                "iran",
                "GO_V2rayCollector",
                "V2rayCollector",
                "iboxz",
            ]
        )
    ]

    with ThreadPoolExecutor(
        max_workers=10
    ) as executor:

        jobs = [
            executor.submit(
                fetch_source,
                url,
            )
            for url in iran_urls
        ]

        for job in as_completed(
            jobs
        ):

            try:
                iran_configs.extend(
                    job.result()
                )
            except Exception:
                pass

    iran_configs = unique(
        iran_configs
    )

    iran_alive = benchmark(
        iran_configs
    )

    iran_alive = unique(
        iran_alive
    )

    # -----------------------------------------------------
    # IRAN OUTPUTS
    # -----------------------------------------------------

    if iran_alive:
        write_iran(
            iran_alive,
            all_configs,
        )

    # -----------------------------------------------------
    # PROTOCOL OUTPUTS
    # -----------------------------------------------------

    write_protocols(
        all_configs
    )

    # -----------------------------------------------------
    # VERIFY GENERAL
    # -----------------------------------------------------

    verify_file(
        "all_configs.txt",
        TOTAL_CONFIGS,
    )

    for index in range(
        SUB_COUNT
    ):
        verify_file(
            f"sub{index + 1}.txt",
            SUB_SIZE,
        )

    # -----------------------------------------------------
    # VERIFY REMARK
    # -----------------------------------------------------

    for name in [
        "all_configs.txt",
        "sub1.txt",
        "sub2.txt",
        "sub3.txt",
        "sub4.txt",
        "sub5.txt",
    ]:

        verify_file(
            name,
            TOTAL_CONFIGS
            if name == "all_configs.txt"
            else SUB_SIZE,
        )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    elapsed = (
        time.time()
        - started
    )

    print(
        "=" * 70
    )

    print(
        "DONE"
    )

    print(
        f"Collected : {len(collected)}"
    )

    print(
        f"Alive     : {len(alive)}"
    )

    print(
        f"General   : {TOTAL_CONFIGS}"
    )

    print(
        f"Subs      : {SUB_COUNT} x {SUB_SIZE}"
    )

    print(
        f"Time      : {elapsed:.1f}s"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":
    main()
