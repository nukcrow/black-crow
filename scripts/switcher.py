import base64
import hashlib
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests


# =========================================================
# CONFIG
# =========================================================

OUT_DIR = "sub/general"
REMARK = "nukcrow"

SOURCE_LIMIT = 50

GENERAL_COUNT = 10000
SUB_SIZE = 1000

IRAN_SIZE = 200
PROTOCOL_SIZE = 100

TIMEOUT = 10
WORKERS = 20

PROTOCOLS = {
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

SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Russia.txt",
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


# =========================================================
# HELPERS
# =========================================================

def decode64(value):
    try:
        value = re.sub(r"\s+", "", value)
        value += "=" * (-len(value) % 4)

        raw = base64.urlsafe_b64decode(value)

        return raw.decode("utf-8", errors="ignore")

    except Exception:
        return ""


def proto(config):
    try:
        scheme = config.split("://", 1)[0].lower()

        if scheme == "hy2":
            return "hysteria2"

        return scheme

    except Exception:
        return ""


def clean(config):
    config = config.strip()

    config = config.replace(
        "\r", ""
    ).replace(
        "\n", ""
    )

    config = config.split("#", 1)[0]

    return config.strip()


def extract(text):
    if not text:
        return []

    pattern = re.compile(
        r"(?i)(?:"
        r"vless|vmess|trojan|ss|hysteria2|hy2"
        r")://[^\s<>'\"`]+"
    )

    found = []

    for x in pattern.findall(text):
        x = clean(x)

        if proto(x) in PROTOCOLS:
            found.append(x)

    # Base64 subscription
    decoded = decode64(text)

    if decoded:
        for x in pattern.findall(decoded):
            x = clean(x)

            if proto(x) in PROTOCOLS:
                found.append(x)

    return found


def fetch(url):
    try:
        r = requests.get(
            url,
            timeout=TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0"
            },
        )

        if r.status_code != 200:
            return []

        configs = extract(r.text)

        # هر مخزن فقط 50 کانفیگ
        return configs[:SOURCE_LIMIT]

    except Exception:
        return []


def valid(config):
    try:
        p = proto(config)

        if p not in PROTOCOLS:
            return False

        if " " in config:
            return False

        u = urlparse(config)

        if p == "vmess":
            data = decode64(
                config.split("://", 1)[1]
            )

            if not data:
                return False

            return True

        if p == "ss":
            return bool(
                config.split("://", 1)[1]
            )

        host = u.hostname

        if not host:
            return False

        try:
            port = u.port
        except ValueError:
            return False

        if not port or not 1 <= port <= 65535:
            return False

        return True

    except Exception:
        return False


def fingerprint(config):
    return hashlib.sha256(
        clean(config).encode()
    ).hexdigest()


# =========================================================
# COLLECT
# =========================================================

def collect(urls):
    result = []
    seen = set()

    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as pool:

        jobs = [
            pool.submit(fetch, url)
            for url in urls
        ]

        for job in as_completed(jobs):

            for config in job.result():

                config = clean(config)

                if not valid(config):
                    continue

                key = fingerprint(config)

                if key in seen:
                    continue

                seen.add(key)
                result.append(config)

    return result


# =========================================================
# WRITE
# =========================================================

def render(configs):
    return "\n".join(
        f"{clean(x)}#{REMARK}"
        for x in configs
    ) + "\n"


def write(name, configs):
    os.makedirs(
        OUT_DIR,
        exist_ok=True
    )

    path = os.path.join(
        OUT_DIR,
        name
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(
            render(configs)
        )


# =========================================================
# SELECT
# =========================================================

def select(pool, count):
    if len(pool) < count:
        raise RuntimeError(
            f"{count} configs required, "
            f"but only {len(pool)} available"
        )

    return pool[:count]


def by_protocol(pool, name):
    return [
        x for x in pool
        if proto(x) == name
    ]


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 60)
    print("NUKCROW COLLECTOR")
    print("=" * 60)

    # -----------------------------------------------------
    # GENERAL REPOSITORIES
    # -----------------------------------------------------

    print(
        f"Collecting {len(SOURCES_GENERAL)} repositories..."
    )

    general = collect(
        SOURCES_GENERAL
    )

    print(
        f"General configs: {len(general)}"
    )

    # -----------------------------------------------------
    # IRAN REPOSITORIES
    # -----------------------------------------------------

    print(
        f"Collecting {len(SOURCES_IRAN)} Iran repositories..."
    )

    iran = collect(
        SOURCES_IRAN
    )

    print(
        f"Iran configs: {len(iran)}"
    )

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    if len(general) < GENERAL_COUNT:
        raise RuntimeError(
            f"Need {GENERAL_COUNT} general configs, "
            f"but only {len(general)} were collected."
        )

    all_configs = select(
        general,
        GENERAL_COUNT
    )

    write(
        "all_configs.txt",
        all_configs
    )

    # -----------------------------------------------------
    # SUB 1 - SUB 10
    # -----------------------------------------------------

    for i in range(10):

        start = i * SUB_SIZE
        end = start + SUB_SIZE

        write(
            f"sub{i + 1}.txt",
            all_configs[start:end]
        )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    iran_pool = (
        iran + general
    )

    iran_unique = []

    seen = set()

    for config in iran_pool:

        key = fingerprint(config)

        if key in seen:
            continue

        seen.add(key)
        iran_unique.append(config)

    if len(iran_unique) < IRAN_SIZE:
        raise RuntimeError(
            "Not enough Iran configs."
        )

    write(
        "best_iran.txt",
        iran_unique[:IRAN_SIZE]
    )

    write(
        "mix_iran.txt",
        iran_unique[:IRAN_SIZE]
    )

    write(
        "mci.txt",
        iran_unique[:IRAN_SIZE]
    )

    write(
        "irancell.txt",
        iran_unique[:IRAN_SIZE]
    )

    write(
        "rightel.txt",
        iran_unique[:IRAN_SIZE]
    )

    # -----------------------------------------------------
    # PROTOCOLS
    # -----------------------------------------------------

    for name in [
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    ]:

        configs = by_protocol(
            general,
            name
        )

        if len(configs) < PROTOCOL_SIZE:

            configs = by_protocol(
                iran_unique,
                name
            )

        if not configs:
            raise RuntimeError(
                f"No available {name} configs"
            )

        write(
            f"{name}.txt",
            configs[:PROTOCOL_SIZE]
        )

    # -----------------------------------------------------
    # RESULT
    # -----------------------------------------------------

    print("=" * 60)
    print("DONE")
    print(f"General: {len(all_configs)}")
    print(f"Iran: {len(iran_unique)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
