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

PER_SOURCE = 50
SUB_SIZE = 1000
IRAN_SIZE = 200
PROTOCOL_SIZE = 100

FETCH_TIMEOUT = 12
TEST_TIMEOUT = 2.0
FETCH_WORKERS = 20
TEST_WORKERS = 100

SUPPORTED = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
}


# =========================================================
# 40 SOURCES
# =========================================================

SOURCES = [
    # General
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",

    # Iranian collectors
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",

    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",

    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/vmess_iran.txt",

    "https://raw.githubusercontent.com/sakha1370/V2rayCollector/main/mixed_iran.txt",

    # Large maintained aggregators
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vless.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vmess.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/trojan.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/shadowsocks.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/hysteria2.txt",

    # Delta-Kronecker
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/vless.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/vmess.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/trojan.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/protocols/ss.txt",

    # Other collectors
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
    "https://raw.githubusercontent.com/NakuTenshi/v2ray_config_collector/main/configs/configs.txt",
]


# =========================================================
# BASE64
# =========================================================

def decode64(value):
    try:
        value = re.sub(r"\s+", "", value)

        if not value:
            return ""

        value += "=" * (-len(value) % 4)

        return base64.urlsafe_b64decode(
            value
        ).decode(
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
        p = config.split(
            "://",
            1,
        )[0].lower()

        if p == "hy2":
            return "hysteria2"

        return p

    except Exception:
        return ""


# =========================================================
# CLEAN
# =========================================================

def clean(config):
    config = config.strip()

    config = config.replace(
        "\r",
        "",
    ).replace(
        "\n",
        "",
    )

    config = config.split(
        "#",
        1,
    )[0]

    return config.strip()


# =========================================================
# EXTRACT
# =========================================================

def extract(text):
    if not text:
        return []

    pattern = re.compile(
        r"(?i)(?:"
        r"vless|vmess|trojan|ss|hysteria2|hy2"
        r")://[^\s<>'\"`]+"
    )

    found = []

    def add(source):
        for item in pattern.findall(source):
            item = clean(item)

            if protocol(item) in SUPPORTED:
                found.append(item)

    add(text)

    decoded = decode64(text)

    if decoded:
        add(decoded)

        decoded2 = decode64(decoded)

        if decoded2:
            add(decoded2)

    return found


# =========================================================
# VALIDATE
# =========================================================

def valid(config):
    try:
        p = protocol(config)

        if p not in SUPPORTED:
            return False

        if any(
            c.isspace()
            for c in config
        ):
            return False

        if p == "vmess":
            payload = config.split(
                "://",
                1,
            )[1]

            return bool(
                decode64(payload)
            )

        if p == "ss":
            return bool(
                config.split(
                    "://",
                    1,
                )[1]
            )

        parsed = urlparse(config)

        host = parsed.hostname

        if not host:
            return False

        try:
            port = parsed.port
        except ValueError:
            return False

        if not port:
            return False

        if port < 1 or port > 65535:
            return False

        return True

    except Exception:
        return False


# =========================================================
# ID
# =========================================================

def identity(config):
    return hashlib.sha256(
        clean(config).encode(
            "utf-8",
            errors="ignore",
        )
    ).hexdigest()


# =========================================================
# FETCH ONE SOURCE
# =========================================================

def fetch_source(url):
    try:
        response = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            headers={
                "User-Agent":
                    "Mozilla/5.0",
            },
        )

        if response.status_code != 200:
            return []

        configs = extract(
            response.text
        )

        result = []
        seen = set()

        for config in configs:

            config = clean(config)

            if not valid(config):
                continue

            key = identity(config)

            if key in seen:
                continue

            seen.add(key)

            result.append(config)

            if len(result) >= PER_SOURCE:
                break

        print(
            f"[OK] {url} -> {len(result)}"
        )

        return result

    except Exception as e:
        print(
            f"[FAIL] {url} -> {e}"
        )

        return []


# =========================================================
# FETCH ALL
# =========================================================

def fetch_all():
    configs = []

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                fetch_source,
                url,
            ): url
            for url in SOURCES
        }

        for job in as_completed(jobs):

            try:
                configs.extend(
                    job.result()
                )

            except Exception:
                pass

    # Global dedupe
    result = []
    seen = set()

    for config in configs:

        key = identity(config)

        if key in seen:
            continue

        seen.add(key)

        result.append(config)

    return result


# =========================================================
# TCP TEST
# =========================================================

def endpoint(config):
    try:
        p = protocol(config)

        if p == "vmess":
            decoded = decode64(
                config.split(
                    "://",
                    1,
                )[1]
            )

            if not decoded:
                return None

            import json

            data = json.loads(
                decoded
            )

            host = (
                data.get("add")
                or data.get("host")
            )

            port = int(
                data.get("port", 0)
            )

            if host and port:
                return host, port

            return None

        parsed = urlparse(
            config
        )

        host = parsed.hostname

        try:
            port = parsed.port
        except ValueError:
            return None

        if host and port:
            return host, port

    except Exception:
        return None

    return None


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


def test_configs(configs):
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

        for job in as_completed(jobs):

            config = jobs[job]

            try:
                if job.result():
                    alive.append(
                        config
                    )
            except Exception:
                pass

    print(
        f"Alive: {len(alive)}"
    )

    return alive


# =========================================================
# WRITE
# =========================================================

def render(configs):
    return "\n".join(
        f"{clean(config)}#nukcrow"
        for config in configs
    ) + "\n"


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

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(
            render(configs)
        )


# =========================================================
# UNIQUE
# =========================================================

def unique(configs):
    result = []
    seen = set()

    for config in configs:

        key = identity(
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
# MAIN
# =========================================================

def main():

    print(
        "=" * 60
    )

    print(
        "NUKCROW COLLECTOR"
    )

    print(
        f"Sources: {len(SOURCES)}"
    )

    print(
        f"Per source: {PER_SOURCE}"
    )

    print(
        "=" * 60
    )

    # -----------------------------------------------------
    # FETCH
    # -----------------------------------------------------

    configs = fetch_all()

    configs = unique(
        configs
    )

    print(
        f"Collected: {len(configs)}"
    )

    if not configs:
        raise RuntimeError(
            "No configs collected."
        )

    # -----------------------------------------------------
    # TEST
    # -----------------------------------------------------

    alive = test_configs(
        configs
    )

    if not alive:
        raise RuntimeError(
            "No alive configs found."
        )

    alive = unique(
        alive
    )

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    all_configs = alive

    write_file(
        "all_configs.txt",
        all_configs,
    )

    # -----------------------------------------------------
    # SUB 1 - SUB 10
    # -----------------------------------------------------

    for i in range(10):

        start = i * SUB_SIZE
        end = start + SUB_SIZE

        chunk = all_configs[
            start:end
        ]

        if not chunk:
            break

        write_file(
            f"sub{i + 1}.txt",
            chunk,
        )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    iran_sources = [
        x
        for x in alive
        if x in configs
    ]

    iran = iran_sources[:IRAN_SIZE]

    if iran:

        write_file(
            "best_iran.txt",
            iran,
        )

        write_file(
            "mix_iran.txt",
            iran,
        )

        write_file(
            "mci.txt",
            iran,
        )

        write_file(
            "irancell.txt",
            iran,
        )

        write_file(
            "rightel.txt",
            iran,
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

        pool = [
            x
            for x in alive
            if protocol(x) == name
        ]

        if pool:

            write_file(
                f"{name}.txt",
                pool[
                    :PROTOCOL_SIZE
                ],
            )

            print(
                f"{name}: {len(pool)}"
            )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print(
        "=" * 60
    )

    print(
        f"Collected : {len(configs)}"
    )

    print(
        f"Alive     : {len(alive)}"
    )

    print(
        f"Output    : {OUT_DIR}"
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":
    main()
