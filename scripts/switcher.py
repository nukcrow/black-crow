import os
import ssl
import json
import time
import base64
import socket
import statistics
import hashlib
import random
from urllib.parse import urlparse, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor

import requests


# ============================================================
# OUTPUT TREE
# ============================================================

# Keep the existing output tree because the Telegram bot depends on these paths.
os.makedirs("sub/general", exist_ok=True)
os.makedirs("sub/protocols", exist_ok=True)
os.makedirs("sub/repository", exist_ok=True)


# ============================================================
# SOURCES
# ============================================================

SOURCES = [
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/refs/heads/main/all/vless.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/domain/vless.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/ru/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/jafar.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/MrRabbitson/RabbitProxyz-proxy-list/main/sub.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no2.txt",
    "https://raw.githubusercontent.com/VP01596/vless-top15/main/All.txt",
    "https://raw.githubusercontent.com/3nerg0n/vless-parser/refs/heads/main/sub_vless_3nerg0n_92sh81",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub2.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/10.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/sub.txt",
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/config.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mehrdadmb2/V2ray_Sub/main/Mix.txt",
    "https://raw.githubusercontent.com/mosapase/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/rasool083/v2ray-sub/main/sub.txt",
    "https://raw.githubusercontent.com/amirkma/proxykma/main/mix.txt",
    "https://raw.githubusercontent.com/Areral/ScarletDevil/main/sub_all.txt",
    "https://raw.githubusercontent.com/Arianlavi/RebeldevConfig/main/RebelLink/all_subscriptions.txt",
    "https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/whitelist-vless.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_sub.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
    "https://raw.githubusercontent.com/vpei/free-node-1/main/o/allnode.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vmess",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
]


# ============================================================
# SETTINGS
# ============================================================

REMARK = "nukcrow"

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
}

PROTO_LIST = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
]

PROTOCOL_CAP = 200

# The bot can expose only these five files.
BOT_SUB_COUNT = 5

# The collector creates ten subscription files in total.
# sub1..sub5 go to the bot; sub6..sub10 stay in the repository.
TOTAL_SUB_COUNT = 10
SUB_CONFIG_CAP = 1000


# ============================================================
# FAST BENCHMARK SETTINGS
# ============================================================

# Maximum number of unique configs that will actually be tested.
# This prevents GitHub Actions from spending too much time
# benchmarking an extremely large source pool.
MAX_BENCHMARK_CANDIDATES = 12000

# Only ONE TCP probe per config.
LATENCY_PROBES = 1

# Short connection timeout.
CONNECT_TIMEOUT = 1.5

# Many parallel workers.
RANK_WORKERS = 120


# ============================================================
# BASE64
# ============================================================

def decode_base64_safe(data):
    try:
        data = data.strip()

        # Support standard and URL-safe base64.
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)

        return base64.b64decode(
            data,
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except Exception:
        return ""


def extract_base64_payload(text):
    """
    Decode a subscription if it is base64.
    Otherwise return the original text.
    """

    text = text.strip()

    if "://" in text:
        return text

    decoded = decode_base64_safe(text)

    if "://" in decoded:
        return decoded

    return text


# ============================================================
# FETCH
# ============================================================

def fetch_one(url):
    headers = {
        "User-Agent": "Mozilla/5.0 nukcrow-collector/3.0"
    }

    found = []

    try:
        res = requests.get(
            url,
            headers=headers,
            timeout=8
        )

        if res.status_code != 200:
            return found

        content = extract_base64_payload(res.text)

        valid_prefixes = (
            "vless://",
            "vmess://",
            "trojan://",
            "ss://",
            "hysteria2://",
            "hy2://",
            "tuic://",
        )

        for line in content.splitlines():
            line = line.strip()

            if line.startswith(valid_prefixes):
                found.append(line)

    except Exception:
        pass

    return found


def fetch_all():
    raw_list = []

    with ThreadPoolExecutor(max_workers=25) as executor:
        for result in executor.map(fetch_one, SOURCES):
            raw_list.extend(result)

    return raw_list


# ============================================================
# VMESS
# ============================================================

def vmess_data(config):
    if not config.startswith("vmess://"):
        return None

    try:
        return json.loads(
            decode_base64_safe(config[8:])
        )

    except Exception:
        return None


# ============================================================
# HOST / PORT
# ============================================================

def extract_host_port(config):
    """
    Return endpoint host/port without doing network operations.
    """

    try:
        data = vmess_data(config)

        if data is not None:
            host = str(
                data.get("add", "")
            ).strip()

            port = int(
                data.get("port", 443)
            )

            return host, port

        parsed = urlparse(config)

        host = parsed.hostname

        if not host:
            return None, None

        if parsed.port:
            port = parsed.port

        else:
            qs = parse_qs(
                parsed.query
            )

            security = qs.get(
                "security",
                [""]
            )[0].lower()

            port = (
                443
                if security in {"tls", "reality"}
                else 80
            )

        return host, int(port)

    except Exception:
        return None, None


# Backward-compatible name.
def extract_ip_port(config):
    return extract_host_port(config)


# ============================================================
# PROTOCOL DETECTION
# ============================================================

def detect_proto(config):

    if config.startswith("vless://"):
        return "vless"

    if config.startswith("vmess://"):
        return "vmess"

    if config.startswith("trojan://"):
        return "trojan"

    if config.startswith("ss://"):
        return "ss"

    if (
        config.startswith("hysteria2://")
        or config.startswith("hy2://")
    ):
        return "hysteria2"

    if config.startswith("tuic://"):
        return "tuic"

    return "unknown"


# ============================================================
# FINGERPRINT
# ============================================================

def config_fingerprint(config):
    """
    Dedupe by meaningful transport identity.

    Different SNI/path/transport variants can coexist
    even when they use the same host:port.
    """

    proto = detect_proto(config)

    try:
        data = vmess_data(config)

        if data is not None:

            fields = {
                "proto": "vmess",
                "add": str(
                    data.get("add", "")
                ).lower(),
                "port": str(
                    data.get("port", "")
                ),
                "id": str(
                    data.get("id", "")
                ),
                "net": str(
                    data.get("net", "")
                ).lower(),
                "type": str(
                    data.get("type", "")
                ).lower(),
                "tls": str(
                    data.get("tls", "")
                ).lower(),
                "host": str(
                    data.get("host", "")
                ).lower(),
                "path": str(
                    data.get("path", "")
                ),
                "sni": str(
                    data.get("sni", "")
                ).lower(),
            }

        else:

            parsed = urlparse(config)
            qs = parse_qs(
                parsed.query
            )

            fields = {
                "proto": proto,
                "host": (
                    parsed.hostname or ""
                ).lower(),
                "port": str(
                    parsed.port or ""
                ),
                "security": qs.get(
                    "security",
                    [""]
                )[0].lower(),
                "type": qs.get(
                    "type",
                    [""]
                )[0].lower(),
                "sni": qs.get(
                    "sni",
                    [""]
                )[0].lower(),
                "host_header": qs.get(
                    "host",
                    [""]
                )[0].lower(),
                "path": qs.get(
                    "path",
                    [""]
                )[0],
                "service": qs.get(
                    "serviceName",
                    [""]
                )[0],
            }

        raw = json.dumps(
            fields,
            sort_keys=True,
            ensure_ascii=False
        )

        return hashlib.sha256(
            raw.encode()
        ).hexdigest()

    except Exception:

        return hashlib.sha256(
            config.strip().encode()
        ).hexdigest()


def dedupe_configs(configs):

    seen = set()
    unique = []

    for cfg in configs:

        fp = config_fingerprint(cfg)

        if fp not in seen:

            seen.add(fp)
            unique.append(cfg)

    return unique


# Backward-compatible name.
def dedupe_by_host_port(configs):
    return dedupe_configs(configs)


# ============================================================
# QUERY HELPERS
# ============================================================

def get_query(config):

    try:
        return parse_qs(
            urlparse(config).query
        )

    except Exception:
        return {}


# ============================================================
# PREFERRED CONFIGS
# ============================================================

def is_preferred(config, proto):

    try:

        if proto == "vmess":

            data = vmess_data(config)

            if not data:
                return False

            net = str(
                data.get("net", "")
            ).lower()

            tls = str(
                data.get("tls", "")
            ).lower()

            return (
                tls == "tls"
                and net in {
                    "ws",
                    "grpc",
                    "h2",
                    "httpupgrade",
                }
            )

        if proto == "hysteria2":
            return True

        qs = get_query(config)

        security = qs.get(
            "security",
            [""]
        )[0].lower()

        ctype = qs.get(
            "type",
            [""]
        )[0].lower()

        if security == "reality":
            return True

        if security == "tls":
            return (
                ctype in PREFERRED_TYPES
                or ctype == ""
            )

        return False

    except Exception:
        return False


def is_quality_candidate(config):
    """
    Discard malformed and low-confidence entries before benchmarking.

    A reachable TCP port alone is not enough: the config must also have
    the basic fields required by its protocol and a secure transport.
    """

    try:
        proto = detect_proto(config)

        if proto not in PROTO_LIST:
            return False

        if proto == "vmess":
            data = vmess_data(config)

            if not data:
                return False

            return bool(
                str(data.get("add", "")).strip()
                and str(data.get("id", "")).strip()
                and int(data.get("port", 0)) > 0
            )

        host, port = extract_host_port(config)

        if not host or not port or port < 1 or port > 65535:
            return False

        # VLESS and Trojan entries without TLS/Reality are intentionally
        # ignored; they are usually lower quality or easily broken.
        if proto in {"vless", "trojan"}:
            qs = get_query(config)
            security = qs.get(
                "security",
                [""]
            )[0].lower()
            transport = qs.get(
                "type",
                [""]
            )[0].lower()

            if security not in {"tls", "reality"}:
                return False

            if transport not in {
                "",
                "tcp",
                "ws",
                "grpc",
                "xhttp",
                "httpupgrade",
                "h2",
            }:
                return False

        return True

    except Exception:
        return False


# ============================================================
# FAST TCP BENCHMARK
# ============================================================

def check_endpoint(
    config,
    timeout=CONNECT_TIMEOUT
):
    """
    Measure TCP connection latency only.

    IMPORTANT:
    No TLS handshake is performed here.
    This makes the benchmark much faster.
    """

    host, port = extract_host_port(config)

    if not host or not port:
        return None

    start = time.perf_counter()

    sock = None

    try:

        sock = socket.create_connection(
            (host, port),
            timeout=timeout
        )

        tcp_ms = (
            time.perf_counter() - start
        ) * 1000.0

        return {
            "tcp_ms": tcp_ms
        }

    except Exception:
        return None

    finally:

        if sock is not None:

            try:
                sock.close()

            except Exception:
                pass


def benchmark_config(config):

    result = check_endpoint(config)

    if not result:
        return None

    tcp_ms = result["tcp_ms"]

    return {
        "config": config,
        "tcp_median": tcp_ms,
        "tcp_min": tcp_ms,
        "jitter": 0.0,
        "success_rate": 1.0,
        "quality_score": tcp_ms,
    }


def rank_configs(configs):

    ranked = []

    if not configs:
        return ranked

    # Don't benchmark an unnecessarily huge pool.
    candidates = list(configs)

    if len(candidates) > MAX_BENCHMARK_CANDIDATES:

        # Randomize candidate selection so source ordering
        # does not permanently decide which configs get tested.
        random.shuffle(candidates)

        candidates = candidates[
            :MAX_BENCHMARK_CANDIDATES
        ]

    print(
        f"Benchmark candidates: {len(candidates)}"
    )

    with ThreadPoolExecutor(
        max_workers=RANK_WORKERS
    ) as executor:

        for result in executor.map(
            benchmark_config,
            candidates
        ):

            if result:
                ranked.append(result)

    ranked.sort(
        key=lambda x: (
            x["quality_score"],
            x["tcp_median"],
        )
    )

    return ranked


# ============================================================
# ALIVE FILTER
# ============================================================

def filter_alive(raw_configs):

    alive = []

    with ThreadPoolExecutor(
        max_workers=RANK_WORKERS
    ) as executor:

        for result in executor.map(
            benchmark_config,
            raw_configs
        ):

            if result:
                alive.append(
                    result["config"]
                )

    return alive


# ============================================================
# REMARK
# ============================================================

def rename_config(config, proto):
    """
    Remove country flags completely.

    Every output config gets only:
        nukcrow
    """

    label = REMARK

    try:

        # VMess uses the "ps" field.
        if proto == "vmess":

            data = vmess_data(config)

            if not data:
                return None

            data["ps"] = label

            encoded = base64.b64encode(
                json.dumps(
                    data,
                    ensure_ascii=False,
                    separators=(",", ":")
                ).encode("utf-8")
            ).decode("ascii")

            return "vmess://" + encoded

        # Other protocols use URL fragment.
        base_part = config.split(
            "#",
            1
        )[0]

        return (
            f"{base_part}#{quote(label)}"
        )

    except Exception:
        return None


# ============================================================
# FILE WRITER
# ============================================================

def write_lines(path, lines):
    """
    Atomic-ish write:
    write temporary file first, then replace target.
    """

    directory = os.path.dirname(path)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    tmp = path + ".tmp"

    with open(
        tmp,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(lines)
        )

        if lines:
            f.write("\n")

    os.replace(
        tmp,
        path
    )


# ============================================================
# GENERAL OUTPUTS
# ============================================================

def write_general_outputs(all_formatted):
    for i in range(TOTAL_SUB_COUNT):
        start = i * SUB_CONFIG_CAP
        end = start + SUB_CONFIG_CAP
        chunk = all_formatted[start:end]
        sub_number = i + 1

        if sub_number <= BOT_SUB_COUNT:
            path = f"sub/general/sub{sub_number}.txt"
        else:
            path = f"sub/repository/sub{sub_number}.txt"

        write_lines(path, chunk)

    # These old paths must not remain, otherwise an old sixth-to-tenth
    # subscription can accidentally be exposed by a future bot menu change.
    for sub_number in range(
        BOT_SUB_COUNT + 1,
        TOTAL_SUB_COUNT + 1
    ):
        old_path = f"sub/general/sub{sub_number}.txt"

        if os.path.exists(old_path):
            os.remove(old_path)

    print(
        f"Bot subs: {BOT_SUB_COUNT} x up to "
        f"{SUB_CONFIG_CAP} configs | "
        f"Repository-only subs: "
        f"{TOTAL_SUB_COUNT - BOT_SUB_COUNT} x up to "
        f"{SUB_CONFIG_CAP} configs"
    )


# ============================================================
# PROTOCOL OUTPUTS
# ============================================================

def write_protocol_outputs(
    proto_buckets
):

    for proto in PROTO_LIST:

        combined = (
            proto_buckets[proto]["preferred"]
            + proto_buckets[proto]["fallback"]
        )

        write_lines(
            f"sub/protocols/{proto}.txt",
            combined[:PROTOCOL_CAP]
        )


# ============================================================
# MAIN
# ============================================================

def main():

    started = time.time()

    # --------------------------------------------------------
    # FETCH
    # --------------------------------------------------------

    print(
        f"Fetching from {len(SOURCES)} sources..."
    )

    raw = fetch_all()

    print(
        f"Fetched (raw): {len(raw)}"
    )

    # --------------------------------------------------------
    # DEDUPE
    # --------------------------------------------------------

    raw = dedupe_configs(raw)

    print(
        f"After transport-aware dedupe: "
        f"{len(raw)}"
    )

    raw = [
        cfg
        for cfg in raw
        if is_quality_candidate(cfg)
    ]

    print(
        f"After quality filter: "
        f"{len(raw)}"
    )

    # --------------------------------------------------------
    # BENCHMARK
    # --------------------------------------------------------

    print(
        "Benchmarking endpoints "
        "(1 TCP probe, no TLS handshake)..."
    )

    ranked = rank_configs(raw)

    print(
        f"Reachable/benchmarked: "
        f"{len(ranked)}"
    )

    # --------------------------------------------------------
    # BUCKETS
    # --------------------------------------------------------

    preferred_all = []
    fallback_all = []

    proto_buckets = {
        p: {
            "preferred": [],
            "fallback": [],
        }
        for p in PROTO_LIST
    }

    formatted_by_fp = {}

    # --------------------------------------------------------
    # FORMAT
    # --------------------------------------------------------

    for record in ranked:

        cfg = record["config"]

        proto = detect_proto(cfg)

        if (
            proto == "unknown"
            or proto not in proto_buckets
        ):
            continue

        # Country lookup is intentionally removed.
        # Every config gets only "nukcrow".
        renamed = rename_config(
            cfg,
            proto
        )

        if not renamed:
            continue

        fp = config_fingerprint(
            cfg
        )

        formatted_by_fp[fp] = renamed

        if is_preferred(
            cfg,
            proto
        ):

            preferred_all.append(
                renamed
            )

            proto_buckets[
                proto
            ]["preferred"].append(
                renamed
            )

        else:

            fallback_all.append(
                renamed
            )

            proto_buckets[
                proto
            ]["fallback"].append(
                renamed
            )

    # --------------------------------------------------------
    # GENERAL OUTPUT
    # --------------------------------------------------------

    all_formatted = (
        preferred_all
        + fallback_all
    )

    write_general_outputs(
        all_formatted
    )

    # --------------------------------------------------------
    # PROTOCOL OUTPUT
    # --------------------------------------------------------

    write_protocol_outputs(
        proto_buckets
    )

    # --------------------------------------------------------
    # CLEAN OLD BEST DIRECTORY
    # --------------------------------------------------------

    # Best outputs are no longer used.
    # Remove old files if they exist from previous runs.
    best_dir = "sub/best"

    if os.path.isdir(best_dir):

        for filename in os.listdir(
            best_dir
        ):

            path = os.path.join(
                best_dir,
                filename
            )

            if os.path.isfile(path):

                try:
                    os.remove(path)

                except Exception:
                    pass

        try:
            os.rmdir(best_dir)

        except Exception:
            pass

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    print(
        f"Done. "
        f"Preferred: {len(preferred_all)} | "
        f"Fallback: {len(fallback_all)} | "
        f"Total: {len(all_formatted)} | "
        f"Elapsed: "
        f"{time.time() - started:.1f}s"
    )


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":
    main()
