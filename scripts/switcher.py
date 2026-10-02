import os
import re
import json
import time
import base64
import socket
import ssl
import queue
import shutil
import tempfile
import subprocess
import random
import ipaddress
import threading
import functools

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

UDP_PROTOCOLS = {"hysteria2", "hy2"}

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

# Stage 1
MAX_TEST = 30000
BENCH_WORKERS = 100
BENCH_TIMEOUT = 2.0
TLS_TIMEOUT = 2.5

SECOND_PASS = 15000
SECOND_PASS_WORKERS = 80
SECOND_PASS_TIMEOUT = 2.0

# Minimum amount of verified configs required before replacing outputs.
MIN_GOOD = GENERAL_TOTAL

# Real xray end-to-end test
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")

REAL_TEST_MAX = 30000
REAL_BATCH_SIZE = 40
REAL_BATCH_PARALLEL = 4
REAL_BASE_PORT = 20000
REAL_TIMEOUT = 5.0

TEST_HOST = "www.gstatic.com"
TEST_PORT = 80
TEST_PATH = "/generate_204"

# Persistent known-good pool
STATE_FILE = os.environ.get("STATE_FILE", ".state/good_pool.json")
STATE_RETEST = 5000
STATE_MAX = 20000
STATE_MAX_FAILS = 3

PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade",
    "tcp",
}

CF_BONUS = 8
MULTI_SOURCE_BONUS = 3


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
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Russia.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
]

SOURCES_IRAN = [
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
]

SOURCES_MCI = []

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
]

SOURCES_RIGHTEL = []


# ============================================================
# GLOBAL STATE
# ============================================================

_thread_local = threading.local()

SOURCE_META = {}
SOURCE_META_LOCK = threading.Lock()

_DNS_CACHE = {}
_DNS_LOCK = threading.Lock()


def _make_tls_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


TLS_CTX = _make_tls_ctx()


# ============================================================
# HTTP
# ============================================================

def session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
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

    try:
        value = value.strip()
        value = value.replace("-", "+").replace("_", "/")
        value += "=" * (-len(value) % 4)

        return base64.b64decode(
            value,
            validate=False,
        ).decode("utf-8", errors="ignore")

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

    try:
        config = config.strip()
        config = unquote(config)

        config = (
            config
            .replace("\\\n", "")
            .replace("\n", "")
            .replace("\r", "")
        )

        if "#" in config:
            config = config.split("#", 1)[0]

        config = config.strip().strip("'\"`")

        return config.strip()

    except Exception:
        return ""


def _collect(text, found):
    if not text:
        return

    for match in URI_PATTERN.findall(text):
        config = normalize_config(match)

        if config:
            found.append(config)


def extract_uris(text):
    if not text:
        return []

    found = []

    try:
        _collect(text, found)

        decoded = decode64(text.strip())

        if decoded:
            _collect(decoded, found)

        for line in text.splitlines():
            line = line.strip()

            if not line:
                continue

            decoded_line = decode64(line)

            if decoded_line:
                _collect(decoded_line, found)

    except Exception:
        pass

    return found


# ============================================================
# SOURCE TRACKING
# ============================================================

def config_key(config):
    return config.strip()


def register_source(config, source):
    with SOURCE_META_LOCK:
        SOURCE_META.setdefault(
            config_key(config),
            set(),
        ).add(source)


def source_names(config):
    with SOURCE_META_LOCK:
        return sorted(
            SOURCE_META.get(
                config_key(config),
                set(),
            )
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

            configs = extract_uris(response.text)

            configs = configs[:MAX_PER_SOURCE]

            for config in configs:
                register_source(config, url)

            return configs

        except Exception as exc:
            last_error = exc

            if attempt < FETCH_RETRIES:
                time.sleep(min(2 ** attempt, 5))

    print(f"[FETCH ERROR] {url}: {last_error}")

    return []


def fetch_group(sources, name):
    results = []

    if not sources:
        return results

    print(f"\nFetching {name}: {len(sources)} sources")

    with ThreadPoolExecutor(
        max_workers=FETCH_WORKERS
    ) as executor:

        futures = {
            executor.submit(fetch_source, source): source
            for source in sources
        }

        for future in as_completed(futures):
            source = futures[future]

            try:
                configs = future.result()

                results.extend(configs)

                print(
                    f"[OK] {len(configs):5d} {source}"
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
# PROTOCOL / PARSING
# ============================================================

def proto(config):
    try:
        return config.split("://", 1)[0].lower()
    except Exception:
        return ""


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
    try:
        value = data.get(key)

        if not value:
            return default

        if isinstance(value, list):
            return value[0]

        return value

    except Exception:
        return default


def vmess_data(config):
    try:
        if not config.lower().startswith("vmess://"):
            return {}

        payload = config.split("://", 1)[1]

        decoded = decode64(payload)

        if not decoded:
            return {}

        data = json.loads(decoded)

        if isinstance(data, dict):
            return data

    except Exception:
        pass

    return {}


# ============================================================
# SHADOWSOCKS PARSER
# ============================================================

def _parse_host_port(value):
    if not value:
        return "", 0

    value = value.strip()

    try:
        if value.startswith("["):
            closing = value.find("]")

            if closing == -1:
                return "", 0

            host = value[1:closing]

            rest = value[closing + 1:]

            if not rest.startswith(":"):
                return "", 0

            port_text = rest[1:]

        else:
            if ":" not in value:
                return "", 0

            host, port_text = value.rsplit(":", 1)

        host = host.strip()

        port = int(port_text.strip())

        if not host:
            return "", 0

        if not (1 <= port <= 65535):
            return "", 0

        return host, port

    except Exception:
        return "", 0


def _parse_ss_method_password(value):
    if not value:
        return "", ""

    value = unquote(value.strip())

    if ":" not in value:
        decoded = decode64(value)

        if decoded and ":" in decoded:
            value = decoded

    if ":" not in value:
        return "", ""

    method, password = value.split(":", 1)

    method = unquote(method.strip())
    password = unquote(password.strip())

    if not method or not password:
        return "", ""

    return method, password


def ss_data(config):
    try:
        if not config.lower().startswith("ss://"):
            return None

        payload = config.split("://", 1)[1]

        payload = payload.split("#", 1)[0]
        payload = payload.strip()

        if not payload:
            return None

        # SIP002:
        # ss://BASE64(method:password)@host:port
        if "@" in payload:
            user_part, endpoint_part = payload.rsplit("@", 1)

            endpoint_part = unquote(endpoint_part)

            host, port = _parse_host_port(endpoint_part)

            if not host or not port:
                return None

            method, password = _parse_ss_method_password(
                user_part
            )

            if not method or not password:
                return None

            return {
                "method": method,
                "password": password,
                "host": host,
                "port": port,
            }

        # Legacy:
        # ss://BASE64(method:password@host:port)
        decoded = decode64(payload)

        if not decoded or "@" not in decoded:
            return None

        user_part, endpoint_part = decoded.rsplit("@", 1)

        method, password = _parse_ss_method_password(
            user_part
        )

        if not method or not password:
            return None

        host, port = _parse_host_port(endpoint_part)

        if not host or not port:
            return None

        return {
            "method": method,
            "password": password,
            "host": host,
            "port": port,
        }

    except Exception:
        return None


# ============================================================
# ENDPOINT
# ============================================================

@functools.lru_cache(maxsize=None)
def endpoint(config):
    try:
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

            if not data:
                return "", 0

            return (
                data.get("host", ""),
                int(data.get("port", 0)),
            )

        parsed_url = parsed(config)

        if not parsed_url:
            return "", 0

        try:
            host = parsed_url.hostname or ""
        except Exception:
            return "", 0

        try:
            port = parsed_url.port or 0
        except Exception:
            return host, 0

        return host, port

    except Exception:
        return "", 0


# ============================================================
# PARAMETERS
# ============================================================

def config_params(config):
    ptype = proto(config)

    if ptype == "vmess":
        data = vmess_data(config)

        def g(*keys):
            for key in keys:
                if data.get(key):
                    return str(data[key])

            return ""

        return {
            "transport": g("net", "type").lower(),
            "security": g("tls", "security").lower(),
            "sni": g("sni", "host").lower(),
            "host_header": g("host").lower(),
            "path": g("path"),
            "service_name": g("serviceName"),
            "pbk": g("pbk"),
            "sid": g("sid"),
            "flow": g("flow"),
            "fp": g("fp"),
        }

    q = query(config)

    return {
        "transport": (
            q1(q, "type")
            or q1(q, "mode")
            or ""
        ).lower(),

        "security": (
            q1(q, "security")
            or q1(q, "tls")
            or ""
        ).lower(),

        "sni": (
            q1(q, "sni")
            or q1(q, "serverName")
            or ""
        ).lower(),

        "host_header": (
            q1(q, "host")
            or q1(q, "hostHeader")
            or ""
        ).lower(),

        "path": q1(q, "path"),
        "service_name": q1(q, "serviceName"),
        "pbk": q1(q, "pbk"),
        "sid": q1(q, "sid"),
        "flow": q1(q, "flow"),
        "fp": q1(q, "fp"),
    }


# ============================================================
# HOST VALIDATION
# ============================================================

def is_junk_host(host):
    if not host:
        return True

    try:
        host = host.strip().lower()

        if not host:
            return True

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

    except Exception:
        return True


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

_LABEL_RE = re.compile(
    r"^[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def valid_host(host):
    if not host:
        return False

    try:
        host = host.strip()

        if not host or len(host) > 253:
            return False

        if is_junk_host(host):
            return False

        try:
            ipaddress.ip_address(host)
            return True

        except ValueError:
            pass

        if "%" in host:
            try:
                ipaddress.IPv6Address(
                    host.split("%", 1)[0]
                )
                return True

            except ValueError:
                return False

        if (
            not _DOMAIN_RE.match(host)
            and not _LABEL_RE.match(host)
        ):
            return False

        return True

    except Exception:
        return False


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
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

        if p == "vmess":
            data = vmess_data(config)

            if not data:
                return False

            if not (
                data.get("id")
                or data.get("uuid")
            ):
                return False

        if p == "ss":
            if not ss_data(config):
                return False

        host, port = endpoint(config)

        if not host or not port:
            return False

        try:
            port = int(port)
        except Exception:
            return False

        if not (1 <= port <= 65535):
            return False

        if not valid_host(host):
            return False

        if p in {
            "vless",
            "trojan",
            "hysteria2",
            "hy2",
        }:
            parsed_url = parsed(config)

            if not parsed_url:
                return False

            try:
                username = unquote(
                    parsed_url.username or ""
                )
            except Exception:
                username = ""

            if not username:
                return False

        return True

    except Exception:
        return False


# ============================================================
# IDENTITY / FINGERPRINT
# ============================================================

def config_identity(config):
    try:
        ptype = proto(config)

        if ptype == "vmess":
            data = vmess_data(config)

            return str(
                data.get("id")
                or data.get("uuid")
                or ""
            ).lower()

        if ptype == "ss":
            data = ss_data(config)

            if not data:
                return ""

            return (
                f"{data.get('method', '')}:"
                f"{data.get('password', '')}"
            )

        parsed_url = parsed(config)

        if not parsed_url:
            return ""

        try:
            return unquote(
                parsed_url.username or ""
            )
        except Exception:
            return ""

    except Exception:
        return ""


@functools.lru_cache(maxsize=None)
def config_fingerprint(config):
    try:
        ptype = proto(config)

        host, port = endpoint(config)

        if not host or not port:
            return ""

        p = config_params(config)

        return "|".join([
            ptype,
            host.lower(),
            str(port),
            config_identity(config),
            p["security"],
            p["transport"],
            p["sni"],
            p["host_header"],
            p["path"],
            p["service_name"],
            p["pbk"],
            p["sid"],
            p["flow"],
            p["fp"],
        ])

    except Exception:
        return ""


def dedupe(configs):
    result = []
    seen = set()

    for config in configs:
        try:
            config = normalize_config(config)

            if not config:
                continue

            if not valid_config(config):
                continue

            key = config_fingerprint(config)

            if not key or key in seen:
                continue

            seen.add(key)
            result.append(config)

        except Exception:
            continue

    return result


# ============================================================
# QUALITY
# ============================================================

@functools.lru_cache(maxsize=None)
def quality_score(config):
    try:
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

        p = config_params(config)

        transport = p["transport"]
        security = p["security"]

        if ptype == "trojan" and not security:
            security = "tls"

        secure = security in {
            "tls",
            "reality",
        }

        if transport in PREFERRED_TYPES:
            score += 8

        if security == "reality":
            score += 22

        elif security == "tls":
            score += 8

        if secure and port == 80:
            score -= 20

        if (
            not secure
            and ptype in {"vless", "vmess"}
        ):
            score -= 6

        if transport in {
            "grpc",
            "xhttp",
            "httpupgrade",
        }:
            score += 4

        if (
            transport == "ws"
            and security == "tls"
        ):
            score += 3

        if p["sni"]:
            score += 4

        if p["path"]:
            score += 2

        if p["service_name"]:
            score += 2

        if p["pbk"]:
            score += 5

        if p["sid"]:
            score += 2

        if ptype == "ss":
            score -= 4

        if ptype in UDP_PROTOCOLS:
            score -= 2

        if host and not is_ip(host):
            score += 3

        names = source_names(config)

        if len(names) >= 2:
            score += MULTI_SOURCE_BONUS

        return score

    except Exception:
        return 0


# ============================================================
# DNS / TCP / TLS
# ============================================================

def resolve(host):
    if is_ip(host):
        return host

    with _DNS_LOCK:
        if host in _DNS_CACHE:
            return _DNS_CACHE[host]

    ip = ""

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        )

        v4 = [
            i[4][0]
            for i in infos
            if i[0] == socket.AF_INET
        ]

        v6 = [
            i[4][0]
            for i in infos
            if i[0] == socket.AF_INET6
        ]

        ip = (v4 or v6 or [""])[0]

    except Exception:
        ip = ""

    with _DNS_LOCK:
        _DNS_CACHE[host] = ip

    return ip


CLOUDFLARE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
]


def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)

    except ValueError:
        return False

    return (
        addr.version == 4
        and any(
            addr in net
            for net in CLOUDFLARE_NETS
        )
    )


def _probe(config, timeout):
    ptype = proto(config)

    # Hysteria2 / Hy2 is UDP/QUIC.
    # Do not falsely mark it alive through TCP.
    if ptype in UDP_PROTOCOLS:
        return None

    host, port = endpoint(config)

    if not host or not port:
        return None

    ip = resolve(host)

    if not ip:
        return None

    p = config_params(config)

    need_tls = (
        p["security"] in {
            "tls",
            "reality",
        }
        or (
            ptype == "trojan"
            and p["security"] != "none"
        )
    )

    sni = (
        p["sni"]
        if p["sni"] and valid_host(p["sni"])
        else None
    )

    if need_tls and not sni and not is_ip(host):
        sni = host

    started = time.perf_counter()

    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ) as sock:

            if need_tls:
                sock.settimeout(TLS_TIMEOUT)

                with TLS_CTX.wrap_socket(
                    sock,
                    server_hostname=sni,
                ):
                    pass

        return (
            (time.perf_counter() - started) * 1000,
            ip,
        )

    except Exception:
        return None


def config_record(config):
    return {
        "config": config,
        "latency": 999.0,
        "score": quality_score(config),
        "alive": False,
        "verified": False,
        "ip": "",
    }


def rank_key(record):
    return (
        record["score"]
        - min(
            record["latency"] / 40.0,
            20.0,
        )
    )


def _run_probes(configs, workers, timeout):
    alive = []

    if not configs:
        return alive

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = {
            executor.submit(
                _probe,
                config,
                timeout,
            ): config
            for config in configs
        }

        for future in as_completed(futures):
            config = futures[future]

            try:
                result = future.result()

            except Exception:
                continue

            if not result:
                continue

            latency, ip = result

            record = config_record(config)

            record["latency"] = latency
            record["alive"] = True
            record["ip"] = ip

            if is_cloudflare(ip):
                record["score"] += CF_BONUS

            alive.append(record)

    return alive


def benchmark(configs):
    if not configs:
        return []

    candidates = configs[:MAX_TEST]

    print(
        f"\nBenchmarking {len(candidates)} "
        f"configs (TCP + TLS)..."
    )

    alive = _run_probes(
        candidates,
        BENCH_WORKERS,
        BENCH_TIMEOUT,
    )

    if (
        len(alive) < SECOND_PASS
        and len(configs) > len(candidates)
    ):
        extra_end = min(
            len(configs),
            len(candidates) + SECOND_PASS,
        )

        extra = configs[
            len(candidates):extra_end
        ]

        print(
            f"Second benchmark pass: "
            f"{len(extra)} configs"
        )

        alive.extend(
            _run_probes(
                extra,
                SECOND_PASS_WORKERS,
                SECOND_PASS_TIMEOUT,
            )
        )

    unique = {}

    for record in alive:
        fp = config_fingerprint(
            record["config"]
        )

        if not fp:
            continue

        old = unique.get(fp)

        if (
            old is None
            or record["latency"] < old["latency"]
        ):
            unique[fp] = record

    alive = sorted(
        unique.values(),
        key=rank_key,
        reverse=True,
    )

    print(
        f"TCP/TLS alive configs: {len(alive)}"
    )

    return alive


def subset_alive(alive_map, configs):
    result = []
    seen = set()

    for config in configs:
        fp = config_fingerprint(config)

        if not fp or fp in seen:
            continue

        record = alive_map.get(fp)

        if record:
            seen.add(fp)
            result.append(record)

    result.sort(
        key=rank_key,
        reverse=True,
    )

    return result


# ============================================================
# XRAY REAL TEST
# ============================================================

def xray_path():
    return shutil.which(XRAY_BIN)


def full_params(config):
    ptype = proto(config)

    if ptype == "vmess":
        d = vmess_data(config)

        def g(key):
            value = d.get(key)

            if value is None:
                return ""

            return str(value)

        net = g("net") or "tcp"

        return {
            "type": net,
            "security": (
                "tls"
                if g("tls").lower() == "tls"
                else ""
            ),
            "sni": g("sni"),
            "host": g("host"),
            "path": g("path"),
            "serviceName": (
                g("path")
                if net == "grpc"
                else ""
            ),
            "alpn": g("alpn"),
            "fp": g("fp"),
            "headerType": (
                g("type")
                if g("type") in {
                    "none",
                    "http",
                }
                else ""
            ),
            "mode": (
                "multi"
                if g("type") == "multi"
                else ""
            ),
            "allowInsecure": g("allowInsecure"),
            "aid": g("aid"),
            "scy": g("scy"),
            "encryption": "",
            "pbk": "",
            "sid": "",
            "spx": "",
            "flow": "",
            "extra": "",
        }

    q = query(config)

    def g(*keys):
        for key in keys:
            value = q1(q, key)

            if value:
                return str(value)

        return ""

    return {
        "type": (
            g("type", "network")
            or "tcp"
        ),
        "security": g(
            "security",
            "tls",
        ),
        "sni": g(
            "sni",
            "serverName",
            "peer",
        ),
        "host": g(
            "host",
            "hostHeader",
        ),
        "path": g("path"),
        "serviceName": g("serviceName"),
        "alpn": g("alpn"),
        "fp": g("fp"),
        "headerType": g("headerType"),
        "mode": g("mode"),
        "allowInsecure": g(
            "allowInsecure",
            "insecure",
        ),
        "aid": "",
        "scy": "",
        "encryption": g("encryption"),
        "pbk": g("pbk"),
        "sid": g("sid"),
        "spx": g("spx"),
        "flow": g("flow"),
        "extra": g("extra"),
    }


def build_stream(
    p,
    address,
    default_security="",
):
    net = (
        p["type"]
        or "tcp"
    ).lower()

    if net == "splithttp":
        net = "xhttp"

    if net == "raw":
        net = "tcp"

    if net not in {
        "tcp",
        "ws",
        "grpc",
        "httpupgrade",
        "xhttp",
    }:
        return None

    sec = (
        p["security"]
        or default_security
        or "none"
    ).lower()

    if sec not in {
        "none",
        "tls",
        "reality",
    }:
        return None

    stream = {
        "network": net,
        "security": sec,
    }

    host_header = p["host"]
    path = p["path"] or "/"

    if net == "ws":
        ws = {
            "path": path,
        }

        if host_header:
            ws["headers"] = {
                "Host": host_header,
            }

        stream["wsSettings"] = ws

    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": p["serviceName"],
            "multiMode": (
                p["mode"] == "multi"
            ),
        }

    elif net == "httpupgrade":
        hu = {
            "path": path,
        }

        if host_header:
            hu["host"] = host_header

        stream["httpupgradeSettings"] = hu

    elif net == "xhttp":
        xh = {
            "path": path,
            "mode": p["mode"] or "auto",
        }

        if host_header:
            xh["host"] = host_header

        if p["extra"]:
            try:
                extra = json.loads(
                    p["extra"]
                )

                if isinstance(extra, dict):
                    xh["extra"] = extra

            except Exception:
                pass

        stream["xhttpSettings"] = xh

    elif (
        net == "tcp"
        and p["headerType"] == "http"
    ):
        hosts = [
            h.strip()
            for h in host_header.split(",")
            if h.strip()
        ]

        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [path],
                    "headers": (
                        {"Host": hosts}
                        if hosts
                        else {}
                    ),
                },
            }
        }

    if sec == "tls":
        sni = (
            p["sni"]
            or host_header
            or (
                ""
                if is_ip(address)
                else address
            )
        )

        tls = {
            "fingerprint": (
                p["fp"]
                or "chrome"
            )
        }

        if sni:
            tls["serverName"] = sni

        alpn = [
            a.strip()
            for a in p["alpn"].split(",")
            if a.strip()
        ]

        if alpn:
            tls["alpn"] = alpn

        if str(
            p["allowInsecure"]
        ).lower() in {
            "1",
            "true",
            "yes",
        }:
            tls["allowInsecure"] = True

        stream["tlsSettings"] = tls

    elif sec == "reality":
        if not p["pbk"]:
            return None

        reality = {
            "fingerprint": (
                p["fp"]
                or "chrome"
            ),
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "spiderX": p["spx"],
        }

        if p["sni"]:
            reality["serverName"] = p["sni"]

        stream["realitySettings"] = reality

    return stream


def to_outbound(config):
    try:
        ptype = proto(config)

        host, port = endpoint(config)

        if not host or not port:
            return None

        p = full_params(config)

        if ptype == "vless":
            stream = build_stream(
                p,
                host,
            )

            if not stream:
                return None

            user = {
                "id": config_identity(config),
                "encryption": (
                    p["encryption"]
                    or "none"
                ),
            }

            if p["flow"]:
                user["flow"] = p["flow"]

            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [user],
                    }]
                },
                "streamSettings": stream,
            }

        if ptype == "vmess":
            stream = build_stream(
                p,
                host,
            )

            if not stream:
                return None

            user = {
                "id": config_identity(config),
                "security": (
                    p["scy"]
                    or "auto"
                ),
            }

            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [user],
                    }]
                },
                "streamSettings": stream,
            }

        if ptype == "trojan":
            stream = build_stream(
                p,
                host,
                default_security="tls",
            )

            if not stream:
                return None

            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": port,
                        "password": (
                            config_identity(config)
                        ),
                    }]
                },
                "streamSettings": stream,
            }

        if ptype == "ss":
            if q1(
                query(config),
                "plugin",
            ):
                return None

            data = ss_data(config)

            if not data:
                return None

            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": data["host"],
                        "port": data["port"],
                        "method": data["method"],
                        "password": data["password"],
                    }]
                },
            }

    except Exception:
        return None

    return None


# ============================================================
# SOCKS PROBE
# ============================================================

def _recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            return None

        data += chunk

    return data


def _socks_probe(
    port,
    host=None,
    dport=None,
    path=None,
    timeout=None,
):
    host = host or TEST_HOST
    dport = dport or TEST_PORT
    path = path or TEST_PATH
    timeout = timeout or REAL_TIMEOUT

    started = time.perf_counter()

    try:
        with socket.create_connection(
            ("127.0.0.1", port),
            timeout=timeout,
        ) as sock:

            sock.settimeout(timeout)

            sock.sendall(
                b"\x05\x01\x00"
            )

            if _recv_exact(
                sock,
                2,
            ) != b"\x05\x00":
                return None

            name = host.encode(
                "idna",
                errors="ignore",
            )

            if len(name) > 255:
                return None

            sock.sendall(
                b"\x05\x01\x00\x03"
                + bytes([len(name)])
                + name
                + dport.to_bytes(
                    2,
                    "big",
                )
            )

            head = _recv_exact(
                sock,
                4,
            )

            if not head or head[1] != 0:
                return None

            atyp = head[3]

            if atyp == 1:
                skip = 4

            elif atyp == 4:
                skip = 16

            else:
                length = _recv_exact(
                    sock,
                    1,
                )

                if not length:
                    return None

                skip = length[0]

            if _recv_exact(
                sock,
                skip + 2,
            ) is None:
                return None

            sock.sendall(
                (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode()
            )

            data = sock.recv(512)

            first = data.split(
                b"\r\n",
                1,
            )[0]

            if (
                first.startswith(b"HTTP/")
                and b" 204" in first
            ):
                return (
                    (time.perf_counter() - started)
                    * 1000
                )

    except Exception:
        return None

    return None


def _probe_with_retry(port):
    first = _socks_probe(port)

    if first is None:
        first = _socks_probe(port)

    if first is None:
        return None

    second = _socks_probe(port)

    if second is None:
        return first

    return min(
        first,
        second,
    )


def _wait_ready(
    proc,
    port,
    timeout=8.0,
):
    end = time.time() + timeout

    while time.time() < end:
        if proc.poll() is not None:
            return False

        try:
            sock = socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.3,
            )
            sock.close()

            return True

        except OSError:
            time.sleep(0.1)

    return False


def _stop(proc):
    if proc is None:
        return

    try:
        proc.terminate()
        proc.wait(timeout=3)

    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=3)

        except Exception:
            pass


def _run_batch(batch, base):
    if not batch:
        return []

    inbounds = []
    outbounds = []
    rules = []

    for i, (_, outbound) in enumerate(batch):
        ob = dict(outbound)
        ob["tag"] = f"o{i}"

        inbounds.append({
            "tag": f"i{i}",
            "listen": "127.0.0.1",
            "port": base + i,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False,
            },
        })

        outbounds.append(ob)

        rules.append({
            "type": "field",
            "inboundTag": [f"i{i}"],
            "outboundTag": f"o{i}",
        })

    outbounds.append({
        "protocol": "freedom",
        "tag": "direct",
    })

    cfg = {
        "log": {
            "loglevel": "none",
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }

    fd, path = tempfile.mkstemp(
        suffix=".json",
        prefix="xray_",
    )

    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            cfg,
            f,
            ensure_ascii=False,
        )

    proc = None

    try:
        proc = subprocess.Popen(
            [
                xray_path(),
                "run",
                "-c",
                path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        if not _wait_ready(
            proc,
            base + len(batch) - 1,
        ):
            _stop(proc)
            proc = None

            if len(batch) == 1:
                return []

            mid = len(batch) // 2

            return (
                _run_batch(
                    batch[:mid],
                    base,
                )
                + _run_batch(
                    batch[mid:],
                    base + mid,
                )
            )

        results = []

        with ThreadPoolExecutor(
            max_workers=len(batch)
        ) as executor:

            futures = {
                executor.submit(
                    _probe_with_retry,
                    base + i,
                ): batch[i][0]
                for i in range(len(batch))
            }

            for future in as_completed(futures):
                try:
                    latency = future.result()
                except Exception:
                    latency = None

                if latency is not None:
                    results.append(
                        (
                            futures[future],
                            latency,
                        )
                    )

        return results

    except Exception:
        return []

    finally:
        _stop(proc)

        try:
            os.remove(path)
        except OSError:
            pass


def real_test(records):
    items = []

    for record in records:
        outbound = to_outbound(
            record["config"]
        )

        if outbound:
            items.append(
                (
                    record,
                    outbound,
                )
            )

        if len(items) >= REAL_TEST_MAX:
            break

    print(
        f"\nReal test (xray): "
        f"{len(items)} testable"
    )

    if not items:
        return []

    batches = [
        items[i:i + REAL_BATCH_SIZE]
        for i in range(
            0,
            len(items),
            REAL_BATCH_SIZE,
        )
    ]

    slots = queue.Queue()

    for slot in range(
        REAL_BATCH_PARALLEL
    ):
        slots.put(
            REAL_BASE_PORT
            + slot * (
                REAL_BATCH_SIZE + 20
            )
        )

    def work(batch):
        base = slots.get()

        try:
            return _run_batch(
                batch,
                base,
            )
        finally:
            slots.put(base)

    verified = []
    done = 0

    with ThreadPoolExecutor(
        max_workers=REAL_BATCH_PARALLEL
    ) as executor:

        futures = [
            executor.submit(work, batch)
            for batch in batches
        ]

        for future in as_completed(futures):
            done += 1

            try:
                results = future.result()

            except Exception:
                results = []

            for record, latency in results:
                record = dict(record)

                record["latency"] = latency
                record["alive"] = True
                record["verified"] = True

                verified.append(record)

            if (
                done % 10 == 0
                or done == len(batches)
            ):
                print(
                    f"  batches "
                    f"{done}/{len(batches)} "
                    f"verified: "
                    f"{len(verified)}"
                )

    unique = {}

    for record in verified:
        fp = config_fingerprint(
            record["config"]
        )

        if not fp:
            continue

        old = unique.get(fp)

        if (
            old is None
            or record["latency"]
            < old["latency"]
        ):
            unique[fp] = record

    verified = sorted(
        unique.values(),
        key=rank_key,
        reverse=True,
    )

    print(
        f"Verified configs: "
        f"{len(verified)}"
    )

    return verified


# ============================================================
# STATE
# ============================================================

def load_state():
    try:
        with open(
            STATE_FILE,
            "r",
            encoding="utf-8",
        ) as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return {}

        return {
            k: v
            for k, v in data.items()
            if (
                isinstance(v, dict)
                and v.get("c")
            )
        }

    except Exception:
        return {}


def save_state(state):
    try:
        directory = os.path.dirname(
            STATE_FILE
        )

        if directory:
            os.makedirs(
                directory,
                exist_ok=True,
            )

        temp = STATE_FILE + ".tmp"

        with open(
            temp,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                state,
                f,
                ensure_ascii=False,
            )

        os.replace(
            temp,
            STATE_FILE,
        )

    except Exception as exc:
        print(
            f"[STATE] save failed: {exc}"
        )


def load_previous_outputs():
    configs = []

    for filename in EXPECTED_FILES:
        path = os.path.join(
            OUT_DIR,
            filename,
        )

        for line in read_lines(path):
            if "#" in line:
                configs.append(
                    line.rsplit("#", 1)[0]
                )

    return configs


def update_state(
    state,
    tested_fps,
    verified,
    alive_fps,
):
    now = int(time.time())

    ok = {}

    for record in verified:
        fp = config_fingerprint(
            record["config"]
        )

        if not fp:
            continue

        ok[fp] = record

        state[fp] = {
            "c": record["config"],
            "fails": 0,
            "lat": round(
                record["latency"]
            ),
            "ts": now,
        }

    for fp in list(state):
        if fp in ok:
            continue

        if (
            fp in tested_fps
            or fp not in alive_fps
        ):
            state[fp]["fails"] = (
                state[fp].get(
                    "fails",
                    0,
                )
                + 1
            )

            if (
                state[fp]["fails"]
                >= STATE_MAX_FAILS
            ):
                del state[fp]

    if len(state) > STATE_MAX:
        keep = sorted(
            state.items(),
            key=lambda kv: (
                kv[1].get(
                    "fails",
                    0,
                ),
                kv[1].get(
                    "lat",
                    9999,
                ),
            ),
        )[:STATE_MAX]

        state.clear()
        state.update(
            dict(keep)
        )

    return state


# ============================================================
# SELECTION
# ============================================================

def merge_records(
    alive_records,
    valid_configs,
    fallback=False,
):
    result = []
    seen = set()

    for record in alive_records:
        fp = config_fingerprint(
            record["config"]
        )

        if not fp or fp in seen:
            continue

        seen.add(fp)
        result.append(record)

    if fallback:
        fallback_records = []

        for config in valid_configs:
            fp = config_fingerprint(
                config
            )

            if not fp or fp in seen:
                continue

            seen.add(fp)

            fallback_records.append(
                config_record(config)
            )

        fallback_records.sort(
            key=lambda r: r["score"],
            reverse=True,
        )

        result.extend(
            fallback_records
        )

    return result


def select_records(
    results,
    limit,
    predicate=None,
):
    selected = []
    seen = set()
    host_counts = {}

    for record in results:
        try:
            config = record["config"]

            if (
                predicate
                and not predicate(config)
            ):
                continue

            fp = config_fingerprint(
                config
            )

            if not fp or fp in seen:
                continue

            host, _ = endpoint(config)

            if not host:
                continue

            host_key = host.lower()

            if (
                host_counts.get(
                    host_key,
                    0,
                )
                >= MAX_PER_HOST
            ):
                continue

            seen.add(fp)

            host_counts[host_key] = (
                host_counts.get(
                    host_key,
                    0,
                )
                + 1
            )

            selected.append(record)

            if len(selected) >= limit:
                break

        except Exception:
            continue

    return selected


# ============================================================
# RENDER
# ============================================================

def config_line(config):
    return (
        normalize_config(config)
        + "#"
        + REMARK
    )


def render_records(records):
    lines = []

    for record in records:
        try:
            line = config_line(
                record["config"]
            )

            if line.startswith(
                tuple(
                    p + "://"
                    for p in SUPPORTED_PROTOCOLS
                )
            ):
                lines.append(line)

        except Exception:
            continue

    return lines


# ============================================================
# FILES
# ============================================================

def atomic_write_lines(path, lines):
    directory = os.path.dirname(path)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    temp_path = (
        path + ".tmp"
    )

    try:
        with open(
            temp_path,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:

            for line in lines:
                f.write(
                    line.rstrip(
                        "\r\n"
                    )
                    + "\n"
                )

        os.replace(
            temp_path,
            path,
        )

    except Exception:
        try:
            if os.path.exists(
                temp_path
            ):
                os.remove(
                    temp_path
                )
        except Exception:
            pass

        raise


def count_nonempty_lines(path):
    if not os.path.exists(path):
        return 0

    try:
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

    except Exception:
        return 0


def write_file(filename, lines):
    atomic_write_lines(
        os.path.join(
            OUT_DIR,
            filename,
        ),
        lines,
    )

    print(
        f"[WRITE] {filename}: "
        f"{len(lines)}"
    )


# ============================================================
# GENERAL
# ============================================================

def write_general(good):
    print(
        "\nWriting general subscriptions..."
    )

    selected = select_records(
        good,
        GENERAL_TOTAL,
    )

    if len(selected) < GENERAL_TOTAL:
        raise RuntimeError(
            f"Not enough verified configs: "
            f"{len(selected)}/{GENERAL_TOTAL}"
        )

    all_lines = render_records(
        selected
    )

    if len(all_lines) != GENERAL_TOTAL:
        raise RuntimeError(
            f"Rendered configs: "
            f"{len(all_lines)}/{GENERAL_TOTAL}"
        )

    write_file(
        "all_configs.txt",
        all_lines,
    )

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

        chunk = all_lines[
            start:end
        ]

        if len(chunk) != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"sub{index + 1}.txt "
                f"has {len(chunk)} configs"
            )

        write_file(
            f"sub{index + 1}.txt",
            chunk,
        )

    rebuilt = []

    for index in range(
        GENERAL_SUB_COUNT
    ):
        rebuilt.extend(
            read_lines(
                os.path.join(
                    OUT_DIR,
                    f"sub{index + 1}.txt",
                )
            )
        )

    if rebuilt != all_lines:
        raise RuntimeError(
            "sub1..sub10 order does "
            "not match all_configs.txt"
        )


# ============================================================
# PROTOCOL FILES
# ============================================================

def write_protocols(
    good,
    alive_all,
    all_unique,
):
    print(
        "\nWriting protocol subscriptions..."
    )

    for ptype in [
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    ]:

        def predicate(
            config,
            p=ptype,
        ):
            current = proto(config)

            if p == "hysteria2":
                return current in {
                    "hysteria2",
                    "hy2",
                }

            return current == p

        selected = select_records(
            good,
            PROTOCOL_SUB_SIZE,
            predicate,
        )

        if not selected:
            print(
                f"[WARN] No verified "
                f"{ptype} configs"
            )
            continue

        write_file(
            f"{ptype}.txt",
            render_records(selected),
        )


# ============================================================
# IRAN / OPERATORS
# ============================================================

def fill_records(
    primary,
    fallback_groups,
    limit,
):
    groups = [
        primary,
        *fallback_groups,
    ]

    ordered = []

    for group in groups:
        ordered.extend(
            r
            for r in group
            if r.get("verified")
        )

    return select_records(
        ordered,
        limit,
    )


def write_iran(
    good_iran,
    good_mci,
    good_irancell,
    good_rightel,
    good_all,
):
    print(
        "\nWriting Iran/operator subscriptions..."
    )

    def write_operator(
        filename,
        primary,
        fallbacks,
    ):
        selected = fill_records(
            primary,
            fallbacks,
            IRAN_SUB_SIZE,
        )

        if len(selected) < IRAN_SUB_SIZE:
            raise RuntimeError(
                f"{filename}: only "
                f"{len(selected)}/"
                f"{IRAN_SUB_SIZE} verified configs"
            )

        write_file(
            filename,
            render_records(selected),
        )

    write_operator(
        "mci.txt",
        good_mci,
        [
            good_iran,
            good_all,
        ],
    )

    write_operator(
        "irancell.txt",
        good_irancell,
        [
            good_iran,
            good_all,
        ],
    )

    write_operator(
        "rightel.txt",
        good_rightel,
        [
            good_iran,
            good_all,
        ],
    )

    write_operator(
        "best_iran.txt",
        good_iran,
        [good_all],
    )

    pool = select_records(
        good_iran + good_all,
        IRAN_SUB_SIZE * 3,
    )

    random.shuffle(pool)

    mix_selected = pool[
        :IRAN_SUB_SIZE
    ]

    if len(mix_selected) < IRAN_SUB_SIZE:
        raise RuntimeError(
            "Could not create "
            "mix_iran.txt"
        )

    write_file(
        "mix_iran.txt",
        render_records(
            mix_selected
        ),
    )


# ============================================================
# SUMMARY
# ============================================================

def print_source_summary():
    print(
        "\n"
        + "=" * 65
    )

    print("SOURCE SUMMARY")

    print(
        "=" * 65
    )

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
# EXPECTED FILES
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

    try:
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

    except Exception:
        return []


# ============================================================
# VERIFY
# ============================================================

def verify_outputs():
    print(
        "\nVerifying outputs..."
    )

    expected = set(
        EXPECTED_FILES
    )

    if not os.path.isdir(OUT_DIR):
        raise RuntimeError(
            f"Output directory does not exist: "
            f"{OUT_DIR}"
        )

    actual = {
        name
        for name in os.listdir(OUT_DIR)
        if name.endswith(".txt")
    }

    unexpected = (
        actual - expected
    )

    if unexpected:
        raise RuntimeError(
            "Unexpected output files: "
            + ", ".join(
                sorted(unexpected)
            )
        )

    if os.path.exists(
        os.path.join(
            OUT_DIR,
            "random_200.txt",
        )
    ):
        raise RuntimeError(
            "random_200.txt must not exist"
        )

    missing = (
        expected - actual
    )

    if missing:
        raise RuntimeError(
            "Missing output files: "
            + ", ".join(
                sorted(missing)
            )
        )

    all_lines = read_lines(
        os.path.join(
            OUT_DIR,
            "all_configs.txt",
        )
    )

    if len(all_lines) != GENERAL_TOTAL:
        raise RuntimeError(
            f"all_configs.txt has "
            f"{len(all_lines)} configs, "
            f"expected {GENERAL_TOTAL}"
        )

    rebuilt = []

    for index in range(
        GENERAL_SUB_COUNT
    ):
        filename = (
            f"sub{index + 1}.txt"
        )

        lines = read_lines(
            os.path.join(
                OUT_DIR,
                filename,
            )
        )

        if len(lines) != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"{filename} has "
                f"{len(lines)} configs, "
                f"expected {GENERAL_SUB_SIZE}"
            )

        rebuilt.extend(lines)

    if rebuilt != all_lines:
        raise RuntimeError(
            "sub1..sub10 do not match "
            "all_configs.txt"
        )

    for filename in [
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
        "best_iran.txt",
        "mix_iran.txt",
    ]:
        lines = read_lines(
            os.path.join(
                OUT_DIR,
                filename,
            )
        )

        if len(lines) != IRAN_SUB_SIZE:
            raise RuntimeError(
                f"{filename} has "
                f"{len(lines)} configs, "
                f"expected {IRAN_SUB_SIZE}"
            )

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

        lines = read_lines(
            os.path.join(
                OUT_DIR,
                filename,
            )
        )

        if not (
            1
            <= len(lines)
            <= PROTOCOL_SUB_SIZE
        ):
            raise RuntimeError(
                f"{filename} has "
                f"{len(lines)} configs"
            )

        for line in lines:
            raw_config = line.rsplit(
                "#",
                1,
            )[0]

            actual_proto = proto(
                raw_config
            )

            if ptype == "hysteria2":
                ok = (
                    actual_proto
                    in UDP_PROTOCOLS
                )
            else:
                ok = (
                    actual_proto
                    == ptype
                )

            if not ok:
                raise RuntimeError(
                    f"{filename} contains "
                    f"wrong protocol: {line}"
                )

    for filename in EXPECTED_FILES:
        lines = read_lines(
            os.path.join(
                OUT_DIR,
                filename,
            )
        )

        if not lines:
            raise RuntimeError(
                f"{filename} is empty"
            )

        if len(set(lines)) != len(lines):
            raise RuntimeError(
                f"Duplicate lines found "
                f"in {filename}"
            )

        for line in lines:
            if (
                not line.endswith(
                    f"#{REMARK}"
                )
                or line.count("#") != 1
            ):
                raise RuntimeError(
                    f"Invalid remark in "
                    f"{filename}: {line}"
                )

            raw_config = line.rsplit(
                "#",
                1,
            )[0]

            if not valid_config(
                raw_config
            ):
                raise RuntimeError(
                    f"Invalid config in "
                    f"{filename}: {line}"
                )

    print(
        "OUTPUT VERIFICATION PASSED"
    )


def print_summary():
    print(
        "\n"
        + "=" * 65
    )

    print(
        "FINAL OUTPUT SUMMARY"
    )

    print(
        "=" * 65
    )

    for filename in EXPECTED_FILES:
        count = count_nonempty_lines(
            os.path.join(
                OUT_DIR,
                filename,
            )
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

    real = bool(
        xray_path()
    )

    print(
        "=" * 65
    )

    print(
        "NUKCROW COLLECTOR"
    )

    print(
        f"Real xray test: "
        f"{'ENABLED' if real else 'DISABLED'}"
    )

    print(
        "=" * 65
    )

    os.makedirs(
        OUT_DIR,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # KNOWN GOOD
    # --------------------------------------------------------

    state = load_state()

    previous = load_previous_outputs()

    state_configs = [
        value["c"]
        for value in state.values()
        if isinstance(value, dict)
        and value.get("c")
    ]

    known = dedupe(
        state_configs
        + previous
    )

    known_fps = {
        config_fingerprint(config)
        for config in known
    }

    print(
        f"\nKnown-good pool: "
        f"{len(known)}"
    )

    # --------------------------------------------------------
    # FETCH
    # --------------------------------------------------------

    raw = fetch_all()

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

    random.shuffle(
        general_unique
    )

    priority = dedupe(
        known
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
    )

    all_unique = dedupe(
        priority
        + general_unique
    )

    print(
        "\nUnique configs:"
    )

    print(
        f"  General:  "
        f"{len(general_unique)}"
    )

    print(
        f"  Iran:     "
        f"{len(iran_unique)}"
    )

    print(
        f"  MCI:      "
        f"{len(mci_unique)}"
    )

    print(
        f"  Irancell: "
        f"{len(irancell_unique)}"
    )

    print(
        f"  Rightel:  "
        f"{len(rightel_unique)}"
    )

    print(
        f"  Global:   "
        f"{len(all_unique)}"
    )

    # --------------------------------------------------------
    # STAGE 1
    # --------------------------------------------------------

    alive_all = benchmark(
        all_unique
    )

    alive_map = {
        config_fingerprint(
            record["config"]
        ): record
        for record in alive_all
    }

    # --------------------------------------------------------
    # STAGE 2
    # --------------------------------------------------------

    if not real:
        print(
            "[ERROR] xray-core not found."
        )
        print(
            "[ERROR] No unverified configs "
            "will be published."
        )
        return

    known_alive = [
        record
        for record in alive_all
        if config_fingerprint(
            record["config"]
        ) in known_fps
    ]

    fresh_alive = [
        record
        for record in alive_all
        if config_fingerprint(
            record["config"]
        ) not in known_fps
    ]

    candidates = (
        known_alive[:STATE_RETEST]
        + fresh_alive
    )

    candidates = candidates[
        :REAL_TEST_MAX
    ]

    good = real_test(
        candidates
    )

    tested_fps = {
        config_fingerprint(
            record["config"]
        )
        for record in candidates
    }

    save_state(
        update_state(
            state,
            tested_fps,
            good,
            set(alive_map),
        )
    )

    print(
        f"\nGood configs this run: "
        f"{len(good)}"
    )

    # --------------------------------------------------------
    # NEVER REPLACE OLD OUTPUT WITH A BAD RUN
    # --------------------------------------------------------

    if len(good) < GENERAL_TOTAL:
        print(
            f"[SKIP] only "
            f"{len(good)}/{GENERAL_TOTAL} "
            f"verified configs"
        )

        print(
            "[SKIP] Previous outputs "
            "remain untouched."
        )

        return

    # --------------------------------------------------------
    # WRITE
    # --------------------------------------------------------

    good_map = {
        config_fingerprint(
            record["config"]
        ): record
        for record in good
    }

    good_iran = subset_alive(
        good_map,
        iran_unique,
    )

    good_mci = subset_alive(
        good_map,
        mci_unique,
    )

    good_irancell = subset_alive(
        good_map,
        irancell_unique,
    )

    good_rightel = subset_alive(
        good_map,
        rightel_unique,
    )

    write_general(
        good
    )

    write_iran(
        good_iran,
        good_mci,
        good_irancell,
        good_rightel,
        good,
    )

    write_protocols(
        good,
        alive_all,
        all_unique,
    )

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    verify_outputs()

    print_source_summary()

    print_summary()

    print(
        f"\nDONE: "
        f"{time.time() - started:.2f}s"
    )


if __name__ == "__main__":
    main()
