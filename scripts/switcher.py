import os
import re
import json
import time
import base64
import socket
import ssl
import random
import ipaddress
import threading
import functools
import html as html_lib

from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ============================================================
# CONFIG
# ============================================================

OUT_DIR = "sub/general"
REMARK = "nukcrow"

SUPPORTED_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
UDP_PROTOCOLS = {"hysteria2", "hy2"}

GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10
GENERAL_TOTAL = GENERAL_SUB_SIZE * GENERAL_SUB_COUNT

PROTOCOL_SUB_SIZE = 100
IRAN_SUB_SIZE = 200

MAX_PER_HOST = 8

FETCH_WORKERS = 5
FETCH_TIMEOUT = 15
FETCH_RETRIES = 3
MAX_PER_SOURCE = 8000

# Benchmark: TCP connect (+ TLS handshake for tls/reality configs)
MAX_TEST = 10000
BENCH_WORKERS = 80
BENCH_TIMEOUT = 2.0
TLS_TIMEOUT = 2.5

SECOND_PASS = 2000
SECOND_PASS_WORKERS = 40
SECOND_PASS_TIMEOUT = 2.0

ALLOW_VALID_FALLBACK = True

PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade", "tcp"}

# Scoring bonuses (Iran oriented)
CF_BONUS = 8              # server IP inside Cloudflare ranges (CDN fronted, stable in Iran)
TELEGRAM_BONUS = 6        # fresh config scraped from Telegram channels
MULTI_SOURCE_BONUS = 3    # config seen in 2+ sources

# Telegram public preview scraping (https://t.me/s/<channel>)
TELEGRAM_ENABLED = True
TELEGRAM_PAGES = 2
TELEGRAM_WORKERS = 4
TELEGRAM_CHANNELS = [
    "v2rayng_fa2",
    "v2rayng_org",
    "V2rayNGvpni",
    "custom_14",
    "v2rayNG_VPNN",
    "V2rayNG3",
    "MsV2ray",
    "foxrayiran",
    "DailyV2RY",
    "yaney_01",
    "FreakConfig",
    "EliV2ray",
    "ServerNett",
    "proxystore11",
    "v2ray_outlineir",
    "v2_vmess",
    "FreeVlessVpn",
    "vmess_vless_v2rayng",
    "PrivateVPNs",
    "vmessiran",
    "V2Ray_FreedomIran",
]

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
# HTTP SESSION
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
        return base64.b64decode(value, validate=False).decode("utf-8", errors="ignore")
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
        config = config.replace("\\n", "").replace("\n", "").replace("\r", "")
        if "#" in config:
            config = config.split("#", 1)[0]
        config = config.strip().strip("'\"`")
        return config.strip()
    except Exception:
        return ""


def _collect(text, found):
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
        SOURCE_META.setdefault(config_key(config), set()).add(source)


def source_names(config):
    with SOURCE_META_LOCK:
        return sorted(SOURCE_META.get(config_key(config), set()))


# ============================================================
# FETCH
# ============================================================

def fetch_source(url):
    last_error = None

    for attempt in range(FETCH_RETRIES + 1):
        try:
            response = session().get(url, timeout=FETCH_TIMEOUT, allow_redirects=True)
            response.raise_for_status()

            configs = extract_uris(response.text)[:MAX_PER_SOURCE]

            for config in configs:
                register_source(config, url)

            return configs

        except Exception as exc:
            last_error = exc
            if attempt < FETCH_RETRIES:
                # Respect HTTP rate limits when a source responds with 429.
                retry_after = 0
                response_obj = locals().get("response")
                if response_obj is not None and getattr(response_obj, "status_code", None) == 429:
                    try:
                        retry_after = int(response_obj.headers.get("Retry-After", "0"))
                    except (TypeError, ValueError):
                        retry_after = 0
                time.sleep(min(max(retry_after, 2 ** attempt), 60))

    print(f"[FETCH ERROR] {url}: {last_error}")
    return []


def fetch_group(sources, name):
    results = []

    if not sources:
        return results

    print(f"\nFetching {name}: {len(sources)} sources")

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        futures = {executor.submit(fetch_source, s): s for s in sources}

        for future in as_completed(futures):
            source = futures[future]
            try:
                configs = future.result()
                results.extend(configs)
                print(f"[OK] {len(configs):5d} {source}")
            except Exception as exc:
                print(f"[ERROR] {source}: {exc}")

    return results


def fetch_telegram_channel(channel):
    found = []
    before = None
    label = f"tg:{channel}"

    for _ in range(TELEGRAM_PAGES):
        url = f"https://t.me/s/{channel}"
        if before:
            url += f"?before={before}"

        try:
            response = session().get(url, timeout=FETCH_TIMEOUT)
            response.raise_for_status()
        except Exception as exc:
            response_obj = locals().get("response")
            if response_obj is not None and getattr(response_obj, "status_code", None) == 429:
                try:
                    wait_seconds = int(response_obj.headers.get("Retry-After", "10"))
                except (TypeError, ValueError):
                    wait_seconds = 10
                time.sleep(min(max(wait_seconds, 1), 60))
            print(f"[TG ERROR] {channel}: {exc}")
            break

        page = response.text

        ids = [int(x) for x in re.findall(r'data-post="[^"/]+/(\d+)"', page)]

        text = re.sub(r"<br\s*/?>", "\n", page)
        text = re.sub(r"<[^>]+>", " ", text)
        text = html_lib.unescape(text)

        for config in extract_uris(text):
            register_source(config, label)
            found.append(config)

        if not ids:
            break

        before = min(ids)
        time.sleep(1.2)

    return found


def fetch_telegram_group():
    results = []

    if not TELEGRAM_ENABLED or not TELEGRAM_CHANNELS:
        return results

    print(f"\nFetching TELEGRAM: {len(TELEGRAM_CHANNELS)} channels")

    with ThreadPoolExecutor(max_workers=TELEGRAM_WORKERS) as executor:
        futures = {executor.submit(fetch_telegram_channel, c): c for c in TELEGRAM_CHANNELS}

        for future in as_completed(futures):
            channel = futures[future]
            try:
                configs = future.result()
                results.extend(configs)
                print(f"[TG OK] {len(configs):5d} {channel}")
            except Exception as exc:
                print(f"[TG ERROR] {channel}: {exc}")

    return results


def fetch_all():
    return {
        "general": fetch_group(SOURCES_GENERAL, "GENERAL"),
        "iran": fetch_group(SOURCES_IRAN, "IRAN"),
        "mci": fetch_group(SOURCES_MCI, "MCI"),
        "irancell": fetch_group(SOURCES_IRANCELL, "IRANCELL"),
        "rightel": fetch_group(SOURCES_RIGHTEL, "RIGHTEL"),
        "telegram": fetch_telegram_group(),
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
        return parse_qs(parsed_url.query, keep_blank_values=True)
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

        decoded = decode64(config.split("://", 1)[1])
        if not decoded:
            return {}

        data = json.loads(decoded)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    return {}


def ss_data(config):
    try:
        parsed_url = urlparse(config)

        if parsed_url.scheme.lower() != "ss":
            return None

        try:
            port = parsed_url.port
        except (ValueError, TypeError):
            return None

        if not port or not (1 <= port <= 65535):
            return None

        try:
            host = parsed_url.hostname
        except (ValueError, TypeError):
            return None

        if not host:
            return None

        raw_netloc = parsed_url.netloc

        # SIP002: ss://BASE64(method:password)@host:port
        if "@" in raw_netloc:
            userinfo, _ = raw_netloc.rsplit("@", 1)
            userinfo = unquote(userinfo)

            method = ""
            secret = ""

            if ":" in userinfo:
                method, secret = userinfo.split(":", 1)
            else:
                decoded_userinfo = decode64(userinfo)
                if ":" in decoded_userinfo:
                    method, secret = decoded_userinfo.split(":", 1)

            method = unquote(method.strip())
            secret = unquote(secret.strip())

            if not method or not secret:
                return None

            return {"method": method, "password": secret, "host": host, "port": port}

        # Legacy: ss://BASE64(method:password@host:port)
        payload = config.split("://", 1)[1].split("#", 1)[0]
        decoded_payload = decode64(payload)

        if not decoded_payload or "@" not in decoded_payload:
            return None

        userinfo, endpoint_part = decoded_payload.rsplit("@", 1)

        if ":" not in userinfo:
            return None

        method, secret = userinfo.split(":", 1)

        endpoint_url = urlparse("ss://" + endpoint_part)

        try:
            decoded_port = endpoint_url.port
        except (ValueError, TypeError):
            return None

        decoded_host = endpoint_url.hostname

        if not decoded_host or not decoded_port:
            return None

        if not (1 <= decoded_port <= 65535):
            return None

        method = unquote(method.strip())
        secret = unquote(secret.strip())

        if not method or not secret:
            return None

        return {
            "method": method,
            "password": secret,
            "host": decoded_host,
            "port": decoded_port,
        }

    except Exception:
        return None


@functools.lru_cache(maxsize=None)
def endpoint(config):
    try:
        ptype = proto(config)

        if ptype == "vmess":
            data = vmess_data(config)
            host = data.get("add") or data.get("address") or ""
            try:
                port = int(data.get("port") or 0)
            except Exception:
                port = 0
            return host, port

        if ptype == "ss":
            data = ss_data(config)
            if not data:
                return "", 0
            try:
                port = int(data.get("port", 0) or 0)
            except Exception:
                port = 0
            return data.get("host", ""), port

        parsed_url = parsed(config)
        if not parsed_url:
            return "", 0

        try:
            host = parsed_url.hostname or ""
        except (ValueError, TypeError):
            return "", 0

        try:
            port = parsed_url.port or 0
        except (ValueError, TypeError):
            return host, 0

        return host, port

    except Exception:
        return "", 0


def config_params(config):
    """Unified transport/security/etc. extraction for every protocol."""
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
        "transport": (q1(q, "type") or q1(q, "mode") or "").lower(),
        "security": (q1(q, "security") or q1(q, "tls") or "").lower(),
        "sni": (q1(q, "sni") or q1(q, "serverName") or "").lower(),
        "host_header": (q1(q, "host") or q1(q, "hostHeader") or "").lower(),
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

        if host in {"localhost", "localhost.localdomain"}:
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
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


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
                ipaddress.IPv6Address(host.split("%", 1)[0])
                return True
            except ValueError:
                return False

        if not _DOMAIN_RE.match(host) and not _LABEL_RE.match(host):
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
            if not (data.get("id") or data.get("uuid")):
                return False

        if p == "ss" and not ss_data(config):
            return False

        host, port = endpoint(config)

        if not host or not port:
            return False

        try:
            port = int(port)
        except (ValueError, TypeError):
            return False

        if not (1 <= port <= 65535):
            return False

        if not valid_host(host):
            return False

        if p in {"vless", "trojan", "hysteria2", "hy2"}:
            parsed_url = parsed(config)
            if not parsed_url:
                return False

            try:
                username = unquote(parsed_url.username or "")
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
            return str(data.get("id") or data.get("uuid") or "").lower()

        if ptype == "ss":
            data = ss_data(config)
            if not data:
                return ""
            return f"{data.get('method', '')}:{data.get('password', '')}"

        parsed_url = parsed(config)
        if not parsed_url:
            return ""

        try:
            return unquote(parsed_url.username or "")
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

            if not config or not valid_config(config):
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
# QUALITY SCORE (Iran oriented)
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
        elif port in {80, 8443, 2053, 2083, 2087, 2096}:
            score += 4

        p = config_params(config)

        transport = p["transport"]
        security = p["security"]

        if ptype == "trojan" and not security:
            security = "tls"

        secure = security in {"tls", "reality"}

        if transport in PREFERRED_TYPES:
            score += 8

        if security == "reality":
            score += 22
        elif security == "tls":
            score += 8

        # TLS/REALITY on port 80 is almost always a fake/broken config
        if secure and port == 80:
            score -= 20

        # Plain (no TLS) transports are easily fingerprinted by DPI
        if not secure and ptype in {"vless", "vmess"}:
            score -= 6

        if transport in {"grpc", "xhttp", "httpupgrade"}:
            score += 4

        if transport == "ws" and security == "tls":
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

        # Plain Shadowsocks is commonly throttled/blocked by DPI
        if ptype == "ss":
            score -= 4

        # Hysteria2 is UDP/QUIC: often throttled and not TCP-testable
        if ptype in UDP_PROTOCOLS:
            score -= 2

        if host and not is_ip(host):
            score += 3

        names = source_names(config)

        if any(n.startswith("tg:") for n in names):
            score += TELEGRAM_BONUS

        if len(names) >= 2:
            score += MULTI_SOURCE_BONUS

        return score

    except Exception:
        return 0


# ============================================================
# BENCHMARK (TCP + TLS handshake)
# ============================================================

def resolve(host):
    if is_ip(host):
        return host

    with _DNS_LOCK:
        if host in _DNS_CACHE:
            return _DNS_CACHE[host]

    ip = ""

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)

        v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
        v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]

        ip = (v4 or v6 or [""])[0]
    except Exception:
        ip = ""

    with _DNS_LOCK:
        _DNS_CACHE[host] = ip

    return ip


def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return addr.version == 4 and any(addr in net for net in CLOUDFLARE_NETS)


def _probe(config, timeout):
    """Returns (latency_ms, ip) or None. UDP protocols are not probed."""
    ptype = proto(config)

    if ptype in UDP_PROTOCOLS:
        return None

    host, port = endpoint(config)

    if not host or not port:
        return None

    ip = resolve(host)

    if not ip:
        return None

    p = config_params(config)
    need_tls = p["security"] in {"tls", "reality"} or (ptype == "trojan" and p["security"] != "none")

    sni = p["sni"] if p["sni"] and valid_host(p["sni"]) else None

    if need_tls and not sni and not is_ip(host):
        sni = host

    started = time.perf_counter()

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if need_tls:
                sock.settimeout(TLS_TIMEOUT)
                with TLS_CTX.wrap_socket(sock, server_hostname=sni):
                    pass

        return (time.perf_counter() - started) * 1000, ip

    except Exception:
        return None


def config_record(config):
    return {
        "config": config,
        "latency": 999.0,
        "score": quality_score(config),
        "alive": False,
        "ip": "",
    }


def rank_key(record):
    """Higher is better: quality score minus a latency penalty."""
    return record["score"] - min(record["latency"] / 40.0, 20.0)


def _run_probes(configs, workers, timeout):
    alive = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_probe, c, timeout): c for c in configs}

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

    print(f"\nBenchmarking {len(candidates)} configs (TCP + TLS)...")

    alive = _run_probes(candidates, BENCH_WORKERS, BENCH_TIMEOUT)

    if len(alive) < SECOND_PASS and len(configs) > len(candidates):
        extra = configs[len(candidates):len(candidates) + SECOND_PASS]

        print(f"Second benchmark pass: {len(extra)} configs")

        alive.extend(_run_probes(extra, SECOND_PASS_WORKERS, SECOND_PASS_TIMEOUT))

    unique = {}

    for record in alive:
        fp = config_fingerprint(record["config"])

        if not fp:
            continue

        old = unique.get(fp)

        if old is None or record["latency"] < old["latency"]:
            unique[fp] = record

    alive = sorted(unique.values(), key=rank_key, reverse=True)

    print(f"Alive configs: {len(alive)}")

    return alive


def subset_alive(alive_map, configs):
    """Reuse the shared benchmark results for a group instead of re-testing."""
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

    result.sort(key=rank_key, reverse=True)

    return result


# ============================================================
# RECORD MERGE / SELECTION
# ============================================================

def merge_records(alive_records, valid_configs):
    result = []
    seen = set()

    for record in alive_records:
        fp = config_fingerprint(record["config"])

        if not fp or fp in seen:
            continue

        seen.add(fp)
        result.append(record)

    if ALLOW_VALID_FALLBACK:
        fallback = []

        for config in valid_configs:
            fp = config_fingerprint(config)

            if not fp or fp in seen:
                continue

            seen.add(fp)
            fallback.append(config_record(config))

        # untested configs: best static score first
        fallback.sort(key=lambda r: r["score"], reverse=True)

        result.extend(fallback)

    return result


def select_records(results, limit, predicate=None):
    selected = []
    seen = set()
    host_counts = {}

    for record in results:
        try:
            config = record["config"]

            if predicate and not predicate(config):
                continue

            fp = config_fingerprint(config)

            if not fp or fp in seen:
                continue

            host, _ = endpoint(config)

            if not host:
                continue

            host_key = host.lower()

            if host_counts.get(host_key, 0) >= MAX_PER_HOST:
                continue

            seen.add(fp)
            host_counts[host_key] = host_counts.get(host_key, 0) + 1
            selected.append(record)

            if len(selected) >= limit:
                break

        except Exception:
            continue

    return selected


def select_subscription(alive_records, valid_configs, limit, predicate=None):
    merged = merge_records(alive_records, valid_configs)
    return select_records(merged, limit, predicate)


# ============================================================
# RENDER
# ============================================================

def config_line(config):
    return normalize_config(config) + "#" + REMARK


def render_records(records):
    lines = []

    for record in records:
        try:
            lines.append(config_line(record["config"]))
        except Exception:
            continue

    return lines


# ============================================================
# FILE WRITING
# ============================================================

def atomic_write_lines(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    temp_path = path + ".tmp"

    try:
        with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
            for line in lines:
                f.write(line.rstrip("\r\n") + "\n")

        os.replace(temp_path, path)

    except Exception:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        raise


def count_nonempty_lines(path):
    if not os.path.exists(path):
        return 0

    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def write_file(filename, lines):
    atomic_write_lines(os.path.join(OUT_DIR, filename), lines)
    print(f"[WRITE] {filename}: {len(lines)}")


# ============================================================
# GENERAL SUBSCRIPTIONS
# ============================================================

def write_general(alive_all, all_unique):
    print("\nWriting general subscriptions...")

    selected = select_subscription(alive_all, all_unique, GENERAL_TOTAL)

    if len(selected) < GENERAL_TOTAL:
        raise RuntimeError(
            f"Not enough configs for general subscriptions: "
            f"{len(selected)}/{GENERAL_TOTAL}"
        )

    all_lines = render_records(selected[:GENERAL_TOTAL])

    if len(all_lines) != GENERAL_TOTAL:
        raise RuntimeError(f"Rendered general output does not contain exactly {GENERAL_TOTAL} lines")

    write_file("all_configs.txt", all_lines)

    for index in range(GENERAL_SUB_COUNT):
        start = index * GENERAL_SUB_SIZE
        sub_lines = all_lines[start:start + GENERAL_SUB_SIZE]

        if len(sub_lines) != GENERAL_SUB_SIZE:
            raise RuntimeError(f"sub{index + 1}.txt must contain {GENERAL_SUB_SIZE} configs")

        write_file(f"sub{index + 1}.txt", sub_lines)

    rebuilt = []

    for index in range(GENERAL_SUB_COUNT):
        rebuilt.extend(read_lines(os.path.join(OUT_DIR, f"sub{index + 1}.txt")))

    if rebuilt != all_lines:
        raise RuntimeError("sub1..sub10 order does not match all_configs.txt")


# ============================================================
# PROTOCOL FILES
# ============================================================

def write_protocols(alive_all, all_unique):
    print("\nWriting protocol subscriptions...")

    for ptype in ["vless", "vmess", "trojan", "ss", "hysteria2"]:
        selected = select_subscription(
            alive_all,
            all_unique,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype: (
                proto(c) == p or (p == "hysteria2" and proto(c) == "hy2")
            ),
        )

        if not selected:
            print(f"[WARN] No {ptype} configs")
            continue

        lines = render_records(selected)

        if not lines:
            print(f"[WARN] No rendered {ptype} configs")
            continue

        write_file(f"{ptype}.txt", lines)


# ============================================================
# IRAN / OPERATORS
# ============================================================

def fill_records(primary, fallback_groups, limit):
    """Alive records of every group first (in priority order), untested last."""
    groups = [primary, *fallback_groups]

    ordered = [r for g in groups for r in g if r.get("alive")]
    ordered += [r for g in groups for r in g if not r.get("alive")]

    return select_records(ordered, limit)


def write_iran(
    alive_iran, iran_unique,
    alive_mci, mci_unique,
    alive_irancell, irancell_unique,
    alive_rightel, rightel_unique,
    alive_all, all_unique,
):
    print("\nWriting Iran/operator subscriptions...")

    global_records = merge_records(alive_all, all_unique)
    iran_records = merge_records(alive_iran, iran_unique)
    mci_records = merge_records(alive_mci, mci_unique)
    irancell_records = merge_records(alive_irancell, irancell_unique)
    rightel_records = merge_records(alive_rightel, rightel_unique)

    def write_operator(filename, primary, fallbacks):
        selected = fill_records(primary, fallbacks, IRAN_SUB_SIZE)

        if len(selected) < IRAN_SUB_SIZE:
            raise RuntimeError(f"Could not create {filename}")

        write_file(filename, render_records(selected))

    write_operator("mci.txt", mci_records, [iran_records, global_records])
    write_operator("irancell.txt", irancell_records, [iran_records, global_records])
    write_operator("rightel.txt", rightel_records, [iran_records, global_records])
    write_operator("best_iran.txt", iran_records, [global_records])

    # mix_iran: shuffle only the best alive pool, untested configs stay last
    pool = iran_records + global_records

    alive_pool = sorted((r for r in pool if r.get("alive")), key=rank_key, reverse=True)
    untested = [r for r in pool if not r.get("alive")]

    top = alive_pool[:IRAN_SUB_SIZE * 8]
    rest = alive_pool[IRAN_SUB_SIZE * 8:]

    random.shuffle(top)

    mix_selected = select_records(top + rest + untested, IRAN_SUB_SIZE)

    if len(mix_selected) < IRAN_SUB_SIZE:
        raise RuntimeError("Could not create mix_iran.txt")

    write_file("mix_iran.txt", render_records(mix_selected))


# ============================================================
# SUMMARIES
# ============================================================

def print_source_summary():
    print("\n" + "=" * 65)
    print("SOURCE SUMMARY")
    print("=" * 65)

    with SOURCE_META_LOCK:
        items = list(SOURCE_META.items())

    source_counts = {}

    for _, sources in items:
        for source in sources:
            source_counts[source] = source_counts.get(source, 0) + 1

    for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"{count:6d}  {source}")


# ============================================================
# OUTPUT VERIFICATION
# ============================================================

EXPECTED_FILES = [
    "all_configs.txt",
    "sub1.txt", "sub2.txt", "sub3.txt", "sub4.txt", "sub5.txt",
    "sub6.txt", "sub7.txt", "sub8.txt", "sub9.txt", "sub10.txt",
    "mci.txt", "irancell.txt", "rightel.txt",
    "best_iran.txt", "mix_iran.txt",
    "vless.txt", "vmess.txt", "trojan.txt", "ss.txt", "hysteria2.txt",
]


def read_lines(path):
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.rstrip("\r\n") for line in f if line.strip()]
    except Exception:
        return []


def verify_outputs():
    print("\nVerifying outputs...")

    expected = set(EXPECTED_FILES)

    if not os.path.isdir(OUT_DIR):
        raise RuntimeError(f"Output directory does not exist: {OUT_DIR}")

    actual = {n for n in os.listdir(OUT_DIR) if n.endswith(".txt")}

    unexpected = actual - expected
    if unexpected:
        raise RuntimeError("Unexpected output files: " + ", ".join(sorted(unexpected)))

    if os.path.exists(os.path.join(OUT_DIR, "random_200.txt")):
        raise RuntimeError("random_200.txt must not exist")

    missing = expected - actual
    if missing:
        raise RuntimeError("Missing output files: " + ", ".join(sorted(missing)))

    all_lines = read_lines(os.path.join(OUT_DIR, "all_configs.txt"))

    if len(all_lines) != GENERAL_TOTAL:
        raise RuntimeError(f"all_configs.txt must contain {GENERAL_TOTAL} configs, got {len(all_lines)}")

    rebuilt = []

    for index in range(GENERAL_SUB_COUNT):
        filename = f"sub{index + 1}.txt"
        lines = read_lines(os.path.join(OUT_DIR, filename))

        if len(lines) != GENERAL_SUB_SIZE:
            raise RuntimeError(f"{filename} must contain {GENERAL_SUB_SIZE} configs, got {len(lines)}")

        rebuilt.extend(lines)

    if rebuilt != all_lines:
        raise RuntimeError("sub1.txt to sub10.txt are not in the exact same order as all_configs.txt")

    if len(set(all_lines)) != len(all_lines):
        raise RuntimeError("Duplicate lines found in all_configs.txt")

    for filename in ["mci.txt", "irancell.txt", "rightel.txt", "best_iran.txt", "mix_iran.txt"]:
        lines = read_lines(os.path.join(OUT_DIR, filename))

        if len(lines) != IRAN_SUB_SIZE:
            raise RuntimeError(f"{filename} must contain {IRAN_SUB_SIZE} configs, got {len(lines)}")

    for ptype in ["vless", "vmess", "trojan", "ss", "hysteria2"]:
        filename = f"{ptype}.txt"
        lines = read_lines(os.path.join(OUT_DIR, filename))

        if not (1 <= len(lines) <= PROTOCOL_SUB_SIZE):
            raise RuntimeError(f"{filename} must contain 1-{PROTOCOL_SUB_SIZE} configs, got {len(lines)}")

        for line in lines:
            if "#" not in line:
                raise RuntimeError(f"{filename} contains invalid line: {line}")

            config = line.rsplit("#", 1)[0]
            actual_proto = proto(config)

            if ptype == "hysteria2":
                ok = actual_proto in UDP_PROTOCOLS
            else:
                ok = actual_proto == ptype

            if not ok:
                raise RuntimeError(f"{filename} contains wrong protocol: {line}")

            if not valid_config(config):
                raise RuntimeError(f"Invalid config in {filename}: {line}")

    for filename in EXPECTED_FILES:
        lines = read_lines(os.path.join(OUT_DIR, filename))

        if not lines:
            raise RuntimeError(f"{filename} is empty")

        if len(set(lines)) != len(lines):
            raise RuntimeError(f"Duplicate lines found in {filename}")

        for line in lines:
            if not line.endswith(f"#{REMARK}"):
                raise RuntimeError(f"Invalid remark in {filename}: {line}")

            if line.count("#") != 1:
                raise RuntimeError(f"Invalid # count in {filename}: {line}")

            if not valid_config(line.rsplit("#", 1)[0]):
                raise RuntimeError(f"Invalid config in {filename}: {line}")

    print("OUTPUT VERIFICATION PASSED")


def print_summary():
    print("\n" + "=" * 65)
    print("FINAL OUTPUT SUMMARY")
    print("=" * 65)

    for filename in EXPECTED_FILES:
        count = count_nonempty_lines(os.path.join(OUT_DIR, filename))
        print(f"{filename:20s} {count:6d}")


# ============================================================
# MAIN
# ============================================================

def main():
    started = time.time()

    print("=" * 65)
    print("NUKCROW COLLECTOR")
    print(f"Telegram Collector: {'ENABLED' if TELEGRAM_ENABLED else 'DISABLED'}")
    print("=" * 65)

    os.makedirs(OUT_DIR, exist_ok=True)

    # --------------------------------------------------------
    # FETCH
    # --------------------------------------------------------

    raw = fetch_all()

    # --------------------------------------------------------
    # DEDUPE
    # --------------------------------------------------------

    general_unique = dedupe(raw["general"])
    telegram_unique = dedupe(raw["telegram"])
    iran_unique = dedupe(raw["iran"] + raw["telegram"])
    mci_unique = dedupe(raw["mci"])
    irancell_unique = dedupe(raw["irancell"])
    rightel_unique = dedupe(raw["rightel"])

    # Iran-oriented / fresh configs are tested first; the big general pool is
    # shuffled so a different random slice gets tested on every run.
    random.shuffle(general_unique)

    priority = dedupe(
        telegram_unique
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
    )

    all_unique = dedupe(priority + general_unique)

    print("\nUnique configs:")
    print(f"  General:   {len(general_unique)}")
    print(f"  Telegram:  {len(telegram_unique)}")
    print(f"  Iran:      {len(iran_unique)}")
    print(f"  MCI:       {len(mci_unique)}")
    print(f"  Irancell:  {len(irancell_unique)}")
    print(f"  Rightel:   {len(rightel_unique)}")
    print(f"  Global:    {len(all_unique)}")

    if len(all_unique) < GENERAL_TOTAL:
        raise RuntimeError(
            f"Not enough unique valid configs for all_configs.txt: "
            f"{len(all_unique)}/{GENERAL_TOTAL}"
        )

    # --------------------------------------------------------
    # BENCHMARK (one shared pass for every group)
    # --------------------------------------------------------

    alive_all = benchmark(all_unique)

    alive_map = {config_fingerprint(r["config"]): r for r in alive_all}

    alive_iran = subset_alive(alive_map, iran_unique)
    alive_mci = subset_alive(alive_map, mci_unique)
    alive_irancell = subset_alive(alive_map, irancell_unique)
    alive_rightel = subset_alive(alive_map, rightel_unique)

    print(f"Alive Iran: {len(alive_iran)} | Irancell: {len(alive_irancell)}")

    # --------------------------------------------------------
    # WRITE
    # --------------------------------------------------------

    write_general(alive_all, all_unique)

    write_iran(
        alive_iran, iran_unique,
        alive_mci, mci_unique,
        alive_irancell, irancell_unique,
        alive_rightel, rightel_unique,
        alive_all, all_unique,
    )

    write_protocols(alive_all, all_unique)

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    verify_outputs()
    print_source_summary()
    print_summary()

    print(f"\nDONE: {time.time() - started:.2f}s")


if __name__ == "__main__":
    main()
