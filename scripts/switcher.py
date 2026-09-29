import os
import re
import json
import time
import base64
import socket
import random
import ipaddress
import threading
import asyncio

from urllib.parse import urlparse, parse_qs, unquote
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

# =========================================================
# GENERAL
# =========================================================

GENERAL_SUB_SIZE = 1000
GENERAL_SUB_COUNT = 10
GENERAL_TOTAL = GENERAL_SUB_SIZE * GENERAL_SUB_COUNT

# =========================================================
# PROTOCOL
# =========================================================

PROTOCOL_SUB_SIZE = 100

# =========================================================
# IRAN
# =========================================================

IRAN_SUB_SIZE = 200

# =========================================================
# HOST DIVERSITY
# =========================================================

MAX_PER_HOST = 8

# =========================================================
# FETCH
# =========================================================

FETCH_WORKERS = 10
FETCH_TIMEOUT = 15
FETCH_RETRIES = 3
MAX_PER_SOURCE = 20000

# =========================================================
# TELEGRAM
# =========================================================

TELEGRAM_ENABLED = (
    os.getenv("TG_API_ID", "").strip()
    and os.getenv("TG_API_HASH", "").strip()
    and os.getenv("TG_SESSION", "").strip()
)

TELEGRAM_CHANNELS_FILE = os.getenv(
    "TELEGRAM_CHANNELS_FILE",
    "telegram_channels.txt",
)

TELEGRAM_MESSAGE_LIMIT = int(
    os.getenv(
        "TG_MESSAGE_LIMIT",
        "500",
    )
)

TELEGRAM_SUB_LINK_LIMIT = int(
    os.getenv(
        "TG_SUB_LINK_LIMIT",
        "100",
    )
)

TELEGRAM_FETCH_TIMEOUT = int(
    os.getenv(
        "TG_FETCH_TIMEOUT",
        "20",
    )
)

# =========================================================
# BENCHMARK
# =========================================================

MAX_TEST = 30000

BENCH_WORKERS = 100
BENCH_TIMEOUT = 1.8

SECOND_PASS = 8000
SECOND_PASS_WORKERS = 60
SECOND_PASS_TIMEOUT = 1.8

# =========================================================
# FALLBACK
# =========================================================

ALLOW_VALID_FALLBACK = True

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
# SOURCE TRACKING
# =========================================================

SOURCE_META = {}
SOURCE_META_LOCK = threading.Lock()

# =========================================================
# GENERAL SOURCES
# =========================================================

SOURCES_GENERAL = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
]

# =========================================================
# IRAN SOURCES
# =========================================================

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
# MCI
# =========================================================

SOURCES_MCI = []

# =========================================================
# IRANCELL
# =========================================================

SOURCES_IRANCELL = [
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt",
]

# =========================================================
# RIGHTEL
# =========================================================

SOURCES_RIGHTEL = []

# =========================================================
# THREAD LOCAL SESSION
# =========================================================

_thread_local = threading.local()


def session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()

        s.headers.update(
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

        _thread_local.session = s

    return _thread_local.session


# =========================================================
# BASE64
# =========================================================

def decode64(value):
    if not value:
        return ""

    value = str(value).strip()

    try:
        value = value.replace("-", "+")
        value = value.replace("_", "/")

        padding = len(value) % 4

        if padding:
            value += "=" * (4 - padding)

        return base64.b64decode(
            value,
            validate=False,
        ).decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:
        return ""


# =========================================================
# EXTRACT CONFIGS
# =========================================================

URI_PATTERN = re.compile(
    r"""(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>\[\]\{\}"'`]+""",
    re.IGNORECASE,
)


def normalize_config(config):
    if not config:
        return ""

    config = (
        str(config)
        .strip()
        .replace("\\/", "/")
    )

    config = unquote(config)

    config = config.split("#", 1)[0].strip()

    config = re.sub(
        r"\s+",
        "",
        config,
    )

    config = config.rstrip(
        ".,;)]}>"
    )

    return config


def extract_payload(text):
    if not text:
        return []

    text = str(text).replace(
        "\r",
        "",
    )

    output = []

    # -----------------------------------------------------
    # DIRECT URI
    # -----------------------------------------------------

    for match in URI_PATTERN.findall(text):
        config = normalize_config(match)

        if config:
            output.append(config)

    # -----------------------------------------------------
    # WHOLE FILE BASE64
    # -----------------------------------------------------

    decoded = decode64(text)

    if decoded:
        for match in URI_PATTERN.findall(
            decoded
        ):
            config = normalize_config(match)

            if config:
                output.append(config)

    # -----------------------------------------------------
    # BASE64 PER LINE
    # -----------------------------------------------------

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if "://" in line:
            continue

        if len(line) < 20:
            continue

        decoded_line = decode64(line)

        if not decoded_line:
            continue

        for match in URI_PATTERN.findall(
            decoded_line
        ):
            config = normalize_config(match)

            if config:
                output.append(config)

    return output


# =========================================================
# SOURCE TRACKING
# =========================================================

def register_source(
    config,
    source,
):
    if not config or not source:
        return

    fp = fingerprint(config)

    with SOURCE_META_LOCK:
        SOURCE_META.setdefault(
            fp,
            set(),
        ).add(
            str(source)
        )


def source_for_config(config):
    fp = fingerprint(config)

    with SOURCE_META_LOCK:
        sources = SOURCE_META.get(
            fp,
            set(),
        )

    return sorted(
        sources
    )


# =========================================================
# FETCH SOURCE
# =========================================================

def fetch_source(
    url,
    source_name=None,
):
    source_name = (
        source_name
        or url
    )

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
                )[
                    :MAX_PER_SOURCE
                ]

                for config in configs:
                    register_source(
                        config,
                        source_name,
                    )

                return configs

        except Exception:
            pass

        if attempt < FETCH_RETRIES:
            time.sleep(0.5)

    return []


# =========================================================
# FETCH GROUP
# =========================================================

def fetch_group(
    name,
    sources,
):
    if not sources:
        print(
            f"\n[FETCH] {name} (0 sources)"
        )
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
                url,
                f"{name.lower()}:{url}",
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

            except Exception as exc:
                print(
                    f"  [-] {url} "
                    f"| {type(exc).__name__}"
                )

    return results


# =========================================================
# TELEGRAM CHANNEL LIST
# =========================================================

def load_telegram_channels():
    channels = []

    env_channels = os.getenv(
        "TELEGRAM_CHANNELS",
        "",
    ).strip()

    if env_channels:
        for value in re.split(
            r"[\s,;]+",
            env_channels,
        ):
            value = value.strip()

            if value:
                channels.append(
                    value
                )

    if os.path.isfile(
        TELEGRAM_CHANNELS_FILE
    ):
        try:
            with open(
                TELEGRAM_CHANNELS_FILE,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:

                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    if line.startswith(
                        "#"
                    ):
                        continue

                    channels.append(
                        line
                    )

        except Exception as exc:
            print(
                "[TELEGRAM] channel file "
                f"error: {exc}"
            )

    output = []

    seen = set()

    for channel in channels:
        channel = channel.strip()

        if not channel:
            continue

        if channel.startswith(
            "https://t.me/"
        ):
            channel = channel[
                len("https://t.me/"):
            ]

        elif channel.startswith(
            "http://t.me/"
        ):
            channel = channel[
                len("http://t.me/"):
            ]

        channel = channel.strip(
            "/ "
        )

        if channel.startswith("@"):
            channel = channel[1:]

        if (
            not channel
            or channel.startswith("+")
        ):
            continue

        key = channel.lower()

        if key in seen:
            continue

        seen.add(key)
        output.append(channel)

    return output


# =========================================================
# TELEGRAM URL EXTRACTION
# =========================================================

HTTP_URL_PATTERN = re.compile(
    r"https?://[^\s<>\[\]\{\}\"'`]+",
    re.IGNORECASE,
)


def clean_url(url):
    if not url:
        return ""

    url = (
        str(url)
        .strip()
        .rstrip(
            ".,;)]}>"
        )
    )

    return url


def looks_like_subscription_url(url):
    if not url:
        return False

    try:
        parsed_url = urlparse(
            url
        )

        if parsed_url.scheme not in {
            "http",
            "https",
        }:
            return False

        host = (
            parsed_url.hostname
            or ""
        ).lower()

        path = (
            parsed_url.path
            or ""
        ).lower()

        query = (
            parsed_url.query
            or ""
        ).lower()

        full = (
            host
            + " "
            + path
            + " "
            + query
        )

        keywords = (
            "sub",
            "config",
            "v2ray",
            "vmess",
            "vless",
            "trojan",
            "proxy",
            "clash",
            "subscription",
            "subscribe",
            "raw.githubusercontent",
            "githubusercontent",
        )

        return any(
            keyword in full
            for keyword in keywords
        )

    except Exception:
        return False


# =========================================================
# TELEGRAM COLLECTOR
# =========================================================

async def _telegram_collect_async(
    api_id,
    api_hash,
    session_string,
    channels,
):
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

    except ImportError:
        print(
            "[TELEGRAM] Telethon is not installed."
        )
        print(
            "[TELEGRAM] Install with: "
            "pip install telethon"
        )
        return []

    configs = []

    client = TelegramClient(
        StringSession(
            session_string
        ),
        int(api_id),
        api_hash,
        connection_retries=3,
        request_retries=3,
        retry_delay=2,
        auto_reconnect=True,
        flood_sleep_threshold=60,
        device_model="NukCrow Collector",
        system_version="GitHub Actions",
        app_version="1.0",
        lang_code="en",
        system_lang_code="en",
    )

    try:
        await client.connect()

        if not await client.is_user_authorized():
            print(
                "[TELEGRAM] Session is not authorized."
            )
            return []

        me = await client.get_me()

        username = getattr(
            me,
            "username",
            None,
        )

        print(
            "[TELEGRAM] connected as "
            f"{username or 'authorized user'}"
        )

        for channel in channels:
            print(
                f"\n[TELEGRAM] @{channel}"
            )

            try:
                entity = await client.get_entity(
                    channel
                )

                message_count = 0
                subscription_urls = []
                seen_urls = set()

                async for message in client.iter_messages(
                    entity,
                    limit=TELEGRAM_MESSAGE_LIMIT,
                ):
                    message_count += 1

                    text = (
                        getattr(
                            message,
                            "raw_text",
                            None,
                        )
                        or getattr(
                            message,
                            "message",
                            None,
                        )
                        or ""
                    )

                    if not text:
                        continue

                    # -------------------------------------
                    # DIRECT CONFIGS
                    # -------------------------------------

                    message_configs = extract_payload(
                        text
                    )

                    for config in message_configs:
                        register_source(
                            config,
                            f"telegram:@{channel}",
                        )

                    configs.extend(
                        message_configs
                    )

                    # -------------------------------------
                    # SUBSCRIPTION URLS
                    # -------------------------------------

                    urls = HTTP_URL_PATTERN.findall(
                        text
                    )

                    for raw_url in urls:
                        url = clean_url(
                            raw_url
                        )

                        if not looks_like_subscription_url(
                            url
                        ):
                            continue

                        key = url.lower()

                        if key in seen_urls:
                            continue

                        seen_urls.add(
                            key
                        )

                        if len(
                            subscription_urls
                        ) >= TELEGRAM_SUB_LINK_LIMIT:
                            break

                        subscription_urls.append(
                            url
                        )

                # -----------------------------------------
                # FETCH SUBSCRIPTION LINKS
                # -----------------------------------------

                if subscription_urls:
                    print(
                        "[TELEGRAM] subscription links: "
                        f"{len(subscription_urls)}"
                    )

                    for url in subscription_urls:
                        try:
                            sub_configs = fetch_source(
                                url,
                                (
                                    f"telegram:@{channel}"
                                    f":subscription:{url}"
                                ),
                            )

                            configs.extend(
                                sub_configs
                            )

                        except Exception as exc:
                            print(
                                "[TELEGRAM] subscription "
                                f"error: {type(exc).__name__}"
                            )

                print(
                    "[TELEGRAM] messages: "
                    f"{message_count} | "
                    "configs: "
                    f"{len(configs)}"
                )

            except Exception as exc:
                print(
                    f"[TELEGRAM] @{channel} "
                    f"failed: {type(exc).__name__}: "
                    f"{exc}"
                )

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    return configs


def fetch_telegram():
    if not TELEGRAM_ENABLED:
        print(
            "\n[TELEGRAM] disabled"
        )
        print(
            "[TELEGRAM] Set "
            "TG_API_ID, TG_API_HASH and "
            "TG_SESSION to enable it."
        )
        return []

    channels = load_telegram_channels()

    if not channels:
        print(
            "\n[TELEGRAM] enabled but "
            "no channels configured."
        )
        return []

    api_id = os.getenv(
        "TG_API_ID",
        "",
    ).strip()

    api_hash = os.getenv(
        "TG_API_HASH",
        "",
    ).strip()

    session_string = os.getenv(
        "TG_SESSION",
        "",
    ).strip()

    print(
        "\n[TELEGRAM] "
        f"{len(channels)} channels"
    )

    try:
        return asyncio.run(
            _telegram_collect_async(
                api_id,
                api_hash,
                session_string,
                channels,
            )
        )

    except Exception as exc:
        print(
            "[TELEGRAM] collector failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return []


# =========================================================
# FETCH ALL
# =========================================================

def fetch_all():
    telegram_configs = fetch_telegram()

    return {
        "general": fetch_group(
            "GENERAL",
            SOURCES_GENERAL,
        ),

        "iran": fetch_group(
            "IRAN",
            SOURCES_IRAN,
        ),

        "mci": fetch_group(
            "MCI",
            SOURCES_MCI,
        ),

        "irancell": fetch_group(
            "IRANCELL",
            SOURCES_IRANCELL,
        ),

        "rightel": fetch_group(
            "RIGHTEL",
            SOURCES_RIGHTEL,
        ),

        "telegram": telegram_configs,
    }


# =========================================================
# PROTOCOL
# =========================================================

def proto(config):
    try:
        return (
            config
            .split(
                "://",
                1,
            )[0]
            .lower()
            .strip()
        )

    except Exception:
        return ""


# =========================================================
# PARSE
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
            keep_blank_values=True,
        )

    except Exception:
        return {}


def q1(
    q,
    key,
    default="",
):
    value = q.get(
        key
    )

    if not value:
        return default

    if isinstance(
        value,
        list,
    ):
        return value[0]

    return str(value)


# =========================================================
# VMESS DATA
# =========================================================

def vmess_data(config):
    if proto(config) != "vmess":
        return {}

    try:
        payload = config.split(
            "://",
            1,
        )[1]

    except Exception:
        return {}

    decoded = decode64(
        payload
    )

    if not decoded:
        return {}

    try:
        data = json.loads(
            decoded
        )

        if not isinstance(
            data,
            dict,
        ):
            return {}

        return data

    except Exception:
        return {}


# =========================================================
# SS DATA
# =========================================================

def ss_data(config):
    if proto(config) != "ss":
        return {}

    p = parsed(config)

    # -----------------------------------------------------
    # SIP002 / NORMAL SS
    # -----------------------------------------------------

    if p:
        try:
            if (
                p.hostname
                and p.port
            ):
                return {
                    "host": p.hostname,
                    "port": p.port,
                    "username": (
                        p.username
                        or ""
                    ),
                    "password": (
                        p.password
                        or ""
                    ),
                }

        except Exception:
            pass

    # -----------------------------------------------------
    # BASE64 SS
    # -----------------------------------------------------

    try:
        payload = config.split(
            "://",
            1,
        )[1]

    except Exception:
        return {}

    payload = payload.split(
        "#",
        1,
    )[0]

    decoded = decode64(
        payload
    )

    if not decoded:
        return {}

    decoded = decoded.strip()

    try:
        if "://" not in decoded:
            decoded = (
                "ss://"
                + decoded
            )

        p2 = urlparse(
            decoded
        )

        host = (
            p2.hostname
            or ""
        )

        try:
            port = p2.port or 0

        except Exception:
            port = 0

        if (
            host
            and port
        ):
            return {
                "host": host,
                "port": port,
                "username": (
                    p2.username
                    or ""
                ),
                "password": (
                    p2.password
                    or ""
                ),
            }

    except Exception:
        pass

    return {}


# =========================================================
# ENDPOINT
# =========================================================

def endpoint(config):
    ptype = proto(config)

    # -----------------------------------------------------
    # VMESS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(
            config
        )

        host = (
            data.get("add")
            or data.get("address")
            or ""
        )

        port = (
            data.get("port")
            or 0
        )

        try:
            port = int(
                port
            )

        except Exception:
            port = 0

        return (
            str(
                host
            ).strip().lower(),
            port,
        )

    # -----------------------------------------------------
    # SS
    # -----------------------------------------------------

    if ptype == "ss":
        data = ss_data(
            config
        )

        host = str(
            data.get(
                "host",
                "",
            )
        ).strip().lower()

        try:
            port = int(
                data.get(
                    "port",
                    0,
                )
            )

        except Exception:
            port = 0

        return (
            host,
            port,
        )

    # -----------------------------------------------------
    # VLESS / TROJAN / HY2
    # -----------------------------------------------------

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
        port = p.port or 0

    except Exception:
        port = 0

    return (
        host.lower().strip(),
        port,
    )


# =========================================================
# HOST CHECK
# =========================================================

def is_junk_host(host):
    if not host:
        return True

    h = (
        host
        .lower()
        .strip()
    )

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

def valid_config(config):
    if not config:
        return False

    ptype = proto(
        config
    )

    if ptype not in SUPPORTED_PROTOCOLS:
        return False

    # -----------------------------------------------------
    # VMESS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(
            config
        )

        if not data:
            return False

        host = (
            data.get("add")
            or data.get("address")
            or ""
        )

        port = (
            data.get("port")
            or 0
        )

        try:
            port = int(
                port
            )

        except Exception:
            return False

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

        vmess_id = (
            data.get("id")
            or data.get("uuid")
            or ""
        )

        if not vmess_id:
            return False

        return True

    # -----------------------------------------------------
    # SS
    # -----------------------------------------------------

    if ptype == "ss":
        data = ss_data(
            config
        )

        host = data.get(
            "host",
            "",
        )

        port = data.get(
            "port",
            0,
        )

        if not host:
            return False

        if is_junk_host(
            host
        ):
            return False

        try:
            port = int(
                port
            )

        except Exception:
            return False

        if not (
            1 <= port <= 65535
        ):
            return False

        return True

    # -----------------------------------------------------
    # OTHER
    # -----------------------------------------------------

    p = parsed(
        config
    )

    if not p:
        return False

    host, port = endpoint(
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

    # -----------------------------------------------------
    # VLESS
    # -----------------------------------------------------

    if ptype == "vless":
        if not p.username:
            return False

        if len(
            p.username
        ) < 8:
            return False

    # -----------------------------------------------------
    # TROJAN
    # -----------------------------------------------------

    elif ptype == "trojan":
        if not p.username:
            return False

    # -----------------------------------------------------
    # HYSTERIA2
    # -----------------------------------------------------

    elif ptype in {
        "hysteria2",
        "hy2",
    }:
        if not p.username:
            return False

    return True


# =========================================================
# IDENTITY
# =========================================================

def config_identity(config):
    ptype = proto(
        config
    )

    # VMESS
    if ptype == "vmess":
        data = vmess_data(
            config
        )

        return str(
            data.get("id")
            or data.get("uuid")
            or ""
        ).strip().lower()

    # SS
    if ptype == "ss":
        data = ss_data(
            config
        )

        return str(
            data.get("username")
            or data.get("password")
            or ""
        ).strip().lower()

    # URL protocols
    p = parsed(
        config
    )

    if not p:
        return ""

    return str(
        p.username
        or ""
    ).strip().lower()


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

    host, port = endpoint(
        config
    )

    security = q1(
        q,
        "security",
        q1(
            q,
            "tls",
        ),
    )

    transport = q1(
        q,
        "type",
        q1(
            q,
            "network",
        ),
    )

    sni = q1(
        q,
        "sni",
        q1(
            q,
            "peer",
        ),
    )

    host_header = q1(
        q,
        "host",
    )

    path = q1(
        q,
        "path",
    )

    service_name = q1(
        q,
        "serviceName",
    )

    pbk = q1(
        q,
        "pbk",
    )

    sid = q1(
        q,
        "sid",
    )

    flow = q1(
        q,
        "flow",
    )

    fpmi = q1(
        q,
        "fp",
    )

    identity = config_identity(
        config
    )

    # -----------------------------------------------------
    # VMESS FIELDS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(
            config
        )

        transport = (
            data.get("net")
            or data.get("type")
            or transport
            or ""
        )

        security = (
            data.get("tls")
            or security
            or ""
        )

        sni = (
            data.get("sni")
            or data.get("host")
            or sni
            or ""
        )

        path = (
            data.get("path")
            or path
            or ""
        )

        flow = (
            data.get("flow")
            or flow
            or ""
        )

        fpmi = (
            data.get("fp")
            or fpmi
            or ""
        )

    return "|".join(
        str(x)
        .strip()
        .lower()
        for x in (
            ptype,
            host,
            port,
            identity,
            security,
            transport,
            sni,
            host_header,
            path,
            service_name,
            pbk,
            sid,
            flow,
            fpmi,
        )
    )


# =========================================================
# DEDUPE
# =========================================================

def dedupe(configs):
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

def quality_score(config):
    score = 0

    ptype = proto(
        config
    )

    q = query(
        config
    )

    host, port = endpoint(
        config
    )

    # -----------------------------------------------------
    # PROTOCOL
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # VMESS
    # -----------------------------------------------------

    if ptype == "vmess":
        data = vmess_data(
            config
        )

        transport = str(
            data.get("net")
            or data.get("type")
            or ""
        ).lower()

        security = str(
            data.get("tls")
            or ""
        ).lower()

        sni = str(
            data.get("sni")
            or data.get("host")
            or ""
        )

        path = str(
            data.get("path")
            or ""
        )

    else:
        transport = q1(
            q,
            "type",
            q1(
                q,
                "network",
            ),
        ).lower()

        security = q1(
            q,
            "security",
        ).lower()

        sni = q1(
            q,
            "sni",
        )

        path = q1(
            q,
            "path",
        )

    # -----------------------------------------------------
    # TRANSPORT
    # -----------------------------------------------------

    if transport in PREFERRED_TYPES:
        score += 20

    # -----------------------------------------------------
    # TLS / REALITY
    # -----------------------------------------------------

    if security in {
        "tls",
        "reality",
    }:
        score += 15

    if sni:
        score += 10

    # -----------------------------------------------------
    # PORT
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # HOST
    # -----------------------------------------------------

    if host:
        try:
            ipaddress.ip_address(
                host
            )

            score += 2

        except Exception:
            if "." in host:
                score += 8

    # -----------------------------------------------------
    # PATH
    # -----------------------------------------------------

    if path:
        score += 5

    if q1(
        q,
        "serviceName",
    ):
        score += 4

    # -----------------------------------------------------
    # REALITY
    # -----------------------------------------------------

    if q1(
        q,
        "pbk",
    ):
        score += 6

    if q1(
        q,
        "sid",
    ):
        score += 3

    return score


# =========================================================
# TCP PROBE
# =========================================================

def tcp_probe(item):
    config, timeout = item

    host, port = endpoint(
        config
    )

    if not host or not port:
        return None

    start = time.perf_counter()

    try:
        with socket.create_connection(
            (
                host,
                port,
            ),
            timeout=timeout,
        ):
            latency = (
                time.perf_counter()
                - start
            )

            return (
                config,
                latency,
            )

    except Exception:
        return None


# =========================================================
# BENCHMARK
# =========================================================

def _benchmark_pass(
    configs,
    workers,
    timeout,
):
    results = []

    if not configs:
        return results

    with ThreadPoolExecutor(
        max_workers=workers
    ) as executor:

        futures = [
            executor.submit(
                tcp_probe,
                (
                    config,
                    timeout,
                ),
            )
            for config in configs
        ]

        for future in as_completed(
            futures
        ):
            try:
                result = future.result()

                if result:
                    config, latency = result

                    results.append(
                        {
                            "config": config,
                            "latency": latency,
                            "score": quality_score(
                                config
                            ),
                        }
                    )

            except Exception:
                pass

    return results


def benchmark(configs):
    if not configs:
        return []

    candidates = configs[
        :MAX_TEST
    ]

    print(
        f"\n[BENCH] testing "
        f"{len(candidates)} configs..."
    )

    results = _benchmark_pass(
        candidates,
        BENCH_WORKERS,
        BENCH_TIMEOUT,
    )

    # -----------------------------------------------------
    # SECOND PASS
    # -----------------------------------------------------

    if len(results) < SECOND_PASS:
        remaining = configs[
            MAX_TEST:
            MAX_TEST + SECOND_PASS
        ]

        if remaining:
            print(
                f"[BENCH] second pass: "
                f"{len(remaining)} configs"
            )

            results.extend(
                _benchmark_pass(
                    remaining,
                    SECOND_PASS_WORKERS,
                    SECOND_PASS_TIMEOUT,
                )
            )

    # -----------------------------------------------------
    # DEDUPE ALIVE
    # -----------------------------------------------------

    unique = {}

    for item in results:
        fp = fingerprint(
            item["config"]
        )

        old = unique.get(
            fp
        )

        if old is None:
            unique[fp] = item
            continue

        new_key = (
            item["score"],
            -item["latency"],
        )

        old_key = (
            old["score"],
            -old["latency"],
        )

        if new_key > old_key:
            unique[fp] = item

    results = list(
        unique.values()
    )

    results.sort(
        key=lambda x: (
            -x["score"],
            x["latency"],
        )
    )

    print(
        f"[BENCH] alive: "
        f"{len(results)}"
    )

    return results


# =========================================================
# RECORD
# =========================================================

def config_record(config):
    return {
        "config": config,
        "latency": 999.0,
        "score": quality_score(
            config
        ),
    }


def records_from_configs(
    configs
):
    return [
        config_record(
            config
        )
        for config in configs
    ]


# =========================================================
# MERGE
# =========================================================

def merge_records(
    alive_records,
    valid_configs,
):
    output = []
    seen = set()

    # -----------------------------------------------------
    # ALIVE FIRST
    # -----------------------------------------------------

    for item in alive_records:
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

        output.append(
            item
        )

    # -----------------------------------------------------
    # VALID FALLBACK
    # -----------------------------------------------------

    if ALLOW_VALID_FALLBACK:
        fallback_records = records_from_configs(
            valid_configs
        )

        fallback_records.sort(
            key=lambda x: -x[
                "score"
            ]
        )

        for item in fallback_records:
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

            output.append(
                item
            )

    return output


# =========================================================
# SELECT
# =========================================================

def select_records(
    results,
    limit,
    predicate=None,
):
    if (
        not results
        or limit <= 0
    ):
        return []

    selected = []
    seen = set()
    host_count = {}

    for item in results:
        if len(
            selected
        ) >= limit:
            break

        config = item[
            "config"
        ]

        if (
            predicate
            and not predicate(
                config
            )
        ):
            continue

        fp = fingerprint(
            config
        )

        if fp in seen:
            continue

        host, _ = endpoint(
            config
        )

        if not host:
            continue

        if (
            host_count.get(
                host,
                0,
            )
            >= MAX_PER_HOST
        ):
            continue

        selected.append(
            item
        )

        seen.add(
            fp
        )

        host_count[
            host
        ] = (
            host_count.get(
                host,
                0,
            )
            + 1
        )

    return selected[
        :limit
    ]


# =========================================================
# SELECT SUBSCRIPTION
# =========================================================

def select_subscription(
    alive_records,
    valid_configs,
    limit,
    predicate=None,
):
    combined = merge_records(
        alive_records,
        valid_configs,
    )

    return select_records(
        combined,
        limit,
        predicate=predicate,
    )


# =========================================================
# REMARK
# =========================================================

def config_line(config):
    config = normalize_config(
        config
    )

    if not config:
        return ""

    config = config.split(
        "#",
        1,
    )[0].strip()

    if not config:
        return ""

    return (
        config
        + "#"
        + REMARK
    )


# =========================================================
# RENDER UNIQUE LINES
# =========================================================

def render_records(
    records,
    limit=None,
):
    lines = []
    seen = set()

    for item in records:
        if isinstance(
            item,
            dict,
        ):
            config = item.get(
                "config",
                "",
            )
        else:
            config = str(
                item
            )

        config = normalize_config(
            config
        )

        if not config:
            continue

        if not valid_config(
            config
        ):
            continue

        line = config_line(
            config
        )

        if not line:
            continue

        if line in seen:
            continue

        seen.add(
            line
        )

        lines.append(
            line
        )

        if (
            limit is not None
            and len(lines)
            >= limit
        ):
            break

    return lines


# =========================================================
# ATOMIC WRITE
# =========================================================

def atomic_write_lines(
    path,
    lines,
):
    directory = os.path.dirname(
        path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    temp_path = (
        path
        + ".tmp"
    )

    with open(
        temp_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for line in lines:
            line = str(
                line
            ).strip()

            if line:
                f.write(
                    line
                    + "\n"
                )

        f.flush()

        try:
            os.fsync(
                f.fileno()
            )
        except Exception:
            pass

    os.replace(
        temp_path,
        path,
    )


# =========================================================
# COUNT REAL FILE
# =========================================================

def count_nonempty_lines(
    path
):
    if not os.path.isfile(
        path
    ):
        return 0

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        return sum(
            1
            for line in f
            if line.strip()
        )


# =========================================================
# WRITE FILE
# =========================================================

def write_file(
    path,
    records,
    limit=None,
    exact=False,
):
    lines = render_records(
        records,
        limit=limit,
    )

    if (
        exact
        and limit is not None
        and len(lines) != limit
    ):
        raise RuntimeError(
            f"{path}: cannot write exact "
            f"{limit}; only {len(lines)} "
            f"valid unique configs available"
        )

    atomic_write_lines(
        path,
        lines,
    )

    actual = count_nonempty_lines(
        path
    )

    if actual != len(lines):
        raise RuntimeError(
            f"{path}: write verification "
            f"failed: expected {len(lines)}, "
            f"got {actual}"
        )

    target = (
        f"/{limit}"
        if limit is not None
        else ""
    )

    print(
        f"[WRITE] "
        f"{os.path.basename(path)} "
        f"-> {actual}{target}"
    )

    return actual


# =========================================================
# GENERAL
# =========================================================

def write_general(
    alive_all,
    all_unique,
):
    print(
        "\n[GENERAL]"
    )

    selected = select_subscription(
        alive_all,
        all_unique,
        GENERAL_TOTAL,
    )

    if len(
        selected
    ) < GENERAL_TOTAL:
        raise RuntimeError(
            f"[GENERAL] only "
            f"{len(selected)} configs available; "
            f"{GENERAL_TOTAL} required"
        )

    selected = selected[
        :GENERAL_TOTAL
    ]

    lines = render_records(
        selected,
        GENERAL_TOTAL,
    )

    if len(lines) != GENERAL_TOTAL:
        raise RuntimeError(
            f"[GENERAL] render produced "
            f"{len(lines)} configs; "
            f"expected {GENERAL_TOTAL}"
        )

    # -----------------------------------------------------
    # ALL CONFIGS
    # -----------------------------------------------------

    all_path = os.path.join(
        OUT_DIR,
        "all_configs.txt",
    )

    atomic_write_lines(
        all_path,
        lines,
    )

    actual_all = count_nonempty_lines(
        all_path
    )

    if actual_all != GENERAL_TOTAL:
        raise RuntimeError(
            f"{all_path}: expected "
            f"{GENERAL_TOTAL}, "
            f"got {actual_all}"
        )

    print(
        f"[WRITE] all_configs.txt -> "
        f"{actual_all}/{GENERAL_TOTAL}"
    )

    # -----------------------------------------------------
    # SUB1 ... SUB10
    # -----------------------------------------------------

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

        chunk = lines[
            start:end
        ]

        if len(chunk) != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"[GENERAL] sub{index + 1}: "
                f"expected {GENERAL_SUB_SIZE}, "
                f"got {len(chunk)}"
            )

        path = os.path.join(
            OUT_DIR,
            f"sub{index + 1}.txt",
        )

        atomic_write_lines(
            path,
            chunk,
        )

        actual = count_nonempty_lines(
            path
        )

        if actual != GENERAL_SUB_SIZE:
            raise RuntimeError(
                f"{path}: expected "
                f"{GENERAL_SUB_SIZE}, "
                f"got {actual}"
            )

        print(
            f"[WRITE] sub{index + 1}.txt -> "
            f"{actual}/{GENERAL_SUB_SIZE}"
        )

    # -----------------------------------------------------
    # FINAL CROSS CHECK
    # -----------------------------------------------------

    combined = []

    for index in range(
        1,
        GENERAL_SUB_COUNT + 1,
    ):
        path = os.path.join(
            OUT_DIR,
            f"sub{index}.txt",
        )

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:

            combined.extend(
                line.strip()
                for line in f
                if line.strip()
            )

    if len(
        combined
    ) != GENERAL_TOTAL:
        raise RuntimeError(
            f"[GENERAL] sub files contain "
            f"{len(combined)} configs; "
            f"expected {GENERAL_TOTAL}"
        )

    if combined != lines:
        raise RuntimeError(
            "[GENERAL] sub1..sub10 do not "
            "exactly match all_configs.txt"
        )

    print(
        "[GENERAL] "
        "all_configs.txt == "
        "sub1 + ... + sub10"
    )


# =========================================================
# PROTOCOLS
# =========================================================

def write_protocols(
    alive_all,
    all_unique,
):
    print(
        "\n[PROTOCOLS]"
    )

    protocols = (
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    )

    for ptype in protocols:
        selected = select_subscription(
            alive_all,
            all_unique,
            PROTOCOL_SUB_SIZE,
            predicate=lambda c, p=ptype:
                proto(c) == p,
        )

        selected = [
            item
            for item in selected
            if proto(
                item["config"]
            ) == ptype
        ]

        selected = selected[
            :PROTOCOL_SUB_SIZE
        ]

        path = os.path.join(
            OUT_DIR,
            f"{ptype}.txt",
        )

        count = write_file(
            path,
            selected,
            limit=PROTOCOL_SUB_SIZE,
            exact=False,
        )

        print(
            f"  {ptype:<10} "
            f"{count:>4}/{PROTOCOL_SUB_SIZE}"
        )


# =========================================================
# FILL EXACT LIMIT
# =========================================================

def fill_records(
    primary,
    fallback_groups,
    limit,
):
    if limit <= 0:
        return []

    selected = []
    seen = set()
    host_count = {}

    pools = [
        primary,
        *fallback_groups,
    ]

    for pool in pools:
        for item in pool:
            if len(
                selected
            ) >= limit:
                break

            config = item[
                "config"
            ]

            fp = fingerprint(
                config
            )

            if fp in seen:
                continue

            host, _ = endpoint(
                config
            )

            if not host:
                continue

            if (
                host_count.get(
                    host,
                    0,
                )
                >= MAX_PER_HOST
            ):
                continue

            seen.add(
                fp
            )

            selected.append(
                item
            )

            host_count[
                host
            ] = (
                host_count.get(
                    host,
                    0,
                )
                + 1
            )

        if len(
            selected
        ) >= limit:
            break

    return selected[
        :limit
    ]


# =========================================================
# IRAN
# =========================================================

def write_iran(
    iran_alive,
    iran_unique,
    mci_alive,
    mci_unique,
    irancell_alive,
    irancell_unique,
    rightel_alive,
    rightel_unique,
    all_alive,
    all_unique,
):
    global_records = merge_records(
        all_alive,
        all_unique,
    )

    iran_records = merge_records(
        iran_alive,
        iran_unique,
    )

    mci_records = merge_records(
        mci_alive,
        mci_unique,
    )

    irancell_records = merge_records(
        irancell_alive,
        irancell_unique,
    )

    rightel_records = merge_records(
        rightel_alive,
        rightel_unique,
    )

    # -----------------------------------------------------
    # BEST IRAN
    # -----------------------------------------------------

    best_iran = fill_records(
        iran_records,
        [
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(
        best_iran
    ) != IRAN_SUB_SIZE:
        raise RuntimeError(
            f"best_iran.txt: expected "
            f"{IRAN_SUB_SIZE}, "
            f"got {len(best_iran)}"
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "best_iran.txt",
        ),
        best_iran,
        limit=IRAN_SUB_SIZE,
        exact=True,
    )

    # -----------------------------------------------------
    # MIX IRAN
    # -----------------------------------------------------

    mix_iran_pool = (
        iran_records
        + global_records
    )

    random.shuffle(
        mix_iran_pool
    )

    mix_iran = select_records(
        mix_iran_pool,
        IRAN_SUB_SIZE,
    )

    if len(
        mix_iran
    ) < IRAN_SUB_SIZE:
        mix_iran = fill_records(
            mix_iran,
            [
                iran_records,
                global_records,
            ],
            IRAN_SUB_SIZE,
        )

    if len(
        mix_iran
    ) != IRAN_SUB_SIZE:
        raise RuntimeError(
            f"mix_iran.txt: expected "
            f"{IRAN_SUB_SIZE}, "
            f"got {len(mix_iran)}"
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "mix_iran.txt",
        ),
        mix_iran,
        limit=IRAN_SUB_SIZE,
        exact=True,
    )

    # -----------------------------------------------------
    # MCI
    # -----------------------------------------------------

    mci = fill_records(
        mci_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(
        mci
    ) != IRAN_SUB_SIZE:
        raise RuntimeError(
            f"mci.txt: expected "
            f"{IRAN_SUB_SIZE}, "
            f"got {len(mci)}"
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "mci.txt",
        ),
        mci,
        limit=IRAN_SUB_SIZE,
        exact=True,
    )

    # -----------------------------------------------------
    # IRANCELL
    # -----------------------------------------------------

    irancell = fill_records(
        irancell_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(
        irancell
    ) != IRAN_SUB_SIZE:
        raise RuntimeError(
            f"irancell.txt: expected "
            f"{IRAN_SUB_SIZE}, "
            f"got {len(irancell)}"
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "irancell.txt",
        ),
        irancell,
        limit=IRAN_SUB_SIZE,
        exact=True,
    )

    # -----------------------------------------------------
    # RIGHTEL
    # -----------------------------------------------------

    rightel = fill_records(
        rightel_records,
        [
            iran_records,
            global_records,
        ],
        IRAN_SUB_SIZE,
    )

    if len(
        rightel
    ) != IRAN_SUB_SIZE:
        raise RuntimeError(
            f"rightel.txt: expected "
            f"{IRAN_SUB_SIZE}, "
            f"got {len(rightel)}"
        )

    write_file(
        os.path.join(
            OUT_DIR,
            "rightel.txt",
        ),
        rightel,
        limit=IRAN_SUB_SIZE,
        exact=True,
    )

    print(
        "\n[IRAN]"
    )

    print(
        f"  best_iran : "
        f"{len(best_iran)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"  mix_iran  : "
        f"{len(mix_iran)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"  mci       : "
        f"{len(mci)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"  irancell  : "
        f"{len(irancell)}/{IRAN_SUB_SIZE}"
    )

    print(
        f"  rightel   : "
        f"{len(rightel)}/{IRAN_SUB_SIZE}"
    )


# =========================================================
# VERIFY SINGLE FILE
# =========================================================

def verify_output_file(
    path,
    expected_max=None,
    expected_exact=None,
):
    if not os.path.isfile(
        path
    ):
        raise RuntimeError(
            f"Missing output file: {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        raw_lines = f.readlines()

    # -----------------------------------------------------
    # EMPTY LINES
    # -----------------------------------------------------

    for line_no, line in enumerate(
        raw_lines,
        start=1,
    ):
        if not line.strip():
            raise RuntimeError(
                f"{path}: empty line at "
                f"line {line_no}"
            )

    lines = [
        line.strip()
        for line in raw_lines
    ]

    count = len(
        lines
    )

    # -----------------------------------------------------
    # EXACT
    # -----------------------------------------------------

    if expected_exact is not None:
        if count != expected_exact:
            raise RuntimeError(
                f"{path}: expected "
                f"{expected_exact}, "
                f"got {count}"
            )

    # -----------------------------------------------------
    # MAX
    # -----------------------------------------------------

    if expected_max is not None:
        if count > expected_max:
            raise RuntimeError(
                f"{path}: maximum "
                f"{expected_max}, "
                f"got {count}"
            )

    # -----------------------------------------------------
    # DUPLICATES
    # -----------------------------------------------------

    if len(
        lines
    ) != len(
        set(lines)
    ):
        raise RuntimeError(
            f"{path}: duplicate config detected"
        )

    # -----------------------------------------------------
    # REMARK
    # -----------------------------------------------------

    expected_remark = (
        "#"
        + REMARK
    )

    for line in lines:
        if not line.endswith(
            expected_remark
        ):
            raise RuntimeError(
                f"{path}: invalid remark: "
                f"{line[-50:]}"
            )

        if line.count("#") != 1:
            raise RuntimeError(
                f"{path}: invalid fragment/remark: "
                f"{line}"
            )

    return count


# =========================================================
# VERIFY ALL OUTPUTS
# =========================================================

def verify_outputs():
    print(
        "\n[VERIFY OUTPUTS]"
    )

    # -----------------------------------------------------
    # random_200 MUST NOT EXIST
    # -----------------------------------------------------

    random_path = os.path.join(
        OUT_DIR,
        "random_200.txt",
    )

    if os.path.exists(
        random_path
    ):
        raise RuntimeError(
            "random_200.txt must NOT exist"
        )

    # -----------------------------------------------------
    # EXPECTED FILES
    # -----------------------------------------------------

    expected_files = {
        "all_configs.txt",
        *{
            f"sub{i}.txt"
            for i in range(
                1,
                GENERAL_SUB_COUNT + 1,
            )
        },
        "vless.txt",
        "vmess.txt",
        "trojan.txt",
        "ss.txt",
        "hysteria2.txt",
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
    }

    actual_files = {
        filename
        for filename in os.listdir(
            OUT_DIR
        )
        if filename.endswith(
            ".txt"
        )
    }

    unexpected = (
        actual_files
        - expected_files
    )

    missing = (
        expected_files
        - actual_files
    )

    if missing:
        raise RuntimeError(
            "Missing output files: "
            + ", ".join(
                sorted(
                    missing
                )
            )
        )

    if unexpected:
        raise RuntimeError(
            "Unexpected output files: "
            + ", ".join(
                sorted(
                    unexpected
                )
            )
        )

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    verify_output_file(
        os.path.join(
            OUT_DIR,
            "all_configs.txt",
        ),
        expected_exact=GENERAL_TOTAL,
    )

    sub_lines = []

    for i in range(
        1,
        GENERAL_SUB_COUNT + 1,
    ):
        path = os.path.join(
            OUT_DIR,
            f"sub{i}.txt",
        )

        verify_output_file(
            path,
            expected_exact=GENERAL_SUB_SIZE,
        )

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            sub_lines.extend(
                line.strip()
                for line in f
                if line.strip()
            )

    # -----------------------------------------------------
    # ALL CONFIGS VS SUBS
    # -----------------------------------------------------

    all_path = os.path.join(
        OUT_DIR,
        "all_configs.txt",
    )

    with open(
        all_path,
        "r",
        encoding="utf-8",
    ) as f:

        all_lines = [
            line.strip()
            for line in f
        ]

    if len(
        all_lines
    ) != GENERAL_TOTAL:
        raise RuntimeError(
            f"all_configs.txt: expected "
            f"{GENERAL_TOTAL}, "
            f"got {len(all_lines)}"
        )

    if len(
        sub_lines
    ) != GENERAL_TOTAL:
        raise RuntimeError(
            f"sub1..sub10 total: expected "
            f"{GENERAL_TOTAL}, "
            f"got {len(sub_lines)}"
        )

    if sub_lines != all_lines:
        raise RuntimeError(
            "all_configs.txt does not exactly "
            "match sub1.txt + ... + sub10.txt"
        )

    # -----------------------------------------------------
    # PROTOCOLS
    # -----------------------------------------------------

    protocol_files = (
        "vless",
        "vmess",
        "trojan",
        "ss",
        "hysteria2",
    )

    for ptype in protocol_files:
        path = os.path.join(
            OUT_DIR,
            f"{ptype}.txt",
        )

        count = verify_output_file(
            path,
            expected_max=PROTOCOL_SUB_SIZE,
        )

        if count < 1:
            raise RuntimeError(
                f"{ptype}.txt is empty"
            )

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as f:

            for line_no, line in enumerate(
                f,
                start=1,
            ):
                config = line.strip()

                clean = config.rsplit(
                    "#",
                    1,
                )[0]

                if proto(
                    clean
                ) != ptype:
                    raise RuntimeError(
                        f"{ptype}.txt line "
                        f"{line_no}: contains "
                        f"another protocol"
                    )

                if not valid_config(
                    clean
                ):
                    raise RuntimeError(
                        f"{ptype}.txt line "
                        f"{line_no}: invalid "
                        f"configuration"
                    )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    iran_files = (
        "best_iran.txt",
        "mix_iran.txt",
        "mci.txt",
        "irancell.txt",
        "rightel.txt",
    )

    for filename in iran_files:
        verify_output_file(
            os.path.join(
                OUT_DIR,
                filename,
            ),
            expected_exact=IRAN_SUB_SIZE,
        )

    print(
        "[VERIFY] all output files are valid"
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
        "NUKCROW SUBSCRIPTIONS"
    )

    print(
        "=" * 65
    )

    if not os.path.isdir(
        OUT_DIR
    ):
        return

    files = sorted(
        filename
        for filename in os.listdir(
            OUT_DIR
        )
        if filename.endswith(
            ".txt"
        )
    )

    for filename in files:
        path = os.path.join(
            OUT_DIR,
            filename,
        )

        try:
            count = count_nonempty_lines(
                path
            )

            print(
                f"{filename:<25}"
                f"{count:>6}"
            )

        except Exception:
            pass

    print(
        "=" * 65
    )


# =========================================================
# SOURCE SUMMARY
# =========================================================

def print_source_summary():
    if not SOURCE_META:
        return

    unique_sources = set()

    for sources in SOURCE_META.values():
        unique_sources.update(
            sources
        )

    print(
        "\n[SOURCES]"
    )

    print(
        f"Unique source references: "
        f"{len(unique_sources)}"
    )

    source_counter = {}

    for sources in SOURCE_META.values():
        for source in sources:
            source_counter[
                source
            ] = (
                source_counter.get(
                    source,
                    0,
                )
                + 1
            )

    top_sources = sorted(
        source_counter.items(),
        key=lambda x: -x[1],
    )[:20]

    for source, count in top_sources:
        print(
            f"  {count:>6} "
            f"| {source}"
        )


# =========================================================
# MAIN
# =========================================================

def main():
    started = time.time()

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
        exist_ok=True,
    )

    # -----------------------------------------------------
    # FETCH
    # -----------------------------------------------------

    raw = fetch_all()

    # -----------------------------------------------------
    # TELEGRAM MERGE
    # -----------------------------------------------------

    general_raw = (
        raw["general"]
        + raw["telegram"]
    )

    iran_raw = raw[
        "iran"
    ]

    # Telegram is global by default.
    # Its configs can participate in Iran fallback.
    telegram_raw = raw[
        "telegram"
    ]

    # -----------------------------------------------------
    # DEDUPE SOURCE POOLS
    # -----------------------------------------------------

    print(
        "\n[DEDUPE]"
    )

    general_unique = dedupe(
        general_raw
    )

    iran_unique = dedupe(
        iran_raw
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

    telegram_unique = dedupe(
        telegram_raw
    )

    print(
        f"GENERAL  : "
        f"{len(general_unique)}"
    )

    print(
        f"IRAN     : "
        f"{len(iran_unique)}"
    )

    print(
        f"MCI      : "
        f"{len(mci_unique)}"
    )

    print(
        f"IRANCELL : "
        f"{len(irancell_unique)}"
    )

    print(
        f"RIGHTEL  : "
        f"{len(rightel_unique)}"
    )

    print(
        f"TELEGRAM : "
        f"{len(telegram_unique)}"
    )

    # -----------------------------------------------------
    # GLOBAL UNIQUE
    # -----------------------------------------------------

    all_unique = dedupe(
        general_unique
        + iran_unique
        + mci_unique
        + irancell_unique
        + rightel_unique
        + telegram_unique
    )

    print(
        f"\nGLOBAL UNIQUE: "
        f"{len(all_unique)}"
    )

    # -----------------------------------------------------
    # IMPORTANT
    # -----------------------------------------------------

    if len(
        all_unique
    ) < GENERAL_TOTAL:
        raise RuntimeError(
            f"Not enough valid unique configs: "
            f"{len(all_unique)} available, "
            f"{GENERAL_TOTAL} required"
        )

    # -----------------------------------------------------
    # BENCHMARK GLOBAL
    # -----------------------------------------------------

    alive_all = benchmark(
        all_unique
    )

    # -----------------------------------------------------
    # BENCHMARK IRAN
    # -----------------------------------------------------

    alive_iran = benchmark(
        iran_unique
    )

    # -----------------------------------------------------
    # BENCHMARK MCI
    # -----------------------------------------------------

    alive_mci = benchmark(
        mci_unique
    )

    # -----------------------------------------------------
    # BENCHMARK IRANCELL
    # -----------------------------------------------------

    alive_irancell = benchmark(
        irancell_unique
    )

    # -----------------------------------------------------
    # BENCHMARK RIGHTEL
    # -----------------------------------------------------

    alive_rightel = benchmark(
        rightel_unique
    )

    # -----------------------------------------------------
    # GENERAL
    # -----------------------------------------------------

    write_general(
        alive_all,
        all_unique,
    )

    # -----------------------------------------------------
    # PROTOCOLS
    # -----------------------------------------------------

    write_protocols(
        alive_all,
        all_unique,
    )

    # -----------------------------------------------------
    # IRAN
    # -----------------------------------------------------

    # Telegram is included as a global fallback.
    iran_fallback_unique = dedupe(
        iran_unique
        + telegram_unique
    )

    alive_iran_fallback = benchmark(
        iran_fallback_unique
    )

    write_iran(
        alive_iran,
        iran_unique,

        alive_mci,
        mci_unique,

        alive_irancell,
        irancell_unique,

        alive_rightel,
        rightel_unique,

        alive_all,
        all_unique,
    )

    # -----------------------------------------------------
    # FINAL VERIFICATION
    # -----------------------------------------------------

    verify_outputs()

    # -----------------------------------------------------
    # SOURCE REPORT
    # -----------------------------------------------------

    print_source_summary()

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
