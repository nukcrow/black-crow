import os
import json
import base64
import socket
from urllib.parse import urlparse, quote, parse_qs
import requests
from concurrent.futures import ThreadPoolExecutor

DIRS = ["sub/protocols", "sub/general"]
for d in DIRS:
    os.makedirs(d, exist_ok=True)

SOURCES = [
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/v2ray.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub/sub.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/barry-far/v2ray-config/main/v2ray.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/refs/heads/main/all/vless.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/config.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/v2ray.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/yebekhe/V2RayConfig/main/v2ray.txt",
    "https://raw.githubusercontent.com/MahdiGhaffari/V2rayAggregator/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/main/mix.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/jafar.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/v2ray.txt",
    "https://raw.githubusercontent.com/Anankke/Sub-Store/master/config/node.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://raw.githubusercontent.com/lm705/vair/main/vair.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/E5%2Fsub.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/v2ray.txt",
    "https://raw.githubusercontent.com/MrRabbitson/RabbitProxyz-proxy-list/main/proxy-list.txt",
    "https://raw.githubusercontent.com/tbbatbb/V2Ray/master/v2ray.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray.txt",
    "https://raw.githubusercontent.com/VP01596/vless-top15/main/vless.txt",
]

REMARK = "persian crow"

# بر اساس نمونه‌های خودت: این ترکیب‌ها معمولاً وصل میشن (CDN-fronted یا Reality)
PREFERRED_SECURITY = {"tls", "reality"}
PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade"}


def decode_base64_safe(data):
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""


def fetch_one(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    found = []
    try:
        res = requests.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            text = res.text.strip()
            decoded = decode_base64_safe(text)
            content = decoded if "://" in decoded else text
            for line in content.splitlines():
                line = line.strip()
                if any(line.startswith(p + "://") for p in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]):
                    found.append(line)
    except Exception:
        pass
    return found


def fetch_all():
    raw_list = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for result in executor.map(fetch_one, SOURCES):
            raw_list.extend(result)
    return raw_list


def extract_ip_port(config):
    try:
        if config.startswith("vmess://"):
            data = json.loads(decode_base64_safe(config[8:]))
            return data.get("add"), int(data.get("port", 443))
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port or (443 if "tls" in config else 80)
        return host, int(port)
    except Exception:
        return None, None


def dedupe_by_host_port(configs):
    """چون خیلی از کانفیگ‌ها فقط UUID متفاوت دارن ولی سرورشون یکیه، بر اساس host:port یکتا می‌کنیم."""
    seen = set()
    unique = []
    for cfg in configs:
        ip, port = extract_ip_port(cfg)
        key = (ip, port)
        if key not in seen and ip:
            seen.add(key)
            unique.append(cfg)
    return unique


def check_tcp_alive(config):
    ip, port = extract_ip_port(config)
    if not ip or not port:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return config
    except Exception:
        pass
    return None


def filter_alive(raw_configs):
    alive = []
    with ThreadPoolExecutor(max_workers=150) as executor:
        for res in executor.map(check_tcp_alive, raw_configs):
            if res:
                alive.append(res)
    return alive


def detect_proto(config):
    if config.startswith("vless://"): return "vless"
    if config.startswith("vmess://"): return "vmess"
    if config.startswith("trojan://"): return "trojan"
    if config.startswith("ss://"): return "ss"
    if config.startswith("hysteria2://") or config.startswith("hy2://"): return "hysteria2"
    if config.startswith("tuic://"): return "tuic"
    return "unknown"


def is_preferred(config, proto):
    """چک واقعی برای هر پروتکل - دیگه به هیچ‌کدوم "کورکورانه" تایید نمی‌دیم."""
    try:
        if proto == "vmess":
            data = json.loads(decode_base64_safe(config[8:]))
            net = str(data.get("net", "")).lower()
            tls = str(data.get("tls", "")).lower()
            return tls == "tls" and net in {"ws", "grpc", "h2", "httpupgrade"}

        if proto == "hysteria2":
            # hysteria2 خودش همیشه روی QUIC+TLS کار می‌کنه، پس همیشه preferred
            return True

        parsed = urlparse(config)
        qs = parse_qs(parsed.query)
        security = (qs.get("security", [""])[0]).lower()
        ctype = (qs.get("type", [""])[0]).lower()
        return security in PREFERRED_SECURITY and (ctype in PREFERRED_TYPES or ctype == "")
    except Exception:
        return False


def rename_config(config, proto):
    try:
        if proto == "vmess":
            data = json.loads(decode_base64_safe(config[8:]))
            data['ps'] = REMARK
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            base_part = config.split("#")[0]
            return f"{base_part}#{quote(REMARK)}"
    except Exception:
        return None


def main():
    print(f"Fetching from {len(SOURCES)} sources (parallel)...")
    raw = fetch_all()
    print(f"Fetched (raw): {len(raw)}")

    raw = dedupe_by_host_port(raw)
    print(f"After host:port dedupe: {len(raw)}")

    print("Checking TCP alive...")
    alive = filter_alive(raw)
    print(f"Alive: {len(alive)}")

    protocol_buckets = {"vless": [], "vmess": [], "trojan": [], "ss": [], "hysteria2": [], "tuic": []}
    preferred_all, fallback_all = [], []

    for cfg in alive:
        proto = detect_proto(cfg)
        if proto not in protocol_buckets:
            continue
        renamed = rename_config(cfg, proto)
        if not renamed:
            continue

        pref = is_preferred(cfg, proto)
        # داخل هر پروتکل هم preferred رو اول می‌ذاریم
        if pref:
            protocol_buckets[proto].insert(0, renamed)
            preferred_all.append(renamed)
        else:
            protocol_buckets[proto].append(renamed)
            fallback_all.append(renamed)

    for p, items in protocol_buckets.items():
        with open(f"sub/protocols/{p}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(items))

    # preferred اول، بعد fallback -> یعنی توی هر فایل general، اول کانفیگ‌های قابل‌اعتمادتر میان
    all_formatted = preferred_all + fallback_all

    chunk_size = 1000
    for i in range(5):
        start = i * chunk_size
        end = start + chunk_size
        chunk_data = all_formatted[start:end]
        with open(f"sub/general/sub{i+1}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(chunk_data))

    print(f"Done. Preferred (tls/reality+ws/grpc/xhttp): {len(preferred_all)} | Fallback: {len(fallback_all)}")


if __name__ == "__main__":
    main()
