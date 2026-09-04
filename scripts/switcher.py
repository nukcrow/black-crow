import os
import ssl
import json
import time
import base64
import socket
from urllib.parse import urlparse, quote, parse_qs
import requests
from concurrent.futures import ThreadPoolExecutor

os.makedirs("sub/general", exist_ok=True)
os.makedirs("sub/protocols", exist_ok=True)

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
]

REMARK = "nukcrow"
PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade"}
PROTO_LIST = ["vless", "vmess", "trojan", "ss", "hysteria2"]
PROTOCOL_CAP = 200

GEO_BATCH_SIZE = 100
GEO_DELAY = 1.4


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
    with ThreadPoolExecutor(max_workers=25) as executor:
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
    seen = set()
    unique = []
    for cfg in configs:
        ip, port = extract_ip_port(cfg)
        key = (ip, port)
        if key not in seen and ip:
            seen.add(key)
            unique.append(cfg)
    return unique


def get_sni(config):
    try:
        parsed = urlparse(config)
        qs = parse_qs(parsed.query)
        return qs.get("sni", [None])[0] or parsed.hostname
    except Exception:
        return None


def check_tcp_alive(config):
    """تست عمیق‌تر (به سبک BPB): علاوه بر TCP، اگه TLS/Reality بود، واقعاً هندشیک TLS رو هم چک می‌کنه.
    خیلی از سرورهای مرده پورتشون باز می‌مونه (TCP alive) ولی هندشیک TLS واقعی نمیدن - این تست جلوشونو می‌گیره."""
    ip, port = extract_ip_port(config)
    if not ip or not port:
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((ip, port))
        if result != 0:
            sock.close()
            return None

        # اگه TLS بود (نه Reality - چون Reality نیاز به pubkey واقعی داره که نداریم)، هندشیک واقعی رو چک کن
        if "security=tls" in config:
            try:
                sni = get_sni(config)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
                tls_sock.settimeout(1.5)
                tls_sock.do_handshake()
                tls_sock.close()
            except Exception:
                sock.close()
                return None
        else:
            sock.close()

        return config
    except Exception:
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
    try:
        if proto == "vmess":
            data = json.loads(decode_base64_safe(config[8:]))
            net = str(data.get("net", "")).lower()
            tls = str(data.get("tls", "")).lower()
            return tls == "tls" and net in {"ws", "grpc", "h2", "httpupgrade"}

        if proto == "hysteria2":
            return True

        parsed = urlparse(config)
        qs = parse_qs(parsed.query)
        security = (qs.get("security", [""])[0]).lower()
        ctype = (qs.get("type", [""])[0]).lower()

        if security == "reality":
            return True
        if security == "tls":
            return ctype in PREFERRED_TYPES or ctype == ""
        return False
    except Exception:
        return False


def country_to_flag(country_code):
    """تبدیل کد کشور دو حرفی (ISO 3166-1) به ایموجی پرچم."""
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return ""


def geolocate_hosts(host_list):
    """با ip-api.com (batch، رایگان) کد کشور هر host رو پیدا می‌کنه. host -> country_code"""
    unique_hosts = list(set(host_list))
    result = {}

    for i in range(0, len(unique_hosts), GEO_BATCH_SIZE):
        chunk = unique_hosts[i:i + GEO_BATCH_SIZE]
        payload = [{"query": h, "fields": "query,countryCode,status"} for h in chunk]
        try:
            res = requests.post("http://ip-api.com/batch", json=payload, timeout=15)
            if res.status_code == 200:
                for item in res.json():
                    if item.get("status") == "success":
                        result[item["query"]] = item.get("countryCode", "")
        except Exception:
            pass
        time.sleep(GEO_DELAY)

    return result


def rename_config(config, proto, flag=""):
    label = f"{flag} {REMARK}".strip() if flag else REMARK
    try:
        if proto == "vmess":
            data = json.loads(decode_base64_safe(config[8:]))
            data['ps'] = label
            return "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
        else:
            base_part = config.split("#")[0]
            return f"{base_part}#{quote(label)}"
    except Exception:
        return None


def main():
    print(f"Fetching from {len(SOURCES)} verified sources (parallel)...")
    raw = fetch_all()
    print(f"Fetched (raw): {len(raw)}")

    raw = dedupe_by_host_port(raw)
    print(f"After host:port dedupe: {len(raw)}")

    print("Checking TCP alive...")
    alive = filter_alive(raw)
    print(f"Alive: {len(alive)}")

    print("Geolocating servers (country flags)...")
    hosts = []
    for cfg in alive:
        h, p = extract_ip_port(cfg)
        if h:
            hosts.append(h)
    geo_map = geolocate_hosts(hosts)
    print(f"Geolocated: {len(geo_map)} / {len(set(hosts))} unique hosts")

    preferred_all, fallback_all = [], []
    proto_buckets = {p: {"preferred": [], "fallback": []} for p in PROTO_LIST}

    for cfg in alive:
        proto = detect_proto(cfg)
        if proto == "unknown":
            continue

        host, _ = extract_ip_port(cfg)
        country_code = geo_map.get(host, "")
        flag = country_to_flag(country_code)

        renamed = rename_config(cfg, proto, flag)
        if not renamed:
            continue

        pref = is_preferred(cfg, proto)
        if pref:
            preferred_all.append(renamed)
        else:
            fallback_all.append(renamed)

        if proto in proto_buckets:
            if pref:
                proto_buckets[proto]["preferred"].append(renamed)
            else:
                proto_buckets[proto]["fallback"].append(renamed)

    all_formatted = preferred_all + fallback_all
    chunk_size = 1000
    for i in range(5):
        start = i * chunk_size
        end = start + chunk_size
        chunk_data = all_formatted[start:end]
        with open(f"sub/general/sub{i+1}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(chunk_data))

    for proto in PROTO_LIST:
        combined = proto_buckets[proto]["preferred"] + proto_buckets[proto]["fallback"]
        capped = combined[:PROTOCOL_CAP]
        with open(f"sub/protocols/{proto}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(capped))
        print(f"  {proto}: {len(capped)}")

    print(f"Done. Preferred: {len(preferred_all)} | Fallback: {len(fallback_all)} | Total: {len(all_formatted)}")


if __name__ == "__main__":
    main()
