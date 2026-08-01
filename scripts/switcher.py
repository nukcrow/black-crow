import os
import re
import json
import base64
import socket
import requests
from urllib.parse import urlparse, unquote, quote
from concurrent.futures import ThreadPoolExecutor

# --- تنظیمات ساختار پوشه‌ها ---
DIRS = [
    "sub/general",
    "sub/protocols",
    "sub/light"
]

for d in DIRS:
    os.makedirs(d, exist_ok=True)

# --- مخازن برتر و پالایش‌شده ---
SOURCES = [
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/v2ray.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub/sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/refs/heads/main/all/vless.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/config.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/v2ray.txt",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
    "https://raw.githubusercontent.com/MahdiGhaffari/V2rayAggregator/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/main/mix.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/refs/heads/main/output/converted.txt"
]

SUPPORTED_PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"]

def decode_base64_safe(data):
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def fetch_configs():
    raw_list = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    for url in SOURCES:
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                text = res.text.strip()
                # بررسی امکان Base64 بودن کل ساب
                decoded = decode_base64_safe(text)
                content = decoded if "://" in decoded else text
                lines = content.splitlines()
                for line in lines:
                    line = line.strip()
                    if any(line.startswith(p + "://") for p in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]):
                        raw_list.append(line)
        except Exception:
            continue
    return list(set(raw_list))

def extract_ip_port(config):
    """استخراج آی‌پی و پورت برای تست پینگ سریع TCP"""
    try:
        if config.startswith("vmess://"):
            b64_part = config[8:]
            json_str = decode_base64_safe(b64_part)
            data = json.loads(json_str)
            return data.get("add"), int(data.get("port", 443))
        
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port
        
        if not port:
            if config.startswith("https") or "tls" in config:
                port = 443
            else:
                port = 80
        return host, int(port)
    except Exception:
        return None, None

def check_tcp_alive(config):
    """تست زنده بودن پورت (TCP Connect Check با تایم‌اوت ۱ ثانیه)"""
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

def parse_and_rename(config):
    """استانداردسازی نام و مشخص کردن نوع پروتکل"""
    proto = "unknown"
    if config.startswith("vless://"): proto = "vless"
    elif config.startswith("vmess://"): proto = "vmess"
    elif config.startswith("trojan://"): proto = "trojan"
    elif config.startswith("ss://"): proto = "ss"
    elif config.startswith("hysteria2://") or config.startswith("hy2://"): proto = "hysteria2"
    elif config.startswith("tuic://"): proto = "tuic"
    
    if proto == "unknown":
        return None, None

    new_remark = f"crow | 🌐 | {proto.upper()}"

    try:
        if proto == "vmess":
            b64_part = config[8:]
            data = json.loads(decode_base64_safe(b64_part))
            data['ps'] = new_remark
            new_config = "vmess://" + base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return proto, new_config
        else:
            if "#" in config:
                base_part = config.split("#")[0]
            else:
                base_part = config
            new_config = f"{base_part}#{quote(new_remark)}"
            return proto, new_config
    except Exception:
        return None, None

def main():
    print("Fetching configs...")
    raw_configs = fetch_configs()
    print(f"Total fetched: {len(raw_configs)}")

    print("Checking TCP connection for active configs...")
    alive_configs = []
    # تست همزمان با ۱۰۰ ترد برای بالا بردن سرعت اسکریپت
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_tcp_alive, raw_configs)
        for res in results:
            if res:
                alive_configs.append(res)
    
    print(f"Total alive configs: {len(alive_configs)}")

    # دسته‌بندی بر اساس پروتکل
    protocol_buckets = {
        "vless": [],
        "vmess": [],
        "trojan": [],
        "ss": [],
        "hysteria2": [],
        "tuic": []
    }

    for cfg in alive_configs:
        proto, formatted = parse_and_rename(cfg)
        if proto in protocol_buckets and formatted:
            protocol_buckets[proto].append(formatted)

    all_active_formatted = []
    for p, items in protocol_buckets.items():
        all_active_formatted.extend(items)
        
        # ۱. ذخیره ساب‌های کامل پروتکل
        with open(f"sub/protocols/{p}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(items))
            
        # ۲. ذخیره ساب‌های سبک ۵۰‌تایی پروتکل
        with open(f"sub/light/{p}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(items[:50]))

    # ۳. تقسیم‌بندی فایل‌های عمومی ۵‌گانه (حداکثر ۲۰۰۰ کانفیگ در هر فایل)
    chunk_size = 2000
    for i in range(5):
        start = i * chunk_size
        end = start + chunk_size
        chunk_data = all_active_formatted[start:end]
        with open(f"sub/general/sub{i+1}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(chunk_data))

    print("All subscription files updated successfully!")

if __name__ == "__main__":
    main()
