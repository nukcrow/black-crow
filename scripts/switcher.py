import os
import re
import json
import random
import base64
import requests
from typing import List, Dict

# مسیر پوشه خروجی ساب‌ها
SUB_DIR = "sub"

# منابع پایش‌شده
SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/bulk-xray-v2ray-vless-vmess-configs/main/sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/v2ray.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/sub.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/Freedom.txt",
    "https://raw.githubusercontent.com/jafarm83/ConfigV2Ray/main/v2ray.txt",
    "https://raw.githubusercontent.com/MrAbolfazlNorouzi/iran-configs/main/v2ray.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/configs.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/mix",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/mix.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Kolandone/v2raycollector/main/mix.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/sub.txt"
]

def extract_flag(text: str) -> str:
    """استخراج پرچم کشور"""
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    match = flag_pattern.search(text)
    if match:
        return match.group(0)
    
    cc_pattern = re.compile(r'\b(US|DE|FR|GB|NL|CA|TR|FI|PL|SG|JP|KR|HK|IR|CF)\b', re.IGNORECASE)
    cc_match = cc_pattern.search(text)
    if cc_match:
        return f"[{cc_match.group(0).upper()}]"
        
    return "🌐"

def get_protocol_name(config: str) -> str:
    """تشخیص نام پروتکل برای برچسب‌گذاری"""
    if config.startswith("vless://"):
        return "VLESS"
    elif config.startswith("vmess://"):
        return "VMESS"
    elif config.startswith(("hysteria2://", "hy2://")):
        return "HY2"
    elif config.startswith("trojan://"):
        return "TROJAN"
    elif config.startswith("tuic://"):
        return "TUIC"
    elif config.startswith("ss://"):
        return "SS"
    return "PROXY"

def process_vmess(config: str) -> str:
    """اصلاح ریمارک VMess به همراه نام پروتکل"""
    try:
        b64_part = config.replace("vmess://", "")
        b64_part += '=' * (-len(b64_part) % 4)
        decoded_bytes = base64.b64decode(b64_part)
        data = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
        
        flag = extract_flag(data.get("ps", ""))
        data["ps"] = f"crow | {flag} | VMESS"
        
        new_json = json.dumps(data, ensure_ascii=False)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return f"vmess://{new_b64}"
    except Exception:
        return ""

def clean_and_tag(config: str) -> str:
    """تغییر ریمارک به فرمت: crow | [پرچم] | [پروتکل]"""
    config = config.strip()
    if not config:
        return ""

    proto = get_protocol_name(config)

    if config.startswith("vmess://"):
        return process_vmess(config)
    
    if "#" in config:
        base_part, old_remark = config.split("#", 1)
        flag = extract_flag(old_remark)
        return f"{base_part}#crow | {flag} | {proto}"
    else:
        return f"{config}#crow | 🌐 | {proto}"

def fetch_configs(url: str) -> List[str]:
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            text = res.text.strip()
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                return decoded.splitlines()
            except Exception:
                return text.splitlines()
    except Exception:
        pass
    return []

def save_file(filepath: str, configs: List[str]):
    """ذخیره لیست کانفیگ‌ها در پوشه مقصد"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(configs))

def main():
    os.makedirs(SUB_DIR, exist_ok=True)
    collected = set()
    valid_prefixes = ("vless://", "hysteria2://", "hy2://", "vmess://", "trojan://", "tuic://", "ss://")

    print("[+] Fetching configurations...")
    for src in SOURCES:
        lines = fetch_configs(src)
        for line in lines:
            line = line.strip()
            if line.startswith(valid_prefixes):
                processed = clean_and_tag(line)
                if processed:
                    collected.add(processed)

    config_list = list(collected)
    random.shuffle(config_list)

    if not config_list:
        print("[-] No valid configs retrieved.")
        return

    # ۱. ساب اختصاصی ۵۰‌تایی ترکیبی (فوق‌العاده سریع برای نرم‌افزارهای موبایل/ویندوز)
    mix_50 = config_list[:50]
    save_file(os.path.join(SUB_DIR, "mix_50.txt"), mix_50)

    # ۲. تفکیک دقیق بر اساس پروتکل
    by_protocol: Dict[str, List[str]] = {
        "vless": [],
        "vmess": [],
        "hysteria2": [],
        "trojan": [],
        "tuic": [],
        "ss": []
    }

    for cfg in config_list:
        if cfg.startswith("vless://"):
            by_protocol["vless"].append(cfg)
        elif cfg.startswith("vmess://"):
            by_protocol["vmess"].append(cfg)
        elif cfg.startswith(("hysteria2://", "hy2://")):
            by_protocol["hysteria2"].append(cfg)
        elif cfg.startswith("trojan://"):
            by_protocol["trojan"].append(cfg)
        elif cfg.startswith("tuic://"):
            by_protocol["tuic"].append(cfg)
        elif cfg.startswith("ss://"):
            by_protocol["ss"].append(cfg)

    # ذخیره فایل‌های کامل و فایل‌های ۵۰‌تایی تفکیک‌شده بر اساس پروتکل
    for proto, cfgs in by_protocol.items():
        if cfgs:
            # فایل کامل پروتکل (تا ۲۰۰۰ کانفیگ)
            save_file(os.path.join(SUB_DIR, f"{proto}.txt"), cfgs[:2000])
            # فایل سبک ۵۰‌تایی پروتکل (برای تست سریع در v2rayN/v2rayNG)
            save_file(os.path.join(SUB_DIR, f"{proto}_50.txt"), cfgs[:50])

    # ۳. ذخیره ساب‌های عمومی ۱ تا ۵ داخل پوشه sub
    CONFIGS_PER_SUB = 2000
    for i in range(5):
        start_idx = i * CONFIGS_PER_SUB
        end_idx = min((i + 1) * CONFIGS_PER_SUB, len(config_list))
        chunk = config_list[start_idx:end_idx]
        if chunk:
            save_file(os.path.join(SUB_DIR, f"sub{i+1}.txt"), chunk)

    print(f"[+] Processed {len(config_list)} configs into '{SUB_DIR}/' folder successfully.")

if __name__ == "__main__":
    main()
