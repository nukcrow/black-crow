import os
import re
import json
import random
import base64
import requests
from typing import List

# تنظیمات خروجی
NUM_SUBS = 5
CONFIGS_PER_SUB = 2000

# لیست پایش‌شده و امن از مخازن ارسالی شما
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
    """استخراج پرچم یا کد کشور از ریمارک قبلی"""
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    match = flag_pattern.search(text)
    if match:
        return match.group(0)
    
    cc_pattern = re.compile(r'\b(US|DE|FR|GB|NL|CA|TR|FI|PL|SG|JP|KR|HK|IR|CF)\b', re.IGNORECASE)
    cc_match = cc_pattern.search(text)
    if cc_match:
        return f"[{cc_match.group(0).upper()}]"
        
    return "🌐"

def process_vmess(config: str) -> str:
    """اصلاح ریمارک در کانفیگ‌های base64 نوع VMess"""
    try:
        b64_part = config.replace("vmess://", "")
        b64_part += '=' * (-len(b64_part) % 4)
        decoded_bytes = base64.b64decode(b64_part)
        data = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
        
        flag = extract_flag(data.get("ps", ""))
        data["ps"] = f"crow | {flag}"
        
        new_json = json.dumps(data, ensure_ascii=False)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return f"vmess://{new_b64}"
    except Exception:
        return ""

def clean_and_tag(config: str) -> str:
    """استانداردسازی ریمارک تمامی کانفیگ‌ها به الگوی crow | [Flag]"""
    config = config.strip()
    if not config:
        return ""

    if config.startswith("vmess://"):
        return process_vmess(config)
    
    if "#" in config:
        base_part, old_remark = config.split("#", 1)
        flag = extract_flag(old_remark)
        return f"{base_part}#crow | {flag}"
    else:
        return f"{config}#crow | 🌐"

def fetch_configs(url: str) -> List[str]:
    """دریافت و رمزکُشایی محتوای مخازن"""
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

def main():
    collected = set()
    # انطباق دقیق با پروتکل‌های نمونه شما
    valid_prefixes = ("vless://", "hysteria2://", "hy2://", "vmess://", "trojan://", "tuic://")

    print("[+] Fetching configurations from clean repos...")
    for src in SOURCES:
        lines = fetch_configs(src)
        for line in lines:
            line = line.strip()
            if line.startswith(valid_prefixes):
                processed = clean_and_tag(line)
                if processed:
                    collected.add(processed)

    config_list = list(collected)
    # برهم‌زدن تصادفی جهت تازه نگه‌داشتن کانفیگ‌های بالای لیست
    random.shuffle(config_list)
    
    total = len(config_list)
    print(f"[+] Total unique valid configs collected: {total}")

    if total == 0:
        print("[-] No valid configs found.")
        return

    # تقسیم به ۵ فایل sub1.txt تا sub5.txt (هر کدام تا ۲۰۰۰ کانفیگ)
    for i in range(NUM_SUBS):
        start_idx = i * CONFIGS_PER_SUB
        end_idx = min((i + 1) * CONFIGS_PER_SUB, total)
        
        chunk = config_list[start_idx:end_idx]
        file_name = f"sub{i+1}.txt"
        
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk))
        
        print(f"[+] Saved '{file_name}' with {len(chunk)} configs.")

if __name__ == "__main__":
    main()
