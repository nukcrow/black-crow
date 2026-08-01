import os
import re
import json
import random
import base64
import requests
from typing import List

# فایل خروجی اصلی مستقیم در ریشه پروژه
OUTPUT_FILE = "sub.txt"

# سقف کل کانفیگ‌ها جهت سرعت بالا و عدم فشار روی نرم‌افزار
MAX_CONFIGS = 500

# منابع تقویت‌شده با تمرکز روی VLESS TLS/WS/gRPC کلادفلر و Hysteria2
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/surfboardv2ray/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/Arash-S3/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/morteza-f/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/ts-indexer/sub-collector/main/sub/mix",
    "https://raw.githubusercontent.com/E3436/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/LalatinaHub/v2ray-index/main/sub/mix",
    "https://raw.githubusercontent.com/erfanyab/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MoV2ray/v2ray/main/mix",
    "https://raw.githubusercontent.com/v2rayCollector/v2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/BardiaPishro/v2ray-configs/main/sub.txt",
    "https://raw.githubusercontent.com/Iranian-v2ray/v2ray-collector/main/mix.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/pek32/v2ray-free/main/v2ray",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/alien-v2ray/v2ray/main/sub.txt",
    "https://raw.githubusercontent.com/v2ray-reload/v2ray-reload/main/sub/mix"
]

def extract_flag(text: str) -> str:
    """استخراج پرچم یا کد کشور"""
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
    """تغییر ریمارک VMess"""
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
    """تغییر ریمارک تمامی پروتکل‌ها به crow + پرچم"""
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
    try:
        res = requests.get(url, timeout=7)
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
    # اولویت شدید با VLESS و Hysteria2 که بیشترین اتصال را دارند
    valid_prefixes = ("vless://", "hysteria2://", "hy2://", "vmess://", "trojan://", "ss://", "tuic://")

    print("[+] Gathering configurations...")
    for src in SOURCES:
        lines = fetch_configs(src)
        for line in lines:
            line = line.strip()
            if line.startswith(valid_prefixes):
                processed = clean_and_tag(line)
                if processed:
                    collected.add(processed)

    config_list = list(collected)
    
    # هم زدن هوشمند لیست برای اینکه در هر آپدیت ترکیبی تازه از کانفیگ‌ها سر رو بیایند
    random.shuffle(config_list)
    
    # انتخاب ۳۰۰ تا ۵۰۰ کانفیگ برتر بر اساس محدودیت
    final_configs = config_list[:MAX_CONFIGS]
    total = len(final_configs)
    
    print(f"[+] Total fresh configs prepared: {total}")

    if total == 0:
        print("[-] No valid configs retrieved.")
        return

    # ذخیره مستقیم در فایل اصلی sub.txt
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final_configs))

    print(f"[+] 'sub.txt' updated successfully with {total} configs.")

if __name__ == "__main__":
    main()
