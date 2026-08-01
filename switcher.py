import os
import re
import json
import base64
import requests
from typing import List, Tuple

# پوشه خروجی
OUTPUT_DIR = "sub"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# سقف کل کانفیگ‌ها برای حفظ امنیت در گیت‌هاب و جلوگیری از بن
MAX_CONFIGS = 1500

# ۲۲ منبع فعال و قوی (مناسب شرایط اختلال شبکه)
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/ts-indexer/sub-collector/main/sub/mix",
    "https://raw.githubusercontent.com/morteza-f/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/E3436/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/LalatinaHub/v2ray-index/main/sub/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/pek32/v2ray-free/main/v2ray",
    "https://raw.githubusercontent.com/erfanyab/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MoV2ray/v2ray/main/mix",
    "https://raw.githubusercontent.com/sub-collector/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/BardiaPishro/v2ray-configs/main/sub.txt",
    "https://raw.githubusercontent.com/Iranian-v2ray/v2ray-collector/main/mix.txt",
    "https://raw.githubusercontent.com/Arash-S3/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/surfboardv2ray/v2ray-collector/main/sub/mix",
    "https://raw.githubusercontent.com/alien-v2ray/v2ray/main/sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/v2ray-reload/v2ray-reload/main/sub/mix",
    "https://raw.githubusercontent.com/v2rayCollector/v2rayCollector/main/sub/mix"
]

def extract_flag(text: str) -> str:
    """استخراج پرچم کشور از متن ریمارک"""
    # الگوی ردیابی ایموجی‌های پرچم سازمان ملل (Unicode Regional Indicator Symbols)
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    match = flag_pattern.search(text)
    if match:
        return match.group(0)
    
    # جستجوی کدهای ۲ حرفی کشورها مانند CA, DE, US
    cc_pattern = re.compile(r'\b(US|DE|FR|GB|NL|CA|TR|FI|PL|SG|JP|KR|HK|IR)\b', re.IGNORECASE)
    cc_match = cc_pattern.search(text)
    if cc_match:
        return f"[{cc_match.group(0).upper()}]"
        
    return "🌐"

def process_vmess(config: str) -> str:
    """اصلاح ریمارک برای کانفیگ‌های VMess بیس۶۴"""
    try:
        b64_part = config.replace("vmess://", "")
        # افزودن padding جهت دکود صحیح
        b64_part += '=' * (-len(b64_part) % 4)
        decoded_bytes = base64.b64decode(b64_part)
        data = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
        
        old_ps = data.get("ps", "")
        flag = extract_flag(old_ps)
        data["ps"] = f"crow | {flag}"
        
        new_json = json.dumps(data, ensure_ascii=False)
        new_b64 = base64.b64encode(new_json.encode('utf-8')).decode('utf-8')
        return f"vmess://{new_b64}"
    except Exception:
        return ""

def clean_and_tag(config: str) -> str:
    """تغییر نام ریمارک به crow همراه با پرچم کشور"""
    config = config.strip()
    if not config:
        return ""

    if config.startswith("vmess://"):
        return process_vmess(config)
    
    # سایر پروتکل‌ها (VLESS, Trojan, Hysteria2, SS, TUIC)
    if "#" in config:
        base_part, old_remark = config.split("#", 1)
        flag = extract_flag(old_remark)
        return f"{base_part}#crow | {flag}"
    else:
        return f"{config}#crow | 🌐"

def fetch_configs(url: str) -> List[str]:
    """دریافت دیتای منابع"""
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
    valid_prefixes = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

    print("[+] Collecting from 22 proxy sources...")
    for src in SOURCES:
        lines = fetch_configs(src)
        for line in lines:
            line = line.strip()
            if line.startswith(valid_prefixes):
                processed = clean_and_tag(line)
                if processed:
                    collected.add(processed)
                    if len(collected) >= MAX_CONFIGS:
                        break
        if len(collected) >= MAX_CONFIGS:
            break

    config_list = list(collected)
    total = len(config_list)
    print(f"[+] Successfully gathered and formatted {total} configs.")

    if total == 0:
        print("[-] No valid configs retrieved.")
        return

    # تقسیم کانفیگ‌ها به دقیقاً ۱۰ فایل سابسکریپشن
    num_files = 10
    chunk_size = max(1, total // num_files)

    for i in range(num_files):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_files - 1 else total
        chunk = config_list[start:end]
        
        file_name = f"{i+1:02d}.txt"
        file_path = os.path.join(OUTPUT_DIR, file_name)
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk))

    print(f"[+] Successfully created 10 subscription files in '{OUTPUT_DIR}/'.")

if __name__ == "__main__":
    main()
