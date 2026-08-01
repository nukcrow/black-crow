import os
import sys
import json
import time
import base64
import socket
import statistics
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor

# اجرای بدون رابط کاربری (مثل سرویس ویندوز) با انکودینگ قدیمی cp1252 کرش می‌کند؛
# این خط خروجی را مجبور به UTF-8 می‌کند تا متن فارسی مشکلی ایجاد نکند.
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

# --- تنظیمات ---
SOURCE_DIR = "sub/protocols"          # فایل‌های خروجی switcher.py (کانفیگ‌های زنده مخزن black-crow)
OUTPUT_FILE = "sub/best30.txt"        # ساب نهایی ۳۰ کانفیگ برتر
TOP_N = 30
PING_ATTEMPTS = 3                     # هر کانفیگ چند بار تست میشه (میانگین گرفته میشه)
TIMEOUT = 1.2                         # ثانیه


def decode_base64_safe(data):
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_configs():
    """همه کانفیگ‌های از پیش فیلترشده‌ی مخزن رو از sub/protocols می‌خونه."""
    configs = []
    if not os.path.isdir(SOURCE_DIR):
        raise SystemExit(f"پوشه {SOURCE_DIR} پیدا نشد؛ اول scripts/switcher.py رو اجرا کن.")
    for fname in os.listdir(SOURCE_DIR):
        path = os.path.join(SOURCE_DIR, fname)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    configs.append(line)
    return list(set(configs))


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


def measure_latency(config):
    """اتصال TCP واقعی به سرور کانفیگ و اندازه‌گیری RTT از همین ماشینی که اسکریپت روش اجرا میشه."""
    ip, port = extract_ip_port(config)
    if not ip or not port:
        return None

    samples = []
    for _ in range(PING_ATTEMPTS):
        try:
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            elapsed = (time.perf_counter() - start) * 1000  # ms
            sock.close()
            if result == 0:
                samples.append(elapsed)
        except Exception:
            continue

    if not samples:
        return None
    return config, statistics.median(samples)


def rename_with_ping(config, proto, ping_ms):
    remark = f"crow | {int(ping_ms)}ms | {proto.upper()}"
    if proto == "vmess":
        try:
            data = json.loads(decode_base64_safe(config[8:]))
            data["ps"] = remark
            return "vmess://" + base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
        except Exception:
            return config
    base_part = config.split("#")[0]
    return f"{base_part}#{quote(remark)}"


def detect_proto(config):
    for p in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]:
        if config.startswith(p + "://"):
            return "hysteria2" if p == "hy2" else p
    return "unknown"


def main():
    print("در حال خواندن کانفیگ‌های مخزن (sub/protocols)...")
    configs = load_configs()
    print(f"مجموع کانفیگ‌ها: {len(configs)}")

    print(f"در حال تست پینگ واقعی هر کانفیگ، {PING_ATTEMPTS} بار برای هرکدام...")
    results = []
    with ThreadPoolExecutor(max_workers=60) as executor:
        for res in executor.map(measure_latency, configs):
            if res:
                results.append(res)

    print(f"کانفیگ‌های پاسخگو: {len(results)}")

    results.sort(key=lambda x: x[1])
    top = results[:TOP_N]

    final_lines = []
    for config, ping_ms in top:
        proto = detect_proto(config)
        final_lines.append(rename_with_ping(config, proto, ping_ms))
        print(f"{ping_ms:6.1f} ms  |  {proto:10s}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    print(f"\nذخیره شد: {OUTPUT_FILE} ({len(final_lines)} کانفیگ برتر)")


if __name__ == "__main__":
    main()
