import os
import sys
import json
import time
import base64
import socket
import statistics
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor

# اجرای بدون رابط کاربری (مثل سرویس/رانر) با انکودینگ قدیمی cp1252 کرش می‌کند؛
# این خط خروجی را مجبور به UTF-8 می‌کند تا متن فارسی مشکلی ایجاد نکند.
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

# --- تنظیمات ---
SOURCE_DIR = "sub/protocols"          # کانفیگ‌های عمومی زنده (خروجی switcher.py)
IRAN_DIR = "sub/protocols_iran"       # کانفیگ‌های زنده‌ی منابع مخصوص ایران
OUTPUT_FILE = "sub/pool.txt"          # استخر بزرگ برای انتخاب رندوم توسط Worker
TOP_N = 150                           # اندازه‌ی کل استخر
IRAN_QUOTA = 40                       # حداقل تعداد تضمینی از منابع ایران‌محور در استخر
PING_ATTEMPTS = 3
TIMEOUT = 1.2


def decode_base64_safe(data):
    try:
        data = data.strip()
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_dir(path):
    configs = []
    if not os.path.isdir(path):
        return configs
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        with open(fpath, "r", encoding="utf-8") as f:
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
            elapsed = (time.perf_counter() - start) * 1000
            sock.close()
            if result == 0:
                samples.append(elapsed)
        except Exception:
            continue

    if not samples:
        return None
    return config, statistics.median(samples)


def rank_by_ping(configs):
    results = []
    with ThreadPoolExecutor(max_workers=60) as executor:
        for res in executor.map(measure_latency, configs):
            if res:
                results.append(res)
    results.sort(key=lambda x: x[1])
    return results


def rename_with_ping(config, proto, ping_ms, tag=""):
    label = f"persianata{tag} | {int(ping_ms)}ms | {proto.upper()}"
    if proto == "vmess":
        try:
            data = json.loads(decode_base64_safe(config[8:]))
            data["ps"] = label
            return "vmess://" + base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")
        except Exception:
            return config
    base_part = config.split("#")[0]
    return f"{base_part}#{quote(label)}"


def detect_proto(config):
    for p in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]:
        if config.startswith(p + "://"):
            return "hysteria2" if p == "hy2" else p
    return "unknown"


def main():
    print("در حال خواندن کانفیگ‌های عمومی...")
    general_configs = load_dir(SOURCE_DIR)
    print(f"عمومی: {len(general_configs)}")

    print("در حال خواندن کانفیگ‌های مخصوص ایران...")
    iran_configs = load_dir(IRAN_DIR)
    print(f"ایران‌محور: {len(iran_configs)}")

    print("در حال تست پینگ کانفیگ‌های ایران‌محور...")
    iran_ranked = rank_by_ping(iran_configs)
    print(f"ایران‌محور پاسخگو: {len(iran_ranked)}")

    print("در حال تست پینگ کانفیگ‌های عمومی...")
    general_ranked = rank_by_ping(general_configs)
    print(f"عمومی پاسخگو: {len(general_ranked)}")

    # --- ساخت استخر نهایی با سهمیه‌ی تضمینی برای ایران‌محور ---
    final_pairs = []  # (config, ping_ms, is_iran)

    iran_take = iran_ranked[:IRAN_QUOTA]
    final_pairs.extend([(c, p, True) for c, p in iran_take])

    remaining_slots = TOP_N - len(final_pairs)
    general_take = general_ranked[:remaining_slots]
    final_pairs.extend([(c, p, False) for c, p in general_take])

    # اگه ایران‌محور به سهمیه نرسید، جای خالی رو با بقیه‌ی عمومی پر می‌کنیم
    if len(final_pairs) < TOP_N:
        extra_needed = TOP_N - len(final_pairs)
        extra = general_ranked[remaining_slots:remaining_slots + extra_needed]
        final_pairs.extend([(c, p, False) for c, p in extra])

    final_pairs.sort(key=lambda x: x[1])

    final_lines = []
    for config, ping_ms, is_iran in final_pairs:
        proto = detect_proto(config)
        tag = " 🇮🇷" if is_iran else ""
        final_lines.append(rename_with_ping(config, proto, ping_ms, tag))
        print(f"{ping_ms:6.1f} ms  |  {proto:10s}  |  {'IRAN' if is_iran else 'general'}")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final_lines))

    print(f"\nذخیره شد: {OUTPUT_FILE} ({len(final_lines)} کانفیگ، از این تعداد {sum(1 for _,_,i in final_pairs if i)} تای ایران‌محور)")


if __name__ == "__main__":
    main()
