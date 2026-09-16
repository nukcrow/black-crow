import os
import json
import time
import base64
import socket
import hashlib
import random
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor

import requests

os.makedirs("sub/general", exist_ok=True)

# ============================================================
# SOURCES (all verified working)
# ============================================================

SOURCES = [
    # Iran-focused
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",

    # General high-volume (verified)
    "https://raw.githubusercontent.com/mheidari98/.proxy/main/all",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/ermaozi01/free_clash_vpn/main/subscribe/v2ray.txt",

    # Added for volume (verified)
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/refs/heads/main/all/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/refs/heads/main/all_servers.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
]

REMARK = "nukcrow"
PROTO_LIST = ["vless", "vmess", "trojan", "ss", "hysteria2"]

SUB_LIMIT = 1000
MAX_SUBS = 10
MAX_TEST = 30000
WORKERS = 150
FETCH_TIMEOUT = 10
CONNECT_TIMEOUT = 2

PREFERRED_TYPES = {"ws", "grpc", "xhttp", "httpupgrade"}


def decode64(x):
    try:
        x = x.strip().replace("-", "+").replace("_", "/")
        x += "=" * (-len(x) % 4)
        return base64.b64decode(x).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract(text):
    if "://" in text:
        return text
    d = decode64(text)
    if "://" in d:
        return d
    return text


def fetch(url):
    out = []
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 nukcrow"})
        if r.status_code != 200:
            return out
        data = extract(r.text)
        for line in data.splitlines():
            line = line.strip()
            if line.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")):
                out.append(line)
    except Exception:
        pass
    return out


def fetch_all():
    result = []
    with ThreadPoolExecutor(max_workers=25) as ex:
        for r in ex.map(fetch, SOURCES):
            result.extend(r)
    return result


def proto(c):
    for p in PROTO_LIST:
        if c.startswith(p + "://"):
            return p
    if c.startswith("hy2://"):
        return "hysteria2"
    return "unknown"


def query(c):
    try:
        return parse_qs(urlparse(c).query)
    except Exception:
        return {}


def host_port(c):
    try:
        u = urlparse(c)
        return u.hostname, u.port or 443
    except Exception:
        return None, None


def fingerprint(c):
    try:
        u = urlparse(c)
        q = query(c)
        data = {
            "proto": proto(c),
            "host": u.hostname,
            "port": u.port,
            "security": q.get("security", [""])[0],
            "type": q.get("type", [""])[0],
            "sni": q.get("sni", [""])[0],
            "path": q.get("path", [""])[0],
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    except Exception:
        return hashlib.sha256(c.encode()).hexdigest()


def dedupe(items):
    seen = set()
    out = []
    for x in items:
        f = fingerprint(x)
        if f not in seen:
            seen.add(f)
            out.append(x)
    return out


def score_config(c, lat):
    p = proto(c)
    q = query(c)
    score = 1000 - lat

    security = q.get("security", [""])[0]
    typ = q.get("type", [""])[0]
    port = host_port(c)[1]

    if port == 443:
        score += 80
    if security == "reality":
        score += 200
    if security == "tls":
        score += 120
    if typ in PREFERRED_TYPES:
        score += 100
    if p == "hysteria2":
        score += 80
    if p == "trojan":
        score += 60
    if p == "vmess":
        score += 20
    if security == "none":
        score -= 80

    return score


def test(c):
    h, p = host_port(c)
    if not h:
        return None
    start = time.time()
    try:
        s = socket.create_connection((h, p), timeout=CONNECT_TIMEOUT)
        s.close()
        ms = (time.time() - start) * 1000
        return {"config": c, "lat": ms, "score": score_config(c, ms)}
    except Exception:
        return None


def benchmark(items):
    results = []
    if len(items) > MAX_TEST:
        random.shuffle(items)
        items = items[:MAX_TEST]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for r in ex.map(test, items):
            if r:
                results.append(r)
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def rename(c):
    try:
        if "#" in c:
            c = c.split("#")[0]
        return c + "#" + quote(REMARK)
    except Exception:
        return None


def write(path, data):
    with open(path, "w", encoding="utf8") as f:
        f.write("\n".join(data))


def main():
    print("fetch")
    configs = fetch_all()
    print("raw", len(configs))

    configs = dedupe(configs)
    print("unique", len(configs))

    ranked = benchmark(configs)
    print("alive", len(ranked))

    final = [rename(x["config"]) for x in ranked]
    final = [x for x in final if x]

    # all_configs.txt — همه‌ی کانفیگ‌های زنده و رتبه‌بندی‌شده، یکجا
    write("sub/general/all_configs.txt", final)

    # sub1..subN داینامیک (حداکثر 10 تا، هیچ فایل خالی نمی‌مونه)
    total = len(final)
    num_subs = min(MAX_SUBS, max(1, (total + SUB_LIMIT - 1) // SUB_LIMIT))
    for i in range(num_subs):
        part = final[i * SUB_LIMIT: (i + 1) * SUB_LIMIT]
        if part:
            write(f"sub/general/sub{i+1}.txt", part)

    for i in range(num_subs + 1, MAX_SUBS + 1):
        path = f"sub/general/sub{i}.txt"
        if os.path.exists(path):
            os.remove(path)

    print("done", len(final), "subs:", num_subs)


if __name__ == "__main__":
    main()
