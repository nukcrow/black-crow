import os
import ssl
import json
import time
import base64
import socket
import hashlib
import random
from urllib.parse import urlparse, parse_qs, quote
from concurrent.futures import ThreadPoolExecutor

import requests


# ============================================================
# OUTPUT
# ============================================================

os.makedirs("sub/general", exist_ok=True)
os.makedirs("sub/protocols", exist_ok=True)


# ============================================================
# SOURCES
# ============================================================

SOURCES = [

    # Iran focused collectors
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/ss_iran.txt",

    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/vless_iran.txt",

    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",

    "https://raw.githubusercontent.com/lagzian/IranConfigCollector/main/Base64.txt",

    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/main/xray_final.txt",

    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_3.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_4.txt",


    # General high volume sources

    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/normal/vmess",

    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss",

    "https://raw.githubusercontent.com/yebekhe/vpn-fail/main/sub-link",

    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",

    "https://raw.githubusercontent.com/Joker-funland/V2ray-configs/main/config.txt",

    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",

    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",

    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html",

    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/main/configs/proxy.txt",

    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",

    "https://raw.githubusercontent.com/vfarid/v2ray-configs/main/proxy.txt",

    "https://raw.githubusercontent.com/AzadNetCH/Clash/main/AzadNet.txt",

    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/a11",

]


# ============================================================
# SETTINGS
# ============================================================

REMARK = "nukcrow"

PROTO_LIST = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2"
]


SUB_COUNT = 5
SUB_LIMIT = 1000

MAX_TEST = 30000

WORKERS = 150

TIMEOUT = 8

CONNECT_TIMEOUT = 2


PREFERRED_TYPES = {
    "ws",
    "grpc",
    "xhttp",
    "httpupgrade"
}



# ============================================================
# BASE64
# ============================================================


def decode64(x):

    try:

        x=x.strip()

        x=x.replace("-","+").replace("_","/")

        x+="="*(-len(x)%4)

        return base64.b64decode(
            x
        ).decode(
            "utf-8",
            errors="ignore"
        )

    except:

        return ""


def extract(text):

    if "://" in text:
        return text

    d=decode64(text)

    if "://" in d:
        return d

    return text



# ============================================================
# FETCH
# ============================================================


def fetch(url):

    out=[]

    try:

        r=requests.get(
            url,
            timeout=TIMEOUT,
            headers={
                "User-Agent":"Mozilla/5.0 nukcrow"
            }
        )

        if r.status_code!=200:
            return out


        data=extract(r.text)


        for line in data.splitlines():

            line=line.strip()

            if line.startswith(
                (
                "vless://",
                "vmess://",
                "trojan://",
                "ss://",
                "hysteria2://",
                "hy2://"
                )
            ):
                out.append(line)


    except:
        pass


    return out



def fetch_all():

    result=[]

    with ThreadPoolExecutor(
        max_workers=40
    ) as ex:

        for r in ex.map(fetch,SOURCES):

            result.extend(r)


    return result



# ============================================================
# PARSER
# ============================================================


def proto(c):

    for p in PROTO_LIST:

        if c.startswith(p+"://"):
            return p

    if c.startswith("hy2://"):
        return "hysteria2"

    return "unknown"



def query(c):

    try:
        return parse_qs(
            urlparse(c).query
        )

    except:

        return {}



def host_port(c):

    try:

        u=urlparse(c)

        return (
            u.hostname,
            u.port or 443
        )

    except:

        return None,None



# ============================================================
# DEDUPE
# ============================================================


def fingerprint(c):

    try:

        u=urlparse(c)

        q=query(c)

        data={
            "proto":proto(c),
            "host":u.hostname,
            "port":u.port,
            "security":q.get("security",[""])[0],
            "type":q.get("type",[""])[0],
            "sni":q.get("sni",[""])[0],
            "path":q.get("path",[""])[0]
        }


        return hashlib.sha256(
            json.dumps(
                data,
                sort_keys=True
            ).encode()
        ).hexdigest()


    except:

        return hashlib.sha256(
            c.encode()
        ).hexdigest()



def dedupe(items):

    seen=set()

    out=[]

    for x in items:

        f=fingerprint(x)

        if f not in seen:

            seen.add(f)

            out.append(x)

    return out



# ============================================================
# SCORE
# ============================================================


def score_config(c,lat):

    p=proto(c)

    q=query(c)

    score=1000-lat


    security=q.get(
        "security",
        [""]
    )[0]


    typ=q.get(
        "type",
        [""]
    )[0]


    port=host_port(c)[1]


    if port==443:
        score+=80


    if security=="reality":
        score+=200


    if security=="tls":
        score+=120


    if typ in PREFERRED_TYPES:
        score+=100


    if p=="hysteria2":
        score+=80


    if p=="trojan":
        score+=60


    if p=="vmess":
        score+=20


    if security=="none":
        score-=80


    return score



# ============================================================
# TEST
# ============================================================


def test(c):

    h,p=host_port(c)

    if not h:
        return None


    start=time.time()


    try:

        s=socket.create_connection(
            (h,p),
            timeout=CONNECT_TIMEOUT
        )

        s.close()


        ms=(time.time()-start)*1000


        return {
            "config":c,
            "lat":ms,
            "score":score_config(c,ms)
        }


    except:

        return None



def benchmark(items):

    results=[]


    if len(items)>MAX_TEST:

        random.shuffle(items)

        items=items[:MAX_TEST]


    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as ex:

        for r in ex.map(test,items):

            if r:

                results.append(r)



    results.sort(
        key=lambda x:x["score"],
        reverse=True
    )


    return results



# ============================================================
# REMARK
# ============================================================


def rename(c):

    try:

        if "#" in c:

            c=c.split("#")[0]


        return c+"#"+quote(REMARK)


    except:

        return None



# ============================================================
# OUTPUT
# ============================================================


def write(path,data):

    with open(
        path,
        "w",
        encoding="utf8"
    ) as f:

        f.write(
            "\n".join(data)
        )



def main():

    print("fetch")

    configs=fetch_all()


    print(
        "raw",
        len(configs)
    )


    configs=dedupe(configs)


    print(
        "unique",
        len(configs)
    )


    ranked=benchmark(configs)


    print(
        "alive",
        len(ranked)
    )


    final=[

        rename(
            x["config"]
        )

        for x in ranked

    ]


    final=[
        x for x in final if x
    ]



    for i in range(SUB_COUNT):

        part=final[
            i*SUB_LIMIT:
            (i+1)*SUB_LIMIT
        ]

        write(
            f"sub/general/sub{i+1}.txt",
            part
        )


    print(
        "done",
        len(final)
    )



if __name__=="__main__":

    main()
