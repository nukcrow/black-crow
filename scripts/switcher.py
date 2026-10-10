#!/usr/bin/env python3
"""nukcrow configuration collector.

Creates only sub1.txt ... sub20.txt and bot.txt under sub/general.
A successful TCP connection only establishes TCP reachability; it does not
validate a VLESS, VMess, Trojan, or Shadowsocks protocol handshake.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OUT_DIR = Path("sub/general")
REMARK = "nukcrow"
FETCH_TIMEOUT = 15
TCP_TIMEOUT = 2.0
FETCH_WORKERS = 32
TEST_WORKERS = 128
MAX_PER_SOURCE = 50_000
MAX_CANDIDATES = 60_000

# Exactly 20 general subscriptions, totaling 20,000 configs.
SUBS = tuple(
    [(f"sub{i}.txt", 2000) for i in range(1, 6)]
    + [(f"sub{i}.txt", 1000) for i in range(6, 11)]
    + [(f"sub{i}.txt", 500) for i in range(11, 21)]
)
TOTAL_CONFIGS = sum(size for _, size in SUBS)

# Paste only your own subscription URLs into these ten slots. No external
# source is prefilled, and bot.txt is otherwise generated as an empty file.
BOT_SOURCES = [
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
]
BOT_MAX_CONFIGS = 5000

# Sources retained from the uploaded collector plus the URLs in the user's
# supplied list. Invalid/duplicate lines are discarded by normalized_sources().
RAW_SOURCES = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vless_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/vmess_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/trojan_iran.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/ss_iran.txt",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/refs/heads/main/public/Top500.txt",
    "https://raw.githubusercontent.com/snaCW/Config/main/config.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/refs/heads/main/main/mix.txt",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no10.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_013.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_014.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub7.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-69.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_015.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub10.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_001.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt",
    "https://raw.githubusercontent.com/mehrtat/vless-collector/main/vless.txt",
    "https://raw.githubusercontent.com/alexantSWE/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/firefoxmmx2/v2rayshare_subcription/main/subscription/clash_sub.yaml",
    "https://raw.githubusercontent.com/Roywaller/clash_subscription/main/clash_subscription.txt",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc0.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc1.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc2.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc3.yaml",
    "https://raw.githubusercontent.com/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter/main/APIs/sc4.yaml",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/clash/naidounode.txt",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/clash/clash.provider.yaml",
    "https://raw.githubusercontent.com/leetomlee123/freenode/main/README.md",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "https://raw.githubusercontent.com/mgit0001/test_clash/main/heima.txt",
    "https://raw.githubusercontent.com/mai19950/clashgithub_com/main/site",
    "https://raw.githubusercontent.com/mai19950/sites/main/sub/v2ray/base64",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/shahidbhutta/Clash/main/Router",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
    "https://raw.githubusercontent.com/mfbpn/tg_mfbpn_sub/main/trial.yaml",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/clash",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray.txt",
    "https://raw.githubusercontent.com/vxiaov/free_proxies/main/links.txt",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/main/v2ray/v2rayshare.txt",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml",
    "https://raw.githubusercontent.com/ts-sf/fly/main/clash",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/yudou66.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/clashmeta.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/ndnode.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodev2ray.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/nodefree.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/v2rayshare.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/wenode.txt",
    "https://raw.githubusercontent.com/ggborr/FREEE-VPN/main/4V2ray",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links2.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/main/data/V2.txt",
    "https://raw.githubusercontent.com/peacefish/nodefree/main/sub/proxy_cf.yaml",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/V2.txt",
    "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/utils/pool/output.yaml",
    "https://raw.githubusercontent.com/yorkLiu/FreeV2RayNode/main/v2ray.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ss.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/ssr.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/trojan.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vless.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/list/vmess.txt",
    "https://raw.githubusercontent.com/NiceVPN123/NiceVPN/main/Clash.yaml",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/trinity_clash.yaml",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/VM_TrinityBase",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/SS/TrinityBase",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/ss_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/trojan_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vless_iran.txt",
    "https://raw.githubusercontent.com/darknessm427/IranConfigCollector/main/bulk/vmess_iran.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    "https://fastly.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://fastly.jsdelivr.net/gh/ALIILAPRO/v2rayng-config@master/sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
    "https://github.com/BreakingTechFr/Proxy_Free/blob/main/proxies/all.txt",
    "https://manager.farsonline24.ir",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/_pool.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/_previous.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/Pawdroid.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/SFZY666.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/aiboboxx.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/anaer.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/blue-Youtube.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/changfengoss.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/chengaopan.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/clashfree.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/coldwater-10.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/ermaozi.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/hkaa0.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/mahdibland.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/peasoft.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/ripaojiedian.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/snakem982.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/soroushmirzaei.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/trial.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/tssf.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/ttvg.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/xrayvip.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/yudou.yaml",
    "https://raw.githubusercontent.com/sinspired/airport/main/subs/zhangkaiitugithub.yaml",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/blues.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/main/output_configs/mixed/Leon406/SubCrawler/sub/share/a11.yaml#sinspired/subs-check",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/main/output_configs/clash/Ruk1ng001.yaml#sinspired/subs-check",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/main/output_configs/surfboard/Ruk1ng001.yaml#sinspired/subs-check",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/main/output_configs/surfboard/Barabama_ndnode.yaml#sinspired/subs-check",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Cable.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless#sinspired/subs-check",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-14.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-19.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/all_valid_proxies.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/shahidbhutta/Clash/main/Router#sinspired/subs-check",
    "https://raw.githubusercontent.com/Arefgh72/v2ray-proxy-pars-tester/main/output/github_all.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/ovmvo/SubShare/main/sub/permanent/mihomo.yaml#sinspired/subs-check",
    "https://raw.githubusercontent.com/liMilCo/v2r/main/base64/2.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/liMilCo/v2r/main/configs.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/Delta-Kronecker/Xray/main/data/working_url/working_all_urls.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub2.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix#sinspired/subs-check",
    "https://raw.githubusercontent.com/SamanGho/v2ray_collector/main/v2tel_links1.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/old-data/RAW.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/Proxies.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/allive.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/main/proxies/all.txt#sinspired/subs-check",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://github.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/vless",
    "https://raw.githubusercontent.com/pachangcheng/mianfeijiedian/refs/heads/main/should.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ssr.txt",
    "https://raw.githubusercontent.com/ccpthisbigdog/freedomchina/refs/heads/main/subdom.txt",
    "https://cdn.jsdelivr.net/gh/ccpthisbigdog/freedomchina/refs/heads/main/subdom.txt",
    "https://raw.githubusercontent.com/ccpthisbigdog/freedomchina/refs/heads/main/clab.yaml",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-protocol-vl",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-protocol-tr",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/refs/heads/main/output/base64/mix-protocol-vm",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/hk/light.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/hk/vless.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/hk/vmess.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/hk/all.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
    "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
    "https://fastly.jsdelivr.net/gh/dongchengjie/airport@main/subs/merged/tested_within.yaml",
    "https://raw.githubusercontent.com/PuddinCat/BestClash/main/proxies.yaml",
    "https://raw.githubusercontent.com/SnapdragonLee/SystemProxy/master/dist/clash_config.yaml",
    "https://raw.githubusercontent.com/mermeroo/V2RAY-CLASH-BASE64-Subscription.Links/main/SUB%20LINKS/All_base64.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/v2ray-subscription.txt",
    "https://raw.githubusercontent.com/free-nodes/clashfree/main/clash.yaml",
    "https://raw.githubusercontent.com/vxiaov/free_proxy_ss/main/v2ray",
    "https://anaer.github.io/Sub/proxies.yaml",
    "https://git.io/emzclash",
    "https://git.io/emzv2ray",
]

URI_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>'\"]+", re.I)
HOST_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss"}


def decode64(value: str) -> str:
    value = value.strip().replace("-", "+").replace("_", "/")
    if not value:
        return ""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "ignore")
    except (ValueError, UnicodeDecodeError):
        return ""


def normalize_text(value: str) -> str:
    return (value or "").replace("\\/", "/").replace("\\.", ".").replace("&#x20;", " ")


def extract_uris(text: str) -> list[str]:
    items = []
    for uri in URI_PATTERN.findall(normalize_text(text)):
        uri = uri.rstrip(",;.)]}")
        if uri:
            items.append(uri)
    return items


def valid_host(host: str) -> bool:
    host = host.strip().strip("[]").lower().rstrip(".")
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return all(HOST_LABEL.fullmatch(label) for label in host.split("."))


def decode_ss_userinfo(value: str) -> str:
    value = unquote(value)
    if ":" in value:
        return value
    return decode64(value)


def parse_uri(uri: str) -> dict | None:
    uri = uri.strip()
    scheme = uri.partition("://")[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        return None
    try:
        if scheme == "vmess":
            data = json.loads(decode64(uri.split("://", 1)[1]))
            host, port, user_id = str(data.get("add", "")), int(str(data.get("port", ""))), str(data.get("id", ""))
            uuid.UUID(user_id)
            if not valid_host(host):
                return None
            return {"scheme": scheme, "host": host.lower().rstrip("."), "port": port, "identity": user_id.lower(), "data": data}

        if scheme == "ss":
            body = uri.split("://", 1)[1].split("#", 1)[0]
            if "@" in body:
                userinfo, address = body.rsplit("@", 1)
            else:
                decoded = decode64(body)
                if "@" not in decoded:
                    return None
                userinfo, address = decoded.rsplit("@", 1)
            host, port_text = address.rsplit(":", 1)
            credentials = decode_ss_userinfo(userinfo)
            if ":" not in credentials or not all(credentials.split(":", 1)):
                return None
            port = int(port_text)
            if not valid_host(host):
                return None
            return {"scheme": scheme, "host": host.lower().rstrip("."), "port": port, "identity": credentials}

        parsed = urlparse(uri)
        host, port, identity = parsed.hostname, parsed.port, unquote(parsed.username or "")
        if not host or not identity or not valid_host(host):
            return None
        if scheme == "vless":
            uuid.UUID(identity)
        params = parse_qs(parsed.query, keep_blank_values=True)
        return {
            "scheme": scheme, "host": host.lower().rstrip("."), "port": port,
            "identity": identity, "params": params,
        }
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def valid_config(uri: str) -> bool:
    parsed = parse_uri(uri)
    if not parsed:
        return False
    port = parsed.get("port")
    return isinstance(port, int) and 1 <= port <= 65535


def fingerprint(uri: str) -> str:
    data = parse_uri(uri)
    if data is None:
        return hashlib.sha256(uri.encode()).hexdigest()
    params = data.get("params", {})
    key = "|".join(str(part) for part in (
        data["scheme"], data["identity"], data["host"], data["port"],
        params.get("security", [""])[0], params.get("type", [""])[0],
        params.get("sni", [""])[0], params.get("host", [""])[0],
        params.get("path", [""])[0], params.get("flow", [""])[0],
    ))
    return hashlib.sha256(key.encode()).hexdigest()


def quality_score(uri: str) -> int:
    data = parse_uri(uri)
    if data is None:
        return -999
    score = {"vless": 12, "trojan": 10, "vmess": 8, "ss": 7}[data["scheme"]]
    params = data.get("params", {})
    security = params.get("security", [""])[0].lower()
    transport = params.get("type", [""])[0].lower()
    score += {"reality": 12, "tls": 10, "none": 3}.get(security, 0)
    score += {"ws": 8, "xhttp": 8, "grpc": 7, "tcp": 6, "httpupgrade": 6}.get(transport, 0)
    score += 3 * sum(bool(params.get(key, [""])[0]) for key in ("sni", "host", "path"))
    if params.get("flow", [""])[0].lower() == "xtls-rprx-vision":
        score += 5
    return score


def render(uri: str) -> str:
    return uri.split("#", 1)[0].strip() + "#" + REMARK


def normalized_sources(values: Iterable[str]) -> list[str]:
    result, seen = [], set()
    for value in values:
        url = value.strip()
        if not url:
            continue
        # A fragment in the supplied list is a label, not part of the fetch URL.
        url = url.split("#", 1)[0]
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def fetch_source(url: str) -> list[str]:
    for attempt in range(3):
        try:
            request = Request(url, headers={
                "User-Agent": "nukcrow-collector/1.0",
                "Accept": "text/plain, text/yaml, application/json, */*",
            })
            with urlopen(request, timeout=FETCH_TIMEOUT) as response:
                if response.status != 200:
                    continue
                charset = response.headers.get_content_charset() or "utf-8"
                text = normalize_text(response.read().decode(charset, "replace"))
            configs = extract_uris(text)
            if not configs:
                configs = extract_uris(decode64(text.strip()))
            valid = [item for item in configs if valid_config(item)][:MAX_PER_SOURCE]
            print(f"[FETCH] {url} -> {len(valid)}")
            return valid
        except (HTTPError, URLError, OSError) as exc:
            if attempt == 2:
                print(f"[FETCH-ERROR] {url} -> {exc}")
            time.sleep(0.4 * (attempt + 1))
    return []


def collect_sources(sources: Iterable[str]) -> list[str]:
    sources = normalized_sources(sources)
    print(f"[SOURCE] usable sources = {len(sources)}")
    gathered: list[str] = []
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = [pool.submit(fetch_source, source) for source in sources]
        for future in as_completed(futures):
            try:
                gathered.extend(future.result())
            except Exception as exc:
                # A malformed response must not cancel the remaining sources.
                print(f"[SOURCE-ERROR] skipped source: {exc}")
    unique, seen = [], set()
    for uri in gathered:
        token = fingerprint(uri)
        if token not in seen and valid_config(uri):
            seen.add(token)
            unique.append(uri)
            if len(unique) >= MAX_CANDIDATES:
                break
    print(f"[COLLECT] structurally valid unique configs = {len(unique)}")
    return unique


def tcp_reachability(uri: str) -> float | None:
    data = parse_uri(uri)
    if data is None:
        return None
    started = time.perf_counter()
    try:
        with socket.create_connection((data["host"], data["port"]), timeout=TCP_TIMEOUT):
            return (time.perf_counter() - started) * 1000
    except OSError:
        return None


def benchmark(configs: list[str]) -> list[tuple[float, int, str]]:
    print(f"[TCP] checking reachability for {len(configs)} configs; this is not a protocol health check.")
    results = []
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futures = {pool.submit(tcp_reachability, uri): uri for uri in configs}
        for count, future in enumerate(as_completed(futures), 1):
            latency = future.result()
            if latency is not None:
                uri = futures[future]
                results.append((latency, quality_score(uri), uri))
            if count % 500 == 0:
                print(f"[TCP] {count}/{len(configs)} reachable={len(results)}")
    results.sort(key=lambda item: (item[0], -item[1]))
    return results


def select_unique(results: list[tuple[float, int, str]], limit: int) -> list[str]:
    selected, seen = [], set()
    for _, _, uri in results:
        token = fingerprint(uri)
        if token not in seen:
            seen.add(token)
            selected.append(uri)
        if len(selected) == limit:
            break
    return selected


def prepare_output_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    expected = {name for name, _ in SUBS} | {"bot.txt"}
    for path in OUT_DIR.glob("*.txt"):
        if path.name not in expected:
            path.unlink()
            print(f"[REMOVE] {path.name}")


def write_configs(filename: str, configs: list[str]) -> None:
    path = OUT_DIR / filename
    rendered = [render(uri) for uri in configs]
    path.write_text("\n".join(rendered) + ("\n" if rendered else ""), encoding="utf-8")
    print(f"[WRITE] {filename} = {len(rendered)}")


def write_subscriptions(selected: list[str]) -> None:
    if len(selected) != TOTAL_CONFIGS:
        raise RuntimeError(f"Need exactly {TOTAL_CONFIGS} TCP-reachable unique configs; got {len(selected)}.")
    offset = 0
    for filename, size in SUBS:
        chunk = selected[offset:offset + size]
        if len(chunk) != size:
            raise RuntimeError(f"{filename} requires {size} configs.")
        write_configs(filename, chunk)
        offset += size


def write_bot() -> None:
    # The ten slots above are intentionally empty in the delivered template.
    configs = collect_sources(BOT_SOURCES)
    selected = select_unique(benchmark(configs), BOT_MAX_CONFIGS) if configs else []
    write_configs("bot.txt", selected)


def verify_outputs() -> None:
    expected = {name: size for name, size in SUBS} | {"bot.txt": None}
    actual = {path.name for path in OUT_DIR.glob("*.txt")}
    if actual != set(expected):
        raise RuntimeError(f"Unexpected output files: {sorted(actual)}")
    seen = set()
    for filename, size in SUBS:
        lines = (OUT_DIR / filename).read_text(encoding="utf-8").splitlines()
        if len(lines) != size:
            raise RuntimeError(f"{filename}: expected {size}, got {len(lines)}")
        for line in lines:
            if not line.endswith("#" + REMARK):
                raise RuntimeError(f"{filename} has an incorrect remark.")
            token = fingerprint(line.rsplit("#", 1)[0])
            if token in seen:
                raise RuntimeError(f"Duplicate config across output subscriptions: {filename}")
            seen.add(token)
    if len(seen) != TOTAL_CONFIGS:
        raise RuntimeError(f"Expected {TOTAL_CONFIGS} unique output configs, got {len(seen)}")
    print(f"[VERIFY] exactly 20 general files, {TOTAL_CONFIGS} unique configs, and bot.txt.")


def main() -> None:
    print(f"nukcrow collector: {TOTAL_CONFIGS} configs across 20 general subscriptions")
    prepare_output_dir()
    configs = collect_sources(RAW_SOURCES)
    selected = select_unique(benchmark(configs), TOTAL_CONFIGS)
    write_subscriptions(selected)
    write_bot()
    verify_outputs()
    print("DONE")


if __name__ == "__main__":
    main()

