<div align="center">

<img src="https://capsule-render.vercel.app/api?type=slice&color=0:050505,50:11151a,100:1b1f24&height=190&section=header&text=black-crow&fontSize=54&fontColor=8A8F98&animation=fadeIn&fontAlignY=38&desc=free%20v2ray%20%C2%B7%20vless%20%C2%B7%20vmess%20%C2%B7%20hysteria2&descSize=14&descColor=484F58&descAlignY=58" width="100%"/>

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&weight=400&size=15&duration=3200&pause=1100&color=8A8F98&background=00000000&center=true&vCenter=true&width=520&lines=collect.;test.;rank.;repeat+every+3+hours." alt="black-crow"/>

<br/>

```bash
$ black-crow --status
fetching · deduplicating · testing · publishing
```

<br/>

<img src="https://img.shields.io/github/last-commit/nukcrow/black-crow?style=for-the-badge&labelColor=050505&color=1b1f24&label=UPDATED"/>
<img src="https://img.shields.io/github/stars/nukcrow/black-crow?style=for-the-badge&labelColor=050505&color=1b1f24"/>
<img src="https://img.shields.io/github/forks/nukcrow/black-crow?style=for-the-badge&labelColor=050505&color=1b1f24"/>
<img src="https://img.shields.io/github/license/nukcrow/black-crow?style=for-the-badge&labelColor=050505&color=1b1f24"/>

<br/>

<a href="https://t.me/nukcrow"><img src="https://img.shields.io/badge/CHANNEL-@nukcrow-1b1f24?style=for-the-badge&logo=telegram&logoColor=8A8F98&labelColor=050505"/></a>
<a href="https://t.me/nukcrowvpnbot"><img src="https://img.shields.io/badge/VPN-@nukcrowvpnbot-1b1f24?style=for-the-badge&logo=telegram&logoColor=8A8F98&labelColor=050505"/></a>

</div>

<br/>

## ◈ About

An automated collector for high-quality V2Ray / Xray subscriptions. Every 3 hours it pulls configs from curated sources, removes duplicates, tests connectivity, ranks them by quality, and publishes ready-to-use subscription links.

## ◈ Subscriptions

| Type | Link |
|:--|:--|
| **All** | `https://raw.githubusercontent.com/nukcrow/black-crow/main/sub/all.txt` |
| **VLESS** | `https://raw.githubusercontent.com/nukcrow/black-crow/main/sub/vless.txt` |
| **VMess** | `https://raw.githubusercontent.com/nukcrow/black-crow/main/sub/vmess.txt` |
| **Hysteria2** | `https://raw.githubusercontent.com/nukcrow/black-crow/main/sub/hysteria2.txt` |

## ◈ Usage

```bash
1. Copy a subscription link
2. Open your client → Subscriptions → Add
3. Paste the link → Update
```

**Compatible clients:** v2rayNG · NekoBox · Hiddify · v2Box · Streisand · sing-box

## ◈ Pipeline

```text
sources ──▶ fetch ──▶ dedup ──▶ TCP test ──▶ classify ──▶ publish
                                                │
                              TLS · WS · gRPC · xHTTP · Reality
```

- **Fetch:** parallel download from curated public sources
- **Dedup:** one entry per unique server identity
- **Test:** TCP connectivity and latency check
- **Classify:** preferred transports are ranked first
- **Publish:** protocol-split files and bundled subscriptions

## ◈ Disclaimer

Configs are collected from public sources and provided as-is, with no guarantee of availability or security. Use at your own risk.

<div align="center">

<br/>

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&size=11&duration=4000&pause=1500&color=484F58&background=00000000&center=true&vCenter=true&width=400&lines=%5B+star+if+useful+%5D;%5B+updated+every+3h+%5D;%5B+nukcrow+%5D" alt="footer"/>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:050505,50:11151a,100:1b1f24&height=80&section=footer" width="100%"/>

</div>
