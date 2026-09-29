<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:161b22,100:21262d&height=220&section=header&text=nukcrow&fontSize=65&fontColor=8A8F98&animation=fadeIn&fontAlignY=38" width="100%"/>

<br/>

<img src="https://readme-typing-svg.demolab.com/?font=Arial&weight=500&size=20&duration=3000&pause=1200&color=A9A9C8&background=00000000&center=true&vCenter=true&width=700&lines=V2Ray+%2F+Xray+Configuration+Platform;Automated+Collection+%E2%80%A2+Testing+%E2%80%A2+Quality+Ranking;Built+with+Python+%2B+GitHub+Actions" alt="NukCrow"/>

<br/><br/>

<p>
  <a href="https://github.com/nukcrow/black-crow">
    <img src="https://img.shields.io/github/stars/nukcrow/black-crow?style=flat-square&color=161b22&labelColor=0d1117&logo=github&logoColor=8A8F98"/>
  </a>
  <a href="https://github.com/nukcrow/black-crow/network/members">
    <img src="https://img.shields.io/github/forks/nukcrow/black-crow?style=flat-square&color=161b22&labelColor=0d1117&logo=github&logoColor=8A8F98"/>
  </a>
  <a href="https://github.com/nukcrow/black-crow/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/nukcrow/black-crow/collector.yml?style=flat-square&color=161b22&labelColor=0d1117&logo=githubactions&logoColor=8A8F98"/>
  </a>
</p>

</div>

---

## `01` — What is NukCrow?

**NukCrow** is an automated V2Ray / Xray configuration aggregation platform.

It continuously collects configurations from multiple public sources, normalizes them, removes duplicates, tests connectivity, ranks reachable configurations, and publishes clean subscription files.

```text
Sources
   │
   ▼
┌──────────────┐
│   Collector  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Normalize   │
│  & Dedup     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Connectivity │
│    Tests     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Quality Rank │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Subscription │
│    Output    │
└──────────────┘
```

---

## `02` — Supported Protocols

<div align="center">

| Protocol | Status |
|:---:|:---:|
| **VLESS** | `● Active` |
| **VMess** | `● Active` |
| **Trojan** | `● Active` |
| **Shadowsocks** | `● Active` |
| **Hysteria2** | `● Active` |

</div>

---

## `03` — Why NukCrow?

> **Collect less noise. Keep more usable configurations.**

NukCrow is designed around an automated pipeline rather than simply downloading configuration lists.

- `Multi-source` aggregation
- `Duplicate` detection
- `Connectivity` testing
- `Quality` filtering
- `Automatic` subscription generation
- `GitHub Actions` automation
- `10-config` subscription chunks
- Continuous updates

---

## `04` — Architecture

```text
                    ┌─────────────────────┐
                    │     Public Sources  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   NukCrow Collector │
                    │       Python        │
                    └──────────┬──────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
        ┌──────────────┐              ┌──────────────┐
        │   Normalize  │              │   Deduplicate│
        └──────┬───────┘              └──────┬───────┘
               └──────────────┬──────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ Connectivity Tests  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Quality Ranking   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    sub/general/     │
                    │  10-config chunks   │
                    └─────────────────────┘
```

---

## `05` — Automated Pipeline

NukCrow is designed to run automatically through GitHub Actions.

```text
┌─────────────────────────────────────────┐
│             GitHub Actions              │
├─────────────────────────────────────────┤
│                                         │
│   Fetch → Parse → Clean → Test → Rank   │
│                         ↓               │
│                     Publish             │
│                                         │
└─────────────────────────────────────────┘
```

No manual collection is required once the workflow is configured.

---

## `06` — Project Structure

```text
black-crow/
│
├── .github/
│   └── workflows/
│
├── collector/
│
├── sub/
│   └── general/
│
├── docs/
│
├── requirements.txt
├── LICENSE
└── README.md
```

---

## `07` — Quick Start

```bash
git clone https://github.com/nukcrow/black-crow.git

cd black-crow

pip install -r requirements.txt
```

Run the collector:

```bash
python collector.py
```

Generated subscriptions are stored under:

```text
sub/general/
```

---

## `08` — Telegram

<div align="center">

<table>
<tr>
<td align="center" width="520">

<br/>

<img src="https://cdn.simpleicons.org/telegram/8A8F98" width="55"/>

### Telegram

`Official NukCrow Services`

<br/>

<a href="https://t.me/nukcrow">

**📢 CHANNEL**

`@nukcrow`

</a>

<br/><br/>

<a href="https://t.me/Nukcrowbot">

**💬 ADMIN SUPPORT**

`@Nukcrowbot`

</a>

<br/><br/>

<a href="https://t.me/nukcrowvpnbot">

**⚡ CONFIGURATION BOT**

`@nukcrowvpnbot`

</a>

<br/><br/>

</td>
</tr>
</table>

</div>

---

## `09` — Disclaimer

NukCrow aggregates publicly available configuration data.

The project does not operate or control third-party servers, networks, or configurations.

Users are responsible for complying with the laws, regulations, and terms applicable to their use of any configuration obtained through this project.

---

<div align="center">

<br/>

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:0d1117,100:161b22&height=80&section=footer&text=nukcrow&fontSize=28&fontColor=8A8F98&animation=fadeIn" width="100%"/>

<sub>

**NukCrow** · Built for automation. Designed for simplicity.

</sub>

</div>
