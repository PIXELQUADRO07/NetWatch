[392.webm](https://github.com/user-attachments/assets/0a7fcc6e-7330-4c1e-bf60-7e642ab8987c)

# ⬡ NetWatch v4

Real-time network monitor and security tool — Capture, analyze, and visualize network traffic with anomaly detection, integrated Nmap scans, geolocation, and live dashboards.

![JavaScript](https://img.shields.io/badge/JavaScript-48.4%25-F7DF1E?logo=javascript&logoColor=black)
![Python](https://img.shields.io/badge/Python-41.2%25-3776AB?logo=python&logoColor=white)
![C++](https://img.shields.io/badge/C%2B%2B-5.6%25-00599C?logo=cplusplus&logoColor=white)
![Shell](https://img.shields.io/badge/Shell-2.7%25-121011?logo=gnu-bash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Anomaly Detection](#anomaly-detection)
- [Configuration](#configuration)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Dashboard Preview

```
┌─────────────────────────────────────────────────────────┐
│  ⬡ NetWatch v4          LIVE ●          09:41:22        │
│  BW 2.3 MB/s  PPS 1842  FLOWS 47  ALERT 2  UP 00:12    │
├──────────────┬──────────────────────────────────────────┤
│ Overview     │  Bandwidth (60s)           2.3 MB/s peak │
│ 🌍 Geo Map   │  ▁▂▄▆█▇▅▃▂▄▆▇█▅▃▁▂▄▆▇█   ~~~~~~~~~~~~~~  │
│ Network Graph│                                          │
│ Flows        │  Top Host by Bandwidth                   │
│ Host         │  192.168.1.10  ████████  1.1 MB/s        │
│ Heatmap      │  192.168.1.20  ████      0.4 MB/s        │
│ Alert (2)    │  10.0.0.5      ██        0.2 MB/s        │
│ Analytics    │                                          │
│ DNS          │  Protocols:  TCP 72%  UDP 24%  ICMP 4%  │
│ Nmap         │                                          │
│ Vulnerabilità│  ⚠ PORT_SCAN  192.168.1.50 → 24 port/10s │
│ ⚙ Config     │  ✓ DNS_TUNNEL  10.0.0.15 DNS avg 512B    │
└──────────────┴──────────────────────────────────────────┘
```

## ✨ Features

| Category | Feature |
|----------|---------|
| **Monitoring** | Live bandwidth · TCP/UDP/ICMP flows · Packets/s · Top hosts real-time |
| **Security** | Port scan detection · DNS tunneling · Bandwidth anomalies · Suspicious ports · External IPs scanning internal hosts |
| **Visualization** | Live area chart · Animated network graph · World geo map · Weekly heatmap |
| **Analytics** | 24h/48h history · Top IPs · Top ports · Alert timeline · Bandwidth trends |
| **Scanning** | 19 Nmap scan types · Vuln scan · Version detection · OS detection · Auto scheduling |
| **Access Security** | JWT auth · bcrypt · Rate limiting · Auto token refresh · Password change |
| **Export** | CSV alerts · CSV hosts · JSON snapshot · (PCAP via capture) |
| **Runtime Config** | Alert thresholds · GeoIP on/off · Suspicious ports · DB retention · Rate limit |
| **Internationalization** | Italian 🇮🇹 · English 🇬🇧 (extensible) |
| **Deploy** | Docker Compose · Bash script · Python Venv |

## 🚀 Quick Start

### Prerequisites

- **Docker + Docker Compose** (recommended) or
- **Python 3.12+** with pip and Node.js 18+

### With Docker (recommended)

```bash
git clone https://github.com/PIXELQUADRO07/netwatch.git
cd netwatch

# Copy and configure environment variables
cp .env.example .env
# nano .env  ← change NETWATCH_SECRET_KEY and NETWATCH_ADMIN_PASS !

# Start everything with one command
docker compose up
```

Open **http://localhost:8080** → Login: `admin` / `netwatch`

> **Note:** The backend container runs with `network_mode: host` and `cap_add: NET_RAW` to capture packets.

### Without Docker (development / demo)

**Demo mode — no root, no pcap, synthetic data:**

```bash
./start.sh --demo
```

**Or manual setup:**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python server.py --demo --port 5000

# Frontend (another terminal)
cd dashboard && npm install && npm run dev
```

Open **http://localhost:5173**

### With real interface (requires root)

```bash
sudo python server.py --interface eth0

# or with auto-discovery of interface
sudo python server.py
```

## 🏗 Architecture

```
netwatch/
├── server.py            ← Flask API server (entry point)
├── db.py                ← SQLite persistence layer
├── auth.py              ← JWT authentication + bcrypt
├── logger.py            ← Structured logging (JSON / TTY)
├── geoip.py             ← GeoIP resolver (MaxMind / ipapi fallback)
├── nmap_scanner.py      ← Nmap wrapper + scheduler
├── capture/
│   └── packet_capture.cpp  ← C++ binary: raw packet capture via libpcap
├── dashboard/           ← React + Vite frontend
│   └── src/
│       ├── App.jsx      ← Main UI (12 tabs, SSE, charts, map)
│       ├── auth.jsx     ← AuthProvider + LoginScreen
│       ├── i18n.jsx     ← I18nProvider + translations
│       └── ConfigPanel.jsx
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── nginx.conf
└── start.sh             ← Quick start script
```

### Data Flow

```
Network → [C++ libpcap] → stdout JSON → [Python server.py]
                                           ├── enrich() → GeoIP, anomalies
                                           ├── db.py → SQLite
                                           └── SSE broadcast → [React UI]
```

### Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Capture** | C++17, libpcap |
| **Backend** | Python 3.12, Flask 3, SQLite, bcrypt, PyJWT |
| **Frontend** | React 18, Vite 5, Recharts, SVG Canvas |
| **Deploy** | Docker, Nginx, Bash |
| **Security** | JWT HS256, bcrypt, rate limiting, CORS |

## 🔐 Authentication

NetWatch uses JWT with HMAC-SHA256 signature.

### Login

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"netwatch"}'
```

### Use the token

```bash
curl http://localhost:5000/api/snapshot \
  -H "Authorization: Bearer <token>"
```

### Environment variables

```bash
NETWATCH_SECRET_KEY=change-this-value   # mandatory in production
NETWATCH_ADMIN_USER=admin
NETWATCH_ADMIN_PASS=netwatch               # change after first login
NETWATCH_JWT_EXPIRY=86400                  # seconds (default 24h)
NETWATCH_AUTH_ENABLED=true                 # false to disable (dev only)
```

## 📡 API Reference

### Main Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Server status (no auth) |
| POST | `/api/auth/login` | Login → JWT |
| POST | `/api/auth/refresh` | Refresh token |
| GET | `/api/stream` | SSE live stream |
| GET | `/api/snapshot` | Latest snapshot |
| GET | `/api/history?limit=60` | Snapshot history |
| GET | `/api/bandwidth/hourly?hours=24` | Hourly bandwidth |
| GET | `/api/analytics/summary` | Complete 24h analytics |
| GET | `/api/analytics/top-ips?hours=24` | Top IPs by traffic |
| GET | `/api/analytics/top-ports` | Top ports |
| GET | `/api/analytics/alert-timeline` | Alert timeline |
| GET | `/api/alerts` | Alert list |
| POST | `/api/alerts/ack_all` | Mark all as read |
| GET | `/api/hosts` | Known hosts |
| GET | `/api/scans` | Nmap scans list |
| POST | `/api/scans` | Start scan |
| GET | `/api/config` | Current config |
| PATCH | `/api/config` | Update config |
| GET | `/api/export/alerts.csv` | Export CSV alerts |
| GET | `/api/export/hosts.csv` | Export CSV hosts |
| GET | `/api/export/snapshots.json` | Export JSON snapshots |

## 🔍 Anomaly Detection

The server runs 6 real-time checks on every snapshot:

| Type | Condition | Severity |
|------|-----------|----------|
| HIGH_BANDWIDTH | Host exceeds configurable B/s threshold | medium |
| FLOW_SPIKE | Active flows > configurable threshold | high |
| PORT_SCAN | Same IP → 20+ different ports in 10s | high |
| SUSPICIOUS_PORT | Traffic to known hacker ports | high |
| DNS_TUNNEL | DNS query with average payload > 400B | medium |
| EXT_SCAN | External IP → 5+ different internal hosts | high |

All thresholds are configurable from the Config panel without restart.

## ⚙️ Configuration

### Runtime Configuration (Config Panel)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `alert_threshold_bps` | 5 MB/s | Bandwidth alert threshold |
| `alert_threshold_flows` | 300 | Active flows threshold |
| `alert_cooldown_sec` | 30 | Seconds between same-type alerts |
| `geoip_enabled` | true | Enable GeoIP resolution |
| `suspicious_ports` | [6667,4444,1337,31337,9001] | Ports to monitor |
| `prune_keep_days` | 7 | DB retention days |
| `rate_limit_max` | 300 | Max API requests per minute per IP |
| `language` | en | UI language (it / en) |

## 🌍 Internationalization

The i18n system is ready to use with ~120 keys:

```javascript
import { useI18n } from './i18n.jsx'

function MyComponent() {
  const { t, lang, changeLang } = useI18n()
  return <h1>{t("tab.overview")}</h1>
}
```

To add a language, add a block in `dashboard/src/i18n.jsx`:

```javascript
const translations = {
  it: { ... },
  en: { ... },
  de: { ... },  // ← add here
}
```

## 🛠 Development

### Backend with hot-reload

```bash
source venv/bin/activate
FLASK_ENV=development python server.py --demo
```

### Frontend with hot-reload

```bash
cd dashboard && npm run dev
```

### Build frontend for production

```bash
cd dashboard && npm run build
```

### Rebuild Docker images

```bash
docker compose build --no-cache
docker compose up
```

### Structured logs (JSON) in production

```bash
NETWATCH_LOG_FORMAT=json python server.py 2>&1 | jq .
```

## 🗺 Roadmap

- [ ] WebSocket instead of SSE for bidirectional communication
- [ ] Threat Intelligence — AbuseIPDB / VirusTotal integration
- [ ] Notifications — Telegram, Discord webhook, email
- [ ] Device discovery — hostname, MAC vendor, OS auto-detection
- [ ] ML anomaly detection — after serious history accumulation
- [ ] Plugin system — `/plugins/` directory for custom detectors
- [ ] Multi-user — multiple accounts with roles
- [ ] Cloud sync — automatic DB backup
- [ ] PCAP export — selective capture of specific flows
- [ ] Mobile responsive — adaptive layout for smartphones

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request** with a clear description

### Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Keep commits atomic and descriptive

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

Built with ⬡ by [NetWatch contributors](https://github.com/PIXELQUADRO07/NetWatch/graphs/contributors)
