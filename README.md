[392.webm](https://github.com/user-attachments/assets/ad8c58a9-14f7-4de9-b47e-bac86172eb2b)
# ⬡ NetWatch v4

**Real-time network monitor and security tool** — cattura, analizza e visualizza il traffico di rete con rilevamento anomalie, scansioni Nmap integrate, geolocalizzazione e dashboard live.

```
┌─────────────────────────────────────────────────────────┐
│  ⬡ NetWatch v4          LIVE ●          09:41:22        │
│  BW 2.3 MB/s  PPS 1842  FLUSSI 47  ALERT 2  UP 00:12    │
├──────────────┬──────────────────────────────────────────┤
│ Overview     │  Bandwidth (60s)           2.3 MB/s peak │
│ 🌍 Mappa Geo │  ▁▂▄▆█▇▅▃▂▄▆▇█▅▃▁▂▄▆▇█   ~~~~~~~~~~~~~~  │
│ Network Graph│                                          │
│ Flussi       │  Top Host per Banda                      │
│ Host         │  192.168.1.10  ████████  1.1 MB/s        │
│ Heatmap      │  192.168.1.20  ████      0.4 MB/s        │
│ Alert (2)    │  10.0.0.5      ██        0.2 MB/s        │
│ Analytics    │                                          │
│ DNS          │  Protocolli:  TCP 72%  UDP 24%  ICMP 4%  │
│ Nmap         │                                          │
│ Vulnerabilità│  ⚠ PORT_SCAN  192.168.1.50 → 24 port/10s │
│ ⚙ Config     │  ✓ DNS_TUNNEL  10.0.0.15 DNS avg 512B    │
└──────────────┴──────────────────────────────────────────┘
```

---

## ✨ Features

| Categoria | Feature |
|-----------|---------|
| **Monitoraggio** | Bandwidth live · Flussi TCP/UDP/ICMP · Pacchetti/s · Top host real-time |
| **Sicurezza** | Port scan detection · DNS tunneling · Bandwidth anomalie · Porte sospette · IP esterni che scansionano host interni |
| **Visualizzazione** | Area chart live · Network graph animato · Mappa geo mondiale · Heatmap settimanale |
| **Analytics** | Storico 24h/48h · Top IP · Top porte · Timeline alert · Trend banda |
| **Scansione** | 19 tipi di scan Nmap · Vuln scan · Version detection · OS detection · Scheduling automatico |
| **Sicurezza accesso** | JWT auth · bcrypt · Rate limiting · Auto-refresh token · Cambio password |
| **Export** | CSV alert · CSV host · JSON snapshot · (PCAP via capture) |
| **Config runtime** | Soglie alert · GeoIP on/off · Porte sospette · Retention DB · Rate limit |
| **i18n** | Italiano 🇮🇹 · English 🇬🇧 (estendibile) |
| **Deploy** | Docker Compose · Script bash · Venv Python |

---

## 🚀 Quick Start

### Con Docker (consigliato)

```bash
git clone https://github.com/youruser/netwatch.git
cd netwatch

# Copia e configura le variabili d'ambiente
cp .env.example .env
# nano .env  ← cambia NETWATCH_SECRET_KEY e NETWATCH_ADMIN_PASS !

# Avvia tutto con un comando
docker compose up
```

Apri **http://localhost:8080** → Login: `admin` / `netwatch`

> **Nota:** Il container backend gira con `network_mode: host` e `cap_add: NET_RAW` per poter catturare i pacchetti.

---

### Senza Docker (sviluppo / demo)

```bash
# Demo mode — nessuna root, nessun pcap, dati sintetici
./start.sh --demo

# Oppure manuale
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python server.py --demo --port 5000

# Frontend (altro terminale)
cd dashboard && npm install && npm run dev
```

Apri **http://localhost:5173**

---

### Con interfaccia reale (richiede root)

```bash
sudo python server.py --interface eth0

# o con auto-discovery dell'interfaccia
sudo python server.py
```

---

## 🏗 Architettura

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

### Flusso dati

```
Rete → [C++ libpcap] → stdout JSON → [Python server.py]
                                          ├── enrich() → GeoIP, anomalie
                                          ├── db.py → SQLite
                                          └── SSE broadcast → [React UI]
```

### Stack tecnologico

| Layer | Tecnologie |
|-------|-----------|
| **Capture** | C++17, libpcap |
| **Backend** | Python 3.12, Flask 3, SQLite, bcrypt, PyJWT |
| **Frontend** | React 18, Vite 5, Recharts, SVG Canvas |
| **Deploy** | Docker, Nginx, Bash |
| **Sicurezza** | JWT HS256, bcrypt, rate limiting, CORS |

---

## 🔐 Autenticazione

NetWatch usa JWT con firma HMAC-SHA256.

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"netwatch"}'

# Usa il token
curl http://localhost:5000/api/snapshot \
  -H "Authorization: Bearer <token>"
```

**Variabili d'ambiente:**
```bash
NETWATCH_SECRET_KEY=cambia-questo-valore   # obbligatorio in produzione
NETWATCH_ADMIN_USER=admin
NETWATCH_ADMIN_PASS=netwatch               # cambia dopo il primo login
NETWATCH_JWT_EXPIRY=86400                  # secondi (default 24h)
NETWATCH_AUTH_ENABLED=true                 # false per disabilitare (dev only)
```

---

## 📡 API Reference

### Endpoints principali

| Metodo | Path | Descrizione |
|--------|------|-------------|
| `GET` | `/api/status` | Status server (no auth) |
| `POST` | `/api/auth/login` | Login → JWT |
| `POST` | `/api/auth/refresh` | Rinnova token |
| `GET` | `/api/stream` | SSE live stream |
| `GET` | `/api/snapshot` | Ultimo snapshot |
| `GET` | `/api/history?limit=60` | Storico snapshot |
| `GET` | `/api/bandwidth/hourly?hours=24` | Banda per ora |
| `GET` | `/api/analytics/summary` | Analytics 24h complete |
| `GET` | `/api/analytics/top-ips?hours=24` | Top IP per traffico |
| `GET` | `/api/analytics/top-ports` | Top porte |
| `GET` | `/api/analytics/alert-timeline` | Timeline alert |
| `GET` | `/api/alerts` | Lista alert |
| `POST` | `/api/alerts/ack_all` | Segna tutti letti |
| `GET` | `/api/hosts` | Host noti |
| `GET` | `/api/scans` | Lista scansioni Nmap |
| `POST` | `/api/scans` | Avvia scansione |
| `GET` | `/api/config` | Config corrente |
| `PATCH` | `/api/config` | Aggiorna config |
| `GET` | `/api/export/alerts.csv` | Export CSV alert |
| `GET` | `/api/export/hosts.csv` | Export CSV host |
| `GET` | `/api/export/snapshots.json` | Export JSON snapshot |

---

## 🔍 Rilevamento anomalie

Il server esegue 6 controlli in real-time su ogni snapshot:

| Tipo | Condizione | Severità |
|------|-----------|---------|
| `HIGH_BANDWIDTH` | Host supera soglia B/s configurabile | medium |
| `FLOW_SPIKE` | Flussi attivi > soglia configurabile | high |
| `PORT_SCAN` | Stesso IP → 20+ porte diverse in 10s | high |
| `SUSPICIOUS_PORT` | Traffico verso porte hacker note | high |
| `DNS_TUNNEL` | Query DNS con payload medio > 400B | medium |
| `EXT_SCAN` | IP esterno → 5+ host interni diversi | high |

Tutte le soglie sono configurabili dal **pannello Config** senza riavvio.

---

## 🌍 Internazionalizzazione

Il sistema i18n è pronto all'uso con ~120 chiavi:

```jsx
import { useI18n } from './i18n.jsx'

function MyComponent() {
  const { t, lang, changeLang } = useI18n()
  return <h1>{t("tab.overview")}</h1>
}
```

Per aggiungere una lingua, aggiungi un blocco in `dashboard/src/i18n.jsx`:
```js
const translations = {
  it: { ... },
  en: { ... },
  de: { ... },  // ← aggiungi qui
}
```

---

## ⚙️ Configurazione runtime

Dal pannello **Config** nella UI (o via API `PATCH /api/config`):

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `alert_threshold_bps` | 5 MB/s | Soglia bandwidth per alert |
| `alert_threshold_flows` | 300 | Soglia flussi attivi |
| `alert_cooldown_sec` | 30 | Secondi tra alert dello stesso tipo |
| `geoip_enabled` | true | Abilita risoluzione GeoIP |
| `suspicious_ports` | `[6667,4444,1337,31337,9001]` | Porte da monitorare |
| `prune_keep_days` | 7 | Giorni di retention nel DB |
| `rate_limit_max` | 300 | Max richieste API per minuto per IP |
| `language` | it | Lingua UI (it / en) |

---

## 🗺 Roadmap

- [ ] **WebSocket** al posto di SSE per comunicazione bidirezionale
- [ ] **Threat Intelligence** — integrazione AbuseIPDB / VirusTotal
- [ ] **Notifiche** — Telegram, Discord webhook, email
- [ ] **Device discovery** — hostname, MAC vendor, OS guess automatico
- [ ] **ML anomaly detection** — dopo accumulo storico serio
- [ ] **Plugin system** — `/plugins/` directory per custom detector
- [ ] **Multi-user** — account multipli con ruoli
- [ ] **Cloud sync** — backup automatico del DB
- [ ] **PCAP export** — cattura selettiva di flussi specifici
- [ ] **Mobile responsive** — layout adattivo per smartphone

---

## 🛠 Sviluppo

```bash
# Backend con hot-reload
source venv/bin/activate
FLASK_ENV=development python server.py --demo

# Frontend con hot-reload
cd dashboard && npm run dev

# Build frontend per produzione
cd dashboard && npm run build

# Rebuild immagini Docker
docker compose build --no-cache
docker compose up
```

**Log strutturati (JSON) in produzione:**
```bash
NETWATCH_LOG_FORMAT=json python server.py 2>&1 | jq .
```

---

## 📄 Licenza

MIT License — vedi `LICENSE` per dettagli.

---

<div align="center">
  <sub>Built with ⬡ by NetWatch contributors</sub>
</div>
