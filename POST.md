# NetWatch — Ho costruito un network monitor open source per la rete locale

Da tempo cercavo uno strumento che mi desse visibilità reale su cosa succede nella mia rete locale. I tool esistenti o sono troppo complessi (Wireshark, ntopng enterprise), o troppo limitati, o richiedono cloud. Così ho deciso di costruirne uno da zero.

**NetWatch** è un network monitor locale, completamente self-hosted, che combina cattura pacchetti in C++, un'API Python e una dashboard React in tempo reale.

---

## Come funziona

L'architettura è volutamente semplice e stratificata:

```
C++ (libpcap) → cattura pacchetti a livello kernel
      ↓ JSON line su stdout ogni secondo
Python Flask → aggrega dati, rileva anomalie, serve REST + SSE
      ↓ Server-Sent Events
React Dashboard → grafici live, mappa, network graph, alert
```

Nessun cloud, nessun agent remoto, nessuna telemetria. Tutto gira in locale.

---

## Cosa monitora

### Traffico in tempo reale
- Bandwidth e pacchetti/sec con grafici live (finestra 60 secondi)
- Top host per banda, separando traffico inviato e ricevuto
- Tutti i flussi attivi con IP sorgente/destinazione, porta, protocollo e dimensione
- Distribuzione protocolli (TCP / UDP / ICMP) aggiornata al secondo

### Rilevamento anomalie
Il motore di detection integrato identifica automaticamente comportamenti sospetti:

- **Port scan** — un host che contatta più di 20 porte distinte in 10 secondi
- **DNS tunneling** — pacchetti UDP/53 con dimensione media anomala (possibile esfiltrazione dati)
- **High bandwidth** — host che supera soglie configurabili (default 5 MB/s)
- **Porte sospette** — connessioni verso porte note per malware e C2 (IRC 6667, 4444, 31337…)
- **External scan** — un IP esterno che contatta più di 5 host interni
- **Flow spike** — picco improvviso nel numero di flussi attivi

Tutti gli alert hanno cooldown configurabile per evitare spam, severità (high/medium/low) e possono essere letti/silenziati dalla dashboard.

### Scansioni Nmap integrate
NetWatch include un'integrazione completa con Nmap, con supporto per tutti i principali tipi di scansione:

| Categoria | Tipi |
|-----------|------|
| Discovery | Ping sweep, ARP scan |
| Port scan | SYN stealth, TCP connect, UDP, ACK, NULL, FIN, Xmas, SCTP |
| Detection | Version detection, OS fingerprinting, Aggressive (-A) |
| Script NSE | vuln, auth, default, discovery, safe, broadcast |
| Evasione | Slow/paranoid (-T0), Fast (-T4 -F) |

Le scansioni vengono schedulate automaticamente o lanciate manualmente dalla UI, e i risultati — incluse le vulnerabilità trovate dagli script NSE — vengono salvati nel database e mostrati con i relativi CVE.

### Geolocalizzazione
Gli IP pubblici vengono arricchiti automaticamente con paese, città, ISP e ASN tramite ip-api.com (gratuito, senza chiave API) o MaxMind GeoLite2 in locale per chi vuole zero dipendenze esterne. La dashboard mostra una mappa mondiale con archi animati verso ogni connessione esterna attiva.

---

## La dashboard

Tutto si trova in un'unica interfaccia con nove sezioni:

- **Overview** — panoramica completa con tutti i KPI, grafici banda/pps, torta protocolli e alert recenti
- **Flussi** — tabella live filtrabile per IP, porta, protocollo con ordinamento e geolocalizzazione destinazione
- **Host** — inventario completo degli host visti con OS, MAC, vendor, banda e tag
- **Mappa Geo** — connessioni esterne sulla mappa mondiale con bandiera paese e provider
- **Network Graph** — grafo interattivo con simulazione fisica: nodi = host, archi = flussi, spessore = banda
- **Heatmap** — griglia ora × giorno della settimana per identificare pattern temporali nel traffico
- **Alert** — timeline, filtri per tipo e severità, gestione lettura
- **Nmap** — lancio scansioni con tutti i 16 tipi disponibili, progress live, storico e risultati porte
- **Vulnerabilità** — riepilogo CVE trovati, grafici per host e script NSE, severità

---

## Persistenza

Tutti i dati vengono salvati su SQLite con schema ottimizzato (WAL mode, indici, cascade delete):

- Snapshot di traffico al secondo (fino a 7 giorni, poi pruning automatico)
- Aggregate orarie per grafici storici a lungo termine
- Host noti con tutto l'inventario Nmap
- Scansioni e risultati porte
- Vulnerabilità con CVE estratti automaticamente dall'output degli script
- Alert con stato letto/non letto

---

## Stack tecnico

- **C++17** — cattura pacchetti con libpcap, parsing Ethernet/IP/TCP/UDP, rilevamento anomalie base, output JSON su stdout
- **Python 3.11+** — Flask, python-nmap, SQLite (stdlib), threading per concorrenza, SSE per push live
- **React + Recharts** — dashboard SPA, grafici area/barre/torta, canvas per network graph, D3 + TopoJSON per la mappa
- **SQLite** — database embedded, zero dipendenze esterne, WAL mode per scritture concorrenti

---

## Avvio rapido

```bash
# 1. Compila il backend C++
g++ -O2 -o capture/packet_capture capture/packet_capture.cpp -lpcap

# 2. Installa dipendenze Python
pip install flask flask-cors python-nmap

# 3. Avvia in demo mode (dati sintetici, senza root)
python server.py --demo

# 4. Avvia la dashboard React
cd dashboard && npm install recharts && npm run dev
```

Per il monitoraggio reale servono i privilegi root per libpcap e Nmap (per i scan SYN/OS/vuln).

---

## Roadmap

Alcune cose che ho in mente per le prossime versioni:

- [ ] Behavioral baseline con Z-score — imparare il "normale" di ogni host e alertare solo sulle deviazioni statistiche reali
- [ ] Passive OS fingerprinting (p0f-style) direttamente dal C++, senza scan attivi
- [ ] Rilevamento beaconing — connessioni periodiche a intervalli regolari, tipico di malware C2
- [ ] Webhook su alert verso Slack, Discord, Teams o PagerDuty
- [ ] Threat intelligence — confronto IP contro AbuseIPDB, Shodan e VirusTotal
- [ ] SNMP polling per router e switch
- [ ] Docker Compose per deploy in un comando
- [ ] Autenticazione JWT sulla dashboard

---

Il codice è modulare e pensato per essere esteso. Ogni componente (cattura, API, storage, scanner) è separato e sostituibile.

Se stai cercando visibilità sulla tua rete senza mandare dati da nessuna parte, potrebbe fare al caso tuo.

---

*Stack: C++ · Python · React · SQLite · libpcap · Nmap*
