// i18n.js – NetWatch internationalization
// Supports: it (Italian), en (English)

const translations = {
  it: {
    // Nav tabs
    "tab.overview":   "Overview",
    "tab.map":        "🌍 Mappa Geo",
    "tab.graph":      "Network Graph",
    "tab.flows":      "Flussi",
    "tab.hosts":      "Host",
    "tab.heatmap":    "Heatmap",
    "tab.alerts":     "Alert",
    "tab.analytics":  "Analytics",
    "tab.dns":        "DNS",
    "tab.nmap":       "Nmap",
    "tab.vulns":      "Vulnerabilità",
    "tab.config":     "⚙ Config",

    // Header
    "header.live":    "LIVE",
    "header.offline": "OFFLINE",
    "header.bw":      "BW",
    "header.pps":     "PPS",
    "header.flows":   "FLUSSI",
    "header.alerts":  "ALERT",
    "header.uptime":  "UPTIME",

    // Stats
    "stat.bandwidth":  "Bandwidth",
    "stat.packets_s":  "Pacchetti/s",
    "stat.flows":      "Flussi",
    "stat.hosts_seen": "Host visti",
    "stat.alerts":     "Alert",
    "stat.uptime":     "Uptime",
    "stat.peak":       "peak",
    "stat.live":       "live",
    "stat.active":     "attivi",
    "stat.in_window":  "in finestra",
    "stat.unread":     "non letti",
    "stat.monitoring": "monitoraggio",

    // Charts
    "chart.bw_live":      "Bandwidth Live (60s)",
    "chart.pps":          "Pacchetti / sec",
    "chart.protocols":    "Protocolli",
    "chart.top_hosts":    "Top Host per Banda (real-time)",
    "chart.heatmap":      "Heatmap Attività Rete",
    "chart.bw_hourly":    "Banda per Ora (sessione corrente)",
    "chart.alert_timeline": "Timeline Alert",

    // Analytics
    "analytics.title":    "Analytics Storici",
    "analytics.24h":      "Ultimi 24h",
    "analytics.top_ips":  "Top IP",
    "analytics.top_ports":"Top Porte",
    "analytics.bw_trend": "Trend Bandwidth",
    "analytics.total_bytes": "Totale Traffico",
    "analytics.peak_bps":    "Picco Banda",
    "analytics.unique_hosts":"Host Unici",
    "analytics.alerts":      "Alert 24h",
    "analytics.alerts_high": "Alert High",

    // Flows
    "flows.filter":   "Filtra IP, porta, protocollo…",
    "flows.all":      "Tutti",
    "flows.count":    "flussi",
    "flows.src":      "Src IP",
    "flows.dst":      "Dst IP",
    "flows.dst_port": "Porta Dst",
    "flows.proto":    "Proto",
    "flows.bytes":    "Bytes",
    "flows.packets":  "Packets",
    "flows.http_host":"HTTP Host",
    "flows.waiting":  "In attesa di traffico…",
    "flows.no_filter":"Nessun flusso con questo filtro",

    // Hosts
    "hosts.filter":   "Filtra per IP o hostname…",
    "hosts.count":    "host noti",
    "hosts.ip":       "IP",
    "hosts.hostname": "Hostname",
    "hosts.os":       "OS",
    "hosts.mac":      "MAC / Vendor",
    "hosts.type":     "Tipo",
    "hosts.sent":     "↑ Inviati",
    "hosts.recv":     "↓ Ricevuti",
    "hosts.last_seen":"Ultimo Visto",
    "hosts.internal": "interno",
    "hosts.external": "esterno",
    "hosts.empty":    "Nessun host noto ancora. Il DB si popola con il traffico.",

    // Alerts
    "alerts.all":     "Tutti gli alert",
    "alerts.high":    "Solo High",
    "alerts.medium":  "Solo Medium",
    "alerts.mark_all":"Segna tutti letti",
    "alerts.count":   "alert",
    "alerts.unread":  "non letti",
    "alerts.ack":     "ack",
    "alerts.empty":   "Nessun alert ricevuto — la rete è silenziosa.",
    "alerts.no_filter":"Nessun alert con questo filtro.",
    "alerts.recent":  "Alert Recenti",

    // Map
    "map.title":      "Mappa Connessioni Globali (dati reali)",
    "map.external_ips":"IP Esterni",
    "map.none":       "Nessun IP esterno rilevato ancora.",
    "map.detected":   "IP esterni rilevati",
    "map.high":       "Alto",
    "map.medium":     "Medio",
    "map.low":        "Basso",

    // Heatmap
    "heatmap.days":   ["Lun","Mar","Mer","Gio","Ven","Sab","Dom"],
    "heatmap.less":   "Meno",
    "heatmap.more":   "Più",
    "heatmap.sub":    "Banda accumulata per ora × giorno (sessione corrente)",

    // Nmap
    "nmap.launch":    "Lancia Scansione",
    "nmap.target":    "Target",
    "nmap.ports":     "Porte",
    "nmap.start":     "Avvia Scansione ↗",
    "nmap.running":   "Scansione in corso…",
    "nmap.scans":     "Scansioni dal Server",
    "nmap.none":      "Nessuna scansione ancora.",
    "nmap.results":   "Risultati",
    "nmap.port":      "Porta",
    "nmap.state":     "Stato",
    "nmap.service":   "Servizio",
    "nmap.version":   "Versione",

    // Vulns
    "vulns.total":    "Totale Vuln",
    "vulns.high":     "Alta Severità",
    "vulns.medium":   "Media Sev.",
    "vulns.hosts":    "Host Affetti",
    "vulns.empty":    "Nessuna vulnerabilità trovata ancora.",
    "vulns.tip":      "Lancia una scansione Vuln Scan dalla tab Nmap per popolare questa sezione.",

    // Config
    "config.title":        "Pannello Configurazione",
    "config.alert_bps":    "Soglia Banda Alert (B/s)",
    "config.alert_flows":  "Soglia Flussi Alert",
    "config.cooldown":     "Cooldown Alert (sec)",
    "config.geoip":        "GeoIP abilitato",
    "config.susp_ports":   "Porte Sospette (JSON array)",
    "config.prune_days":   "Giorni Retention DB",
    "config.rate_limit":   "Rate Limit (req/min)",
    "config.language":     "Lingua",
    "config.dark_mode":    "Dark Mode",
    "config.save":         "Salva",
    "config.saved":        "Salvato ✓",

    // Auth
    "auth.title":    "NetWatch Login",
    "auth.username": "Username",
    "auth.password": "Password",
    "auth.login":    "Accedi",
    "auth.logging":  "Accesso…",
    "auth.error":    "Credenziali non valide",
    "auth.logout":   "Logout",
    "auth.change_pw":"Cambia Password",

    // DNS
    "dns.queries":  "Query DNS Live",
    "dns.beaconing":"Beaconing Rilevato",
    "dns.none":     "Nessuna query DNS catturata ancora.\n(richiede traffico UDP porta 53)",
    "dns.no_beacon":"Nessun beaconing rilevato.",

    // General
    "general.waiting": "In attesa di dati…",
    "general.no_data": "Nessun dato",
    "general.loading": "Caricamento…",
    "general.error":   "Errore",
    "general.refresh": "Aggiorna",
    "general.export":  "Esporta",
    "general.from":    "da",
  },

  en: {
    "tab.overview":   "Overview",
    "tab.map":        "🌍 Geo Map",
    "tab.graph":      "Network Graph",
    "tab.flows":      "Flows",
    "tab.hosts":      "Hosts",
    "tab.heatmap":    "Heatmap",
    "tab.alerts":     "Alerts",
    "tab.analytics":  "Analytics",
    "tab.dns":        "DNS",
    "tab.nmap":       "Nmap",
    "tab.vulns":      "Vulnerabilities",
    "tab.config":     "⚙ Config",

    "header.live":    "LIVE",
    "header.offline": "OFFLINE",
    "header.bw":      "BW",
    "header.pps":     "PPS",
    "header.flows":   "FLOWS",
    "header.alerts":  "ALERTS",
    "header.uptime":  "UPTIME",

    "stat.bandwidth":  "Bandwidth",
    "stat.packets_s":  "Packets/s",
    "stat.flows":      "Flows",
    "stat.hosts_seen": "Hosts seen",
    "stat.alerts":     "Alerts",
    "stat.uptime":     "Uptime",
    "stat.peak":       "peak",
    "stat.live":       "live",
    "stat.active":     "active",
    "stat.in_window":  "in window",
    "stat.unread":     "unread",
    "stat.monitoring": "monitoring",

    "chart.bw_live":       "Live Bandwidth (60s)",
    "chart.pps":           "Packets / sec",
    "chart.protocols":     "Protocols",
    "chart.top_hosts":     "Top Hosts by Bandwidth (real-time)",
    "chart.heatmap":       "Network Activity Heatmap",
    "chart.bw_hourly":     "Bandwidth by Hour (current session)",
    "chart.alert_timeline":"Alert Timeline",

    "analytics.title":    "Historical Analytics",
    "analytics.24h":      "Last 24h",
    "analytics.top_ips":  "Top IPs",
    "analytics.top_ports":"Top Ports",
    "analytics.bw_trend": "Bandwidth Trend",
    "analytics.total_bytes": "Total Traffic",
    "analytics.peak_bps":    "Peak Bandwidth",
    "analytics.unique_hosts":"Unique Hosts",
    "analytics.alerts":      "Alerts 24h",
    "analytics.alerts_high": "High Alerts",

    "flows.filter":   "Filter IP, port, protocol…",
    "flows.all":      "All",
    "flows.count":    "flows",
    "flows.src":      "Src IP",
    "flows.dst":      "Dst IP",
    "flows.dst_port": "Dst Port",
    "flows.proto":    "Proto",
    "flows.bytes":    "Bytes",
    "flows.packets":  "Packets",
    "flows.http_host":"HTTP Host",
    "flows.waiting":  "Waiting for traffic…",
    "flows.no_filter":"No flows match this filter",

    "hosts.filter":   "Filter by IP or hostname…",
    "hosts.count":    "known hosts",
    "hosts.ip":       "IP",
    "hosts.hostname": "Hostname",
    "hosts.os":       "OS",
    "hosts.mac":      "MAC / Vendor",
    "hosts.type":     "Type",
    "hosts.sent":     "↑ Sent",
    "hosts.recv":     "↓ Recv",
    "hosts.last_seen":"Last Seen",
    "hosts.internal": "internal",
    "hosts.external": "external",
    "hosts.empty":    "No known hosts yet. DB populates with traffic.",

    "alerts.all":     "All alerts",
    "alerts.high":    "High only",
    "alerts.medium":  "Medium only",
    "alerts.mark_all":"Mark all read",
    "alerts.count":   "alerts",
    "alerts.unread":  "unread",
    "alerts.ack":     "ack",
    "alerts.empty":   "No alerts received — the network is quiet.",
    "alerts.no_filter":"No alerts match this filter.",
    "alerts.recent":  "Recent Alerts",

    "map.title":      "Global Connections Map (real data)",
    "map.external_ips":"External IPs",
    "map.none":       "No external IPs detected yet.",
    "map.detected":   "external IPs detected",
    "map.high":       "High",
    "map.medium":     "Medium",
    "map.low":        "Low",

    "heatmap.days":   ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],
    "heatmap.less":   "Less",
    "heatmap.more":   "More",
    "heatmap.sub":    "Accumulated bandwidth per hour × day (current session)",

    "nmap.launch":    "Launch Scan",
    "nmap.target":    "Target",
    "nmap.ports":     "Ports",
    "nmap.start":     "Start Scan ↗",
    "nmap.running":   "Scan running…",
    "nmap.scans":     "Scans from Server",
    "nmap.none":      "No scans yet.",
    "nmap.results":   "Results",
    "nmap.port":      "Port",
    "nmap.state":     "State",
    "nmap.service":   "Service",
    "nmap.version":   "Version",

    "vulns.total":    "Total Vulns",
    "vulns.high":     "High Severity",
    "vulns.medium":   "Medium Sev.",
    "vulns.hosts":    "Affected Hosts",
    "vulns.empty":    "No vulnerabilities found yet.",
    "vulns.tip":      "Run a Vuln Scan from the Nmap tab to populate this section.",

    "config.title":       "Configuration Panel",
    "config.alert_bps":   "Alert Bandwidth Threshold (B/s)",
    "config.alert_flows": "Alert Flows Threshold",
    "config.cooldown":    "Alert Cooldown (sec)",
    "config.geoip":       "GeoIP enabled",
    "config.susp_ports":  "Suspicious Ports (JSON array)",
    "config.prune_days":  "DB Retention Days",
    "config.rate_limit":  "Rate Limit (req/min)",
    "config.language":    "Language",
    "config.dark_mode":   "Dark Mode",
    "config.save":        "Save",
    "config.saved":       "Saved ✓",

    "auth.title":    "NetWatch Login",
    "auth.username": "Username",
    "auth.password": "Password",
    "auth.login":    "Login",
    "auth.logging":  "Logging in…",
    "auth.error":    "Invalid credentials",
    "auth.logout":   "Logout",
    "auth.change_pw":"Change Password",

    "dns.queries":  "Live DNS Queries",
    "dns.beaconing":"Beaconing Detected",
    "dns.none":     "No DNS queries captured yet.\n(requires UDP port 53 traffic)",
    "dns.no_beacon":"No beaconing detected.",

    "general.waiting": "Waiting for data…",
    "general.no_data": "No data",
    "general.loading": "Loading…",
    "general.error":   "Error",
    "general.refresh": "Refresh",
    "general.export":  "Export",
    "general.from":    "from",
  },
};

// React hook for translations
import { createContext, useContext, useState, useCallback } from "react";

export const I18nContext = createContext(null);

export function I18nProvider({ children }) {
  const [lang, setLang] = useState(
    () => localStorage.getItem("netwatch_lang") || "en"
  );

  const t = useCallback(
    (key, fallback) => {
      const val = translations[lang]?.[key] ?? translations["it"]?.[key] ?? fallback ?? key;
      return val;
    },
    [lang]
  );

  const changeLang = useCallback((newLang) => {
    if (translations[newLang]) {
      setLang(newLang);
      localStorage.setItem("netwatch_lang", newLang);
    }
  }, []);

  return (
    <I18nContext.Provider value={{ t, lang, changeLang, langs: Object.keys(translations) }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}

export default translations;
