/*
 * packet_capture.cpp
 * Network Monitor - C++ packet capture backend
 *
 * Compile:
 *   g++ -O2 -o packet_capture packet_capture.cpp -lpcap -ljsoncpp
 *   # or without jsoncpp:
 *   g++ -O2 -o packet_capture packet_capture.cpp -lpcap
 *
 * Run (needs root/sudo):
 *   sudo ./packet_capture [interface]   e.g. sudo ./packet_capture eth0
 *
 * Output: JSON lines on stdout, one per second aggregation window.
 */

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <iostream>
#include <unordered_map>
#include <string>
#include <chrono>
#include <csignal>
#include <cstring>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <set>

// ─── Data structures ────────────────────────────────────────────────────────

struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     protocol;   // IPPROTO_TCP / IPPROTO_UDP / ...

    bool operator==(const FlowKey& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               protocol == o.protocol;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = std::hash<std::string>{}(k.src_ip + k.dst_ip);
        h ^= std::hash<uint32_t>{}((uint32_t)k.src_port << 16 | k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct FlowStats {
    uint64_t bytes    = 0;
    uint64_t packets  = 0;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

struct HostStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_recv = 0;
    uint64_t pkts_sent  = 0;
    uint64_t pkts_recv  = 0;
};

// ─── Globals ────────────────────────────────────────────────────────────────

static std::unordered_map<FlowKey, FlowStats, FlowKeyHash> g_flows;
static std::unordered_map<std::string, HostStats>          g_hosts;
static uint64_t g_total_bytes   = 0;
static uint64_t g_total_packets = 0;
static volatile bool g_running  = true;
static auto g_window_start = std::chrono::steady_clock::now();

// ─── Helpers ────────────────────────────────────────────────────────────────

std::string proto_name(uint8_t p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTHER";
    }
}

// Escape a string for JSON
std::string json_str(const std::string& s) {
    return "\"" + s + "\"";
}

// ─── Anomaly detection (simple heuristics) ──────────────────────────────────

struct Alert {
    std::string type;
    std::string detail;
    std::string severity;   // "low" | "medium" | "high"
};

std::vector<Alert> detect_anomalies() {
    std::vector<Alert> alerts;

    // 1. Port scan: a single source contacting many distinct dst ports
    std::unordered_map<std::string, std::set<uint16_t>> src_ports;
    // (we'd need #include <set> — included below)
    // 2. High traffic host (> 10 MB in window)
    for (auto& [ip, hs] : g_hosts) {
        uint64_t total = hs.bytes_sent + hs.bytes_recv;
        if (total > 10 * 1024 * 1024) {
            alerts.push_back({"HIGH_BANDWIDTH", ip + " used " + std::to_string(total / 1024) + " KB", "medium"});
        }
    }
    // 3. Flow count spike
    if (g_flows.size() > 500) {
        alerts.push_back({"FLOW_SPIKE", "Active flows: " + std::to_string(g_flows.size()), "high"});
    }

    return alerts;
}

// ─── JSON snapshot output ───────────────────────────────────────────────────

void emit_snapshot() {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - g_window_start).count();

    // Build top-10 hosts by total bytes
    std::vector<std::pair<std::string, uint64_t>> host_list;
    for (auto& [ip, hs] : g_hosts)
        host_list.push_back({ip, hs.bytes_sent + hs.bytes_recv});
    std::sort(host_list.begin(), host_list.end(), [](auto& a, auto& b){ return a.second > b.second; });

    // Build top-10 flows by bytes
    std::vector<std::pair<FlowKey, FlowStats>> flow_list(g_flows.begin(), g_flows.end());
    std::sort(flow_list.begin(), flow_list.end(), [](auto& a, auto& b){ return a.second.bytes > b.second.bytes; });

    auto alerts = detect_anomalies();

    std::ostringstream js;
    js << "{";
    js << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << ",";
    js << "\"window_sec\":" << std::fixed << std::setprecision(2) << elapsed << ",";
    js << "\"total_bytes\":" << g_total_bytes << ",";
    js << "\"total_packets\":" << g_total_packets << ",";
    js << "\"active_flows\":" << g_flows.size() << ",";

    // hosts array
    js << "\"top_hosts\":[";
    int limit = std::min((int)host_list.size(), 10);
    for (int i = 0; i < limit; i++) {
        auto& [ip, _] = host_list[i];
        auto& hs = g_hosts[ip];
        if (i) js << ",";
        js << "{";
        js << "\"ip\":" << json_str(ip) << ",";
        js << "\"bytes_sent\":" << hs.bytes_sent << ",";
        js << "\"bytes_recv\":" << hs.bytes_recv << ",";
        js << "\"pkts_sent\":"  << hs.pkts_sent  << ",";
        js << "\"pkts_recv\":"  << hs.pkts_recv;
        js << "}";
    }
    js << "],";

    // flows array
    js << "\"top_flows\":[";
    int flimit = std::min((int)flow_list.size(), 10);
    for (int i = 0; i < flimit; i++) {
        auto& [fk, fs] = flow_list[i];
        if (i) js << ",";
        js << "{";
        js << "\"src_ip\":"   << json_str(fk.src_ip)    << ",";
        js << "\"dst_ip\":"   << json_str(fk.dst_ip)    << ",";
        js << "\"src_port\":" << fk.src_port             << ",";
        js << "\"dst_port\":" << fk.dst_port             << ",";
        js << "\"proto\":"    << json_str(proto_name(fk.protocol)) << ",";
        js << "\"bytes\":"    << fs.bytes                << ",";
        js << "\"packets\":"  << fs.packets;
        js << "}";
    }
    js << "],";

    // alerts
    js << "\"alerts\":[";
    for (size_t i = 0; i < alerts.size(); i++) {
        if (i) js << ",";
        js << "{";
        js << "\"type\":"     << json_str(alerts[i].type)     << ",";
        js << "\"detail\":"   << json_str(alerts[i].detail)   << ",";
        js << "\"severity\":" << json_str(alerts[i].severity);
        js << "}";
    }
    js << "]";

    js << "}";

    std::cout << js.str() << "\n";
    std::cout.flush();

    // Reset window
    g_flows.clear();
    g_hosts.clear();
    g_total_bytes   = 0;
    g_total_packets = 0;
    g_window_start  = now;
}

// ─── Packet handler ─────────────────────────────────────────────────────────

void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* header, const u_char* packet) {
    static auto last_emit = std::chrono::steady_clock::now();

    auto now = std::chrono::steady_clock::now();
    double since_emit = std::chrono::duration<double>(now - last_emit).count();
    if (since_emit >= 1.0) {
        emit_snapshot();
        last_emit = now;
    }

    // Parse Ethernet
    if (header->caplen < sizeof(struct ether_header)) return;
    auto* eth = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // Parse IP
    const u_char* ip_ptr = packet + sizeof(struct ether_header);
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    auto* iph = reinterpret_cast<const struct ip*>(ip_ptr);

    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->ip_dst, dst_buf, INET_ADDRSTRLEN);
    std::string src_ip(src_buf), dst_ip(dst_buf);

    uint32_t pkt_len = header->len;
    uint8_t  proto   = iph->ip_p;
    uint16_t src_port = 0, dst_port = 0;

    int ip_hlen = iph->ip_hl * 4;
    const u_char* transport = ip_ptr + ip_hlen;

    if (proto == IPPROTO_TCP && header->caplen >= sizeof(struct ether_header) + ip_hlen + sizeof(struct tcphdr)) {
        auto* tcph = reinterpret_cast<const struct tcphdr*>(transport);
        src_port = ntohs(tcph->th_sport);
        dst_port = ntohs(tcph->th_dport);
    } else if (proto == IPPROTO_UDP && header->caplen >= sizeof(struct ether_header) + ip_hlen + sizeof(struct udphdr)) {
        auto* udph = reinterpret_cast<const struct udphdr*>(transport);
        src_port = ntohs(udph->uh_sport);
        dst_port = ntohs(udph->uh_dport);
    }

    // Update flow
    FlowKey fk{src_ip, dst_ip, src_port, dst_port, proto};
    auto& fs = g_flows[fk];
    fs.bytes   += pkt_len;
    fs.packets += 1;
    fs.last_seen = now;
    if (fs.packets == 1) fs.first_seen = now;

    // Update hosts
    g_hosts[src_ip].bytes_sent += pkt_len;
    g_hosts[src_ip].pkts_sent  += 1;
    g_hosts[dst_ip].bytes_recv += pkt_len;
    g_hosts[dst_ip].pkts_recv  += 1;

    g_total_bytes   += pkt_len;
    g_total_packets += 1;
}

// ─── Main ───────────────────────────────────────────────────────────────────

void signal_handler(int) { g_running = false; }

int main(int argc, char* argv[]) {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];

    // Choose interface
    std::string iface;
    if (argc >= 2) {
        iface = argv[1];
    } else {
        pcap_if_t* devs;
        if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
            std::cerr << "[capture] No interfaces found: " << errbuf << "\n";
            return 1;
        }
        iface = devs->name;
        pcap_freealldevs(devs);
    }

    std::cerr << "[capture] Listening on interface: " << iface << "\n";

    pcap_t* handle = pcap_open_live(iface.c_str(), 65535, 1 /*promisc*/, 100 /*ms timeout*/, errbuf);
    if (!handle) {
        std::cerr << "[capture] pcap_open_live failed: " << errbuf << "\n";
        return 1;
    }

    // Only IPv4
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    g_window_start = std::chrono::steady_clock::now();

    while (g_running) {
        pcap_dispatch(handle, 100, packet_handler, nullptr);
    }

    emit_snapshot();  // final snapshot
    pcap_close(handle);
    std::cerr << "[capture] Stopped.\n";
    return 0;
}
