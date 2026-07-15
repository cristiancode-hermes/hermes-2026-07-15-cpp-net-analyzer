#include <net-analyzer/analyzer.hpp>
#include <fstream>
#include <sstream>
#include <ranges>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <spdlog/spdlog.h>

// ── InterfaceStats ──

json InterfaceStats::to_json() const {
  return json{
    {"interface", name},
    {"rx_bytes", rx_bytes},
    {"rx_packets", rx_packets},
    {"rx_errors", rx_errors},
    {"rx_dropped", rx_dropped},
    {"tx_bytes", tx_bytes},
    {"tx_packets", tx_packets},
    {"tx_errors", tx_errors},
    {"tx_dropped", tx_dropped},
    {"total_bytes", total_bytes()}
  };
}

double InterfaceStats::utilization_pct(uint64_t speed_bps) const {
  if (speed_bps == 0) return 0.0;
  double bytes_per_sec = static_cast<double>(rx_bytes + tx_bytes);
  return (bytes_per_sec * 8.0) / speed_bps * 100.0;
}

// ── TcpConnection ──

json TcpConnection::to_json() const {
  return json{
    {"slot", slot},
    {"local_address", local_addr},
    {"local_port", local_port},
    {"remote_address", remote_addr},
    {"remote_port", remote_port},
    {"state", state},
    {"uid", uid},
    {"process", process_name}
  };
}

// ── Tcp state names ──

std::string_view NetAnalyzer::tcp_state_name(uint8_t state) {
  static const std::unordered_map<uint8_t, std::string_view> names = {
    {0x01, "ESTABLISHED"}, {0x02, "SYN_SENT"}, {0x03, "SYN_RECV"},
    {0x04, "FIN_WAIT1"},   {0x05, "FIN_WAIT2"},  {0x06, "TIME_WAIT"},
    {0x07, "CLOSE"},       {0x08, "CLOSE_WAIT"}, {0x09, "LAST_ACK"},
    {0x0A, "LISTEN"},      {0x0B, "CLOSING"}
  };
  auto it = names.find(state);
  return it != names.end() ? it->second : "UNKNOWN";
}

static uint32_t hex_to_u32(const std::string& hex_str) {
  return static_cast<uint32_t>(std::stoul(hex_str, nullptr, 16));
}

static uint16_t hex_to_u16(const std::string& hex_str) {
  return static_cast<uint16_t>(std::stoul(hex_str, nullptr, 16));
}

static std::string hex_ip_to_dotted(const std::string& hex_ip) {
  // Hex IP is in little-endian hex: 0100007F -> 127.0.0.1
  if (hex_ip.length() < 8) return "0.0.0.0";
  uint32_t ip = hex_to_u32(hex_ip);
  auto a = static_cast<uint8_t>(ip & 0xFF);
  auto b = static_cast<uint8_t>((ip >> 8) & 0xFF);
  auto c = static_cast<uint8_t>((ip >> 16) & 0xFF);
  auto d = static_cast<uint8_t>((ip >> 24) & 0xFF);
  return std::to_string(a) + '.' + std::to_string(b) + '.' +
         std::to_string(c) + '.' + std::to_string(d);
}

// ── NetAnalyzer ──

NetAnalyzer::NetAnalyzer() {
  spdlog::debug("NetAnalyzer initialized");
}

Result<std::vector<InterfaceStats>> NetAnalyzer::read_interfaces() const {
  std::ifstream file("/proc/net/dev");
  if (!file.is_open()) {
    return std::unexpected(Error{1, "Cannot open /proc/net/dev"});
  }

  std::vector<InterfaceStats> interfaces;
  std::string line;
  
  // Skip first two header lines
  std::getline(file, line);
  std::getline(file, line);

  while (std::getline(file, line)) {
    auto colon_pos = line.find(':');
    if (colon_pos == std::string::npos) continue;

    InterfaceStats iface;
    iface.name = line.substr(0, colon_pos);
    // Trim whitespace (both leading and trailing)
    while (!iface.name.empty() && iface.name.back() == ' ')
      iface.name.pop_back();
    while (!iface.name.empty() && iface.name.front() == ' ')
      iface.name.erase(0, 1);

    std::istringstream ss(line.substr(colon_pos + 1));
    ss >> iface.rx_bytes >> iface.rx_packets >> std::skipws
       >> iface.rx_errors >> iface.rx_dropped
       >> iface.tx_bytes >> iface.tx_packets
       >> iface.tx_errors >> iface.tx_dropped;

    interfaces.push_back(std::move(iface));
  }

  return interfaces;
}

Result<std::vector<std::string>> NetAnalyzer::list_interfaces() const {
  auto ifaces = read_interfaces();
  if (!ifaces) return std::unexpected(ifaces.error());

  std::vector<std::string> names;
  names.reserve(ifaces->size());
  for (const auto& iface : *ifaces) {
    names.push_back(iface.name);
  }
  return names;
}

static std::string get_process_name_for_inode(uint64_t inode) {
  if (inode == 0) return "";
  // Search /proc/[pid]/fd/ for matching socket inode
  for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
    std::string pid_str = entry.path().filename().string();
    if (!std::ranges::all_of(pid_str, [](char c) { return std::isdigit(c); }))
      continue;
    
    std::string fd_dir = "/proc/" + pid_str + "/fd";
    std::error_code ec;
    for (const auto& fd_entry : std::filesystem::directory_iterator(fd_dir, ec)) {
      if (ec) break;
      std::error_code lec;
      auto target = std::filesystem::read_symlink(fd_entry.path(), lec);
      if (lec) continue;
      
      auto target_str = target.string();
      if (target_str.find("socket:[" + std::to_string(inode) + "]") != std::string::npos) {
        // Found matching process, read its comm
        std::ifstream comm("/proc/" + pid_str + "/comm");
        std::string comm_name;
        std::getline(comm, comm_name);
        return comm_name;
      }
    }
  }
  return "";
}

Result<std::vector<TcpConnection>> NetAnalyzer::read_tcp_file(const std::string& path) const {
  std::ifstream file(path);
  if (!file.is_open()) {
    return std::vector<TcpConnection>{};  // TCP6 may not exist — not an error
  }

  std::vector<TcpConnection> connections;
  std::string line;
  std::getline(file, line);  // header

  while (std::getline(file, line)) {
    std::istringstream ss(line);
    TcpConnection conn;

    std::string slot_str, local_str, remote_str, state_str;
    std::string tx_rx_str, tr_str, uid_str, timeout_str, inode_str;
    std::string rest;

    std::getline(ss, slot_str, ':');
    // Consume whitespace
    ss >> local_str >> remote_str >> state_str;
    ss >> tx_rx_str >> tr_str >> uid_str >> timeout_str >> inode_str;
    std::getline(ss, rest);

    conn.slot = std::stoi(slot_str);

    // Parse local: hex_ip:port
    auto lcol = local_str.find(':');
    if (lcol != std::string::npos) {
      conn.local_addr = hex_ip_to_dotted(local_str.substr(0, lcol));
      conn.local_port = hex_to_u16(local_str.substr(lcol + 1));
    }

    // Parse remote
    auto rcol = remote_str.find(':');
    if (rcol != std::string::npos) {
      conn.remote_addr = hex_ip_to_dotted(remote_str.substr(0, rcol));
      conn.remote_port = hex_to_u16(remote_str.substr(rcol + 1));
    }

    uint8_t tcp_state = static_cast<uint8_t>(hex_to_u16(state_str));
    conn.state = std::string(tcp_state_name(tcp_state));

    if (!uid_str.empty()) {
      conn.uid = std::stoul(uid_str);
    }

    // Get process name from inode
    if (!inode_str.empty()) {
      uint64_t inode = std::stoull(inode_str);
      conn.process_name = get_process_name_for_inode(inode);
    }

    connections.push_back(std::move(conn));
  }

  return connections;
}

Result<std::vector<TcpConnection>> NetAnalyzer::read_connections() const {
  auto result = read_tcp_file("/proc/net/tcp");
  if (!result) return result;

  // Try TCP6 as well
  auto tcp6 = read_tcp_file("/proc/net/tcp6");
  if (tcp6) {
    result->insert(result->end(),
      std::make_move_iterator(tcp6->begin()),
      std::make_move_iterator(tcp6->end()));
  }

  return result;
}

Result<NetAnalyzer::Snapshot> NetAnalyzer::snapshot() const {
  auto ifaces = read_interfaces();
  if (!ifaces) return std::unexpected(ifaces.error());

  Snapshot snap;
  snap.reserve(ifaces->size());
  for (const auto& iface : *ifaces) {
    snap.emplace_back(iface.name, std::make_pair(iface.rx_bytes, iface.tx_bytes));
  }
  return snap;
}

std::vector<BandwidthDelta> NetAnalyzer::calculate_bandwidth(
  const Snapshot& prev, const Snapshot& curr, double interval_s) {
  
  std::vector<BandwidthDelta> deltas;
  for (const auto& [name, rx_tx] : curr) {
    auto it = std::ranges::find_if(prev, [&](const auto& p) { return p.first == name; });
    if (it == prev.end()) continue;

    double rx_kbps = (static_cast<double>(rx_tx.first) - it->second.first) / interval_s / 1024.0 * 8.0;
    double tx_kbps = (static_cast<double>(rx_tx.second) - it->second.second) / interval_s / 1024.0 * 8.0;
    
    // Skip interfaces with no traffic
    if (rx_kbps < 0.001 && tx_kbps < 0.001) continue;

    deltas.push_back(BandwidthDelta{name, std::max(0.0, rx_kbps), std::max(0.0, tx_kbps)});
  }
  return deltas;
}

Result<json> NetAnalyzer::system_summary() const {
  auto ifaces = read_interfaces();
  if (!ifaces) return std::unexpected(ifaces.error());

  json summary = json::object();
  
  for (const auto& iface : *ifaces) {
    summary[iface.name] = iface.to_json();
  }

  // Add total
  uint64_t total_rx = 0, total_tx = 0;
  for (const auto& iface : *ifaces) {
    total_rx += iface.rx_bytes;
    total_tx += iface.tx_bytes;
  }
  summary["_total"] = {{"rx_bytes", total_rx}, {"tx_bytes", total_tx}};

  return summary;
}
