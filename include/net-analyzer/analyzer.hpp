#ifndef NET_ANALYZER_NET_ANALYZER_HPP
#define NET_ANALYZER_NET_ANALYZER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <expected>
#include <nlohmann/json.hpp>
#include <chrono>

using json = nlohmann::json;

// ── Data structures ──

struct Error {
  int code;
  std::string message;
};

template <typename T>
using Result = std::expected<T, Error>;

/// Network interface statistics from /proc/net/dev
struct InterfaceStats {
  std::string name;
  uint64_t rx_bytes;
  uint64_t rx_packets;
  uint64_t rx_errors;
  uint64_t rx_dropped;
  uint64_t tx_bytes;
  uint64_t tx_packets;
  uint64_t tx_errors;
  uint64_t tx_dropped;

  json to_json() const;
  uint64_t total_bytes() const { return rx_bytes + tx_bytes; }
  double utilization_pct(uint64_t speed_bps = 1'000'000'000) const;
};

/// Active TCP connection entry from /proc/net/tcp
struct TcpConnection {
  int slot;
  std::string local_addr;
  uint16_t local_port;
  std::string remote_addr;
  uint16_t remote_port;
  std::string state;
  uint32_t uid;
  std::string process_name;

  json to_json() const;
};

/// Bandwidth delta between two samples
struct BandwidthDelta {
  std::string iface;
  double rx_kbps;
  double tx_kbps;
};

// ── Network Analyzer ──

class NetAnalyzer {
public:
  NetAnalyzer();

  /// Read interface stats from /proc/net/dev
  Result<std::vector<InterfaceStats>> read_interfaces() const;

  /// Read TCP connections from /proc/net/tcp + /proc/net/tcp6
  Result<std::vector<TcpConnection>> read_connections() const;

  /// Snapshot for bandwidth calculation
  using Snapshot = std::vector<std::pair<std::string, std::pair<uint64_t, uint64_t>>>;

  Result<Snapshot> snapshot() const;

  /// Calculate bandwidth between two snapshots
  static std::vector<BandwidthDelta> calculate_bandwidth(
    const Snapshot& prev, const Snapshot& curr, double interval_s);

  /// Get interface list
  Result<std::vector<std::string>> list_interfaces() const;

  /// Get system-wide summary
  Result<json> system_summary() const;

  /// TCP state name from kernel code
  static std::string_view tcp_state_name(uint8_t state);

private:
  Result<std::vector<TcpConnection>> read_tcp_file(const std::string& path) const;
};

#endif // NET_ANALYZER_NET_ANALYZER_HPP
