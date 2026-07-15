#include <net-analyzer/analyzer.hpp>
#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <print>
#include <ranges>
#include <algorithm>

using namespace std::chrono_literals;

// ── Format helpers ──

static std::string human_size(uint64_t bytes) {
  const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  double val = static_cast<double>(bytes);
  int unit = 0;
  while (val >= 1024.0 && unit < 4) { val /= 1024.0; unit++; }
  return std::format("{:.1f} {}", val, units[unit]);
}

static std::string human_rate(double kbps) {
  if (kbps < 1.0) return std::format("{:.1f} bps", kbps * 1024.0);
  if (kbps < 1024.0) return std::format("{:.1f} Kbps", kbps);
  return std::format("{:.2f} Mbps", kbps / 1024.0);
}

// ── Display functions ──

static void print_interfaces_table(const std::vector<InterfaceStats>& ifaces) {
  std::println(std::cout, "{:<12} {:>12} {:>12} {:>12} {:>12} {:>10} {:>6} {:>6}",
               "INTERFACE", "RX_BYTES", "TX_BYTES", "RX_PKTS", "TX_PKTS", "RX_ERR", "TX_ERR", "DROP");

  std::println(std::cout, "{}", std::string(80, '─'));

  for (const auto& iface : ifaces) {
    // Skip loopback unless verbose
    if (iface.name == "lo") continue;
    
    std::println(std::cout, "{:<12} {:>12} {:>12} {:>12} {:>12} {:>10} {:>6} {:>6}",
                 iface.name,
                 human_size(iface.rx_bytes),
                 human_size(iface.tx_bytes),
                 iface.rx_packets,
                 iface.tx_packets,
                 iface.rx_errors,
                 iface.tx_errors,
                 iface.rx_dropped);
  }
}

static void print_connections_table(const std::vector<TcpConnection>& conns) {
  std::println(std::cout, "{:<5} {:<22} {:<22} {:<12} {:<6} {:<10}",
               "SLOT", "LOCAL", "REMOTE", "STATE", "UID", "PROCESS");

  std::println(std::cout, "{}", std::string(85, '─'));

  for (const auto& c : conns) {
    std::println(std::cout, "{:<5} {:<22} {:<22} {:<12} {:<6} {:<10}",
                 c.slot,
                 std::format("{}:{}", c.local_addr, c.local_port),
                 std::format("{}:{}", c.remote_addr, c.remote_port),
                 c.state, c.uid,
                 c.process_name.empty() ? "-" : c.process_name);
  }
}

static void print_bandwidth_table(const std::vector<BandwidthDelta>& deltas) {
  std::println(std::cout, "{:<12} {:>14} {:>14} {:>14}",
               "INTERFACE", "RX_RATE", "TX_RATE", "TOTAL_RATE");

  std::println(std::cout, "{}", std::string(58, '─'));

  double total_rx = 0, total_tx = 0;
  for (const auto& d : deltas) {
    std::println(std::cout, "{:<12} {:>14} {:>14} {:>14}",
                 d.iface, human_rate(d.rx_kbps),
                 human_rate(d.tx_kbps),
                 human_rate(d.rx_kbps + d.tx_kbps));
    total_rx += d.rx_kbps;
    total_tx += d.tx_kbps;
  }

  std::println(std::cout, "{}", std::string(58, '─'));
  std::println(std::cout, "{:<12} {:>14} {:>14} {:>14}",
               "TOTAL", human_rate(total_rx), human_rate(total_tx),
               human_rate(total_rx + total_tx));
}

// ── Main ──

int main(int argc, char** argv) {
  CLI::App app{"Net Analyzer — Network monitoring tool for Linux (/proc/net)"};

  bool show_json = false;
  bool show_connections = false;
  bool monitor_mode = false;
  int monitor_interval = 2;
  std::string filter_iface;

  app.add_flag("-j,--json", show_json, "JSON output mode");
  app.add_flag("-c,--connections", show_connections, "Show active TCP connections");
  app.add_flag("-m,--monitor", monitor_mode, "Real-time bandwidth monitoring mode");
  app.add_option("-i,--interval", monitor_interval, "Monitor refresh interval (seconds)")->default_val(2);
  app.add_option("-f,--filter", filter_iface, "Filter by interface name");

  CLI11_PARSE(app, argc, argv);

  // Set up color logging
  auto console = spdlog::stdout_color_mt("console");
  spdlog::set_level(spdlog::level::warn);

  NetAnalyzer analyzer;

  if (monitor_mode) {
    // Monitor mode: continuously show bandwidth deltas
    auto prev = analyzer.snapshot();
    if (!prev) {
      std::println(std::cerr, "Error: {}", prev.error().message);
      return 1;
    }

    std::println(std::cout, "Net Analyzer — Monitor Mode (refresh every {}s)\n", monitor_interval);

    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(monitor_interval));
      auto curr = analyzer.snapshot();
      if (!curr) break;

      auto deltas = NetAnalyzer::calculate_bandwidth(*prev, *curr, monitor_interval);

      // Clear screen (ANSI)
      std::println(std::cout, "\033[2J\033[H");
      std::println(std::cout, "Net Analyzer — Monitor Mode (refresh every {}s)\n", monitor_interval);

      if (!filter_iface.empty()) {
        std::erase_if(deltas, [&](const auto& d) { return d.iface != filter_iface; });
      }

      if (show_json) {
        json j = json::array();
        for (const auto& d : deltas) {
          j.push_back({{"interface", d.iface}, {"rx_kbps", d.rx_kbps}, {"tx_kbps", d.tx_kbps}});
        }
        std::println(std::cout, "{}", j.dump(2));
      } else {
        print_bandwidth_table(deltas);
      }

      prev = std::move(*curr);
    }
    return 0;
  }

  if (show_connections) {
    auto conns = analyzer.read_connections();
    if (!conns) {
      std::println(std::cerr, "Error reading connections: {}", conns.error().message);
      return 1;
    }

    if (!filter_iface.empty()) {
      // For connections, filter means by state name substring match
      std::erase_if(*conns, [&](const TcpConnection& c) {
        return c.state.find(filter_iface) == std::string::npos;
      });
    }

    if (show_json) {
      json arr = json::array();
      for (const auto& c : *conns) arr.push_back(c.to_json());
      std::println(std::cout, "{}", arr.dump(2));
    } else {
      print_connections_table(*conns);
    }
    return 0;
  }

  // Default: show interface stats
  auto ifaces = analyzer.read_interfaces();
  if (!ifaces) {
    std::println(std::cerr, "Error reading interfaces: {}", ifaces.error().message);
    return 1;
  }

  if (!filter_iface.empty()) {
    std::erase_if(*ifaces, [&](const InterfaceStats& iface) { return iface.name != filter_iface; });
  }

  if (show_json) {
    json arr = json::array();
    for (const auto& iface : *ifaces) arr.push_back(iface.to_json());
    std::println(std::cout, "{}", arr.dump(2));
  } else {
    std::println(std::cout, "Net Analyzer — Interface Statistics\n");
    print_interfaces_table(*ifaces);
  }

  return 0;
}
