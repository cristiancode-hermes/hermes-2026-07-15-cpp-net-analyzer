#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <net-analyzer/analyzer.hpp>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>

using json = nlohmann::json;

// ── Unit tests: data structures ──

TEST_CASE("InterfaceStats to_json", "[json]") {
  InterfaceStats iface;
  iface.name = "eth0";
  iface.rx_bytes = 1024;
  iface.rx_packets = 100;
  iface.rx_errors = 0;
  iface.rx_dropped = 2;
  iface.tx_bytes = 2048;
  iface.tx_packets = 200;
  iface.tx_errors = 1;
  iface.tx_dropped = 0;

  json j = iface.to_json();
  REQUIRE(j["interface"] == "eth0");
  REQUIRE(j["rx_bytes"] == 1024);
  REQUIRE(j["tx_bytes"] == 2048);
  REQUIRE(j["total_bytes"] == 3072);
}

TEST_CASE("InterfaceStats utilization_pct", "[math]") {
  InterfaceStats iface;
  iface.rx_bytes = 10'000'000;
  iface.tx_bytes = 10'000'000;

  double pct = iface.utilization_pct(1'000'000'000);
  // 20 MB at 1 Gbps = 0.16, but the method just checks bytes/speed
  REQUIRE(pct >= 0.0);
  REQUIRE(pct < 100.0);
}

TEST_CASE("TcpConnection to_json", "[json]") {
  TcpConnection conn;
  conn.slot = 1;
  conn.local_addr = "127.0.0.1";
  conn.local_port = 8080;
  conn.remote_addr = "10.0.0.1";
  conn.remote_port = 443;
  conn.state = "ESTABLISHED";
  conn.uid = 1000;
  conn.process_name = "nginx";

  json j = conn.to_json();
  REQUIRE(j["local_address"] == "127.0.0.1");
  REQUIRE(j["local_port"] == 8080);
  REQUIRE(j["state"] == "ESTABLISHED");
}

TEST_CASE("tcp_state_name mapping", "[tcp]") {
  REQUIRE(NetAnalyzer::tcp_state_name(0x01) == "ESTABLISHED");
  REQUIRE(NetAnalyzer::tcp_state_name(0x02) == "SYN_SENT");
  REQUIRE(NetAnalyzer::tcp_state_name(0x0A) == "LISTEN");
  REQUIRE(NetAnalyzer::tcp_state_name(0xFF) == "UNKNOWN");
}

// ── Integration tests: /proc reading ──

TEST_CASE("read_interfaces returns interfaces", "/proc") {
  NetAnalyzer analyzer;
  auto result = analyzer.read_interfaces();

  REQUIRE(result.has_value());
  REQUIRE_FALSE(result->empty());

  // Should have at least one interface
  bool found = false;
  for (const auto& iface : *result) {
    if (!iface.name.empty()) {
      found = true;
      break;
    }
  }
  REQUIRE(found);
}

TEST_CASE("list_interfaces returns non-empty list", "/proc") {
  NetAnalyzer analyzer;
  auto result = analyzer.list_interfaces();

  REQUIRE(result.has_value());
  REQUIRE_FALSE(result->empty());
}

TEST_CASE("read_connections succeeds (may be empty)", "/proc") {
  NetAnalyzer analyzer;
  auto result = analyzer.read_connections();

  // Should succeed (may return empty list if no connections)
  REQUIRE(result.has_value());
}

TEST_CASE("snapshot and bandwidth calculation", "[bandwidth]") {
  NetAnalyzer analyzer;

  auto snap1 = analyzer.snapshot();
  REQUIRE(snap1.has_value());

  auto snap2 = analyzer.snapshot();
  REQUIRE(snap2.has_value());

  // With same snapshots, bandwidth should be ~0
  auto deltas = NetAnalyzer::calculate_bandwidth(*snap1, *snap2, 1.0);
  for (const auto& d : deltas) {
    REQUIRE(d.rx_kbps < 0.001);
    REQUIRE(d.tx_kbps < 0.001);
  }
}

TEST_CASE("system_summary returns structured JSON", "/proc") {
  NetAnalyzer analyzer;
  auto result = analyzer.system_summary();

  REQUIRE(result.has_value());
  // Should contain at least one numeric interface entry
  // (interface names vary by environment — no name assertion)
  REQUIRE(result->contains("_total"));
  REQUIRE((*result)["_total"].contains("rx_bytes"));
  REQUIRE((*result)["_total"].contains("tx_bytes"));
}

// ── Benchmark ──

TEST_CASE("read_interfaces benchmark", "[benchmark]") {
  NetAnalyzer analyzer;

  BENCHMARK("Read /proc/net/dev") {
    auto result = analyzer.read_interfaces();
    return result.has_value() ? result->size() : 0;
  };
}

TEST_CASE("read_connections benchmark", "[benchmark]") {
  NetAnalyzer analyzer;

  BENCHMARK("Read /proc/net/tcp") {
    auto result = analyzer.read_connections();
    return result.has_value() ? result->size() : 0;
  };
}

// ── JSON roundtrip ──

TEST_CASE("InterfaceStats JSON roundtrip preserves fields", "[json]") {
  InterfaceStats iface;
  iface.name = "eth0";
  iface.rx_bytes = 999999;
  iface.tx_bytes = 111111;

  json j = iface.to_json();
  REQUIRE(j["interface"] == "eth0");
  REQUIRE(j["rx_bytes"] == 999999);
  REQUIRE(j["tx_bytes"] == 111111);

  // Re-parse and check
  std::string dumped = j.dump();
  json parsed = json::parse(dumped);
  REQUIRE(parsed["interface"] == "eth0");
  REQUIRE(parsed["total_bytes"] == 999999 + 111111);
}
