#ifndef NEXUSMINER_CONFIG_HPP
#define NEXUSMINER_CONFIG_HPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "config/worker_config.hpp"
#include "config/stats_printer_config.hpp"
#include "config/types.hpp"

namespace spdlog { class logger; }
namespace nexusminer
{
namespace config
{
#define CONFIG_VERSION 1

// Tritium GenesisHash validation constant
constexpr size_t TRITIUM_GENESIS_HEX_LENGTH = 64;  // 32 bytes as hex = 64 chars

// Mining configuration for stateless mining (MINER_SET_REWARD protocol)
struct MiningConfig
{
    std::string m_reward_address;  // NXS account address for mining rewards
};

class Config
{
	friend class TomlConfig;  // Allow TOML parser to use setters
	
public:

	explicit Config(std::shared_ptr<spdlog::logger> logger);

	bool read_config(std::string const& miner_config_file);

	std::uint16_t get_version() const { return m_version; }
	std::string const& get_wallet_ip() const { return m_wallet_ip; }
	// Phase 2: port refers to the stateless miner LLP port (miningport in nexus.conf)
	// Default is 8323 to match LLL-TAO's default miningport
	std::uint16_t get_port() const { return m_port; }
	std::string const& get_local_ip() const { return m_local_ip; }
	Mining_mode get_mining_mode() const { return m_mining_mode; }
	std::uint8_t get_log_level() const { return m_log_level; }
	std::string const& get_logfile() const { return m_logfile; }
	std::uint16_t get_connection_retry_interval() const { return m_connection_retry_interval; }
	std::uint16_t get_print_statistics_interval() const { return m_print_statistics_interval; }
	std::uint16_t get_height_interval() const { return m_get_height_interval; }
	std::uint16_t get_ping_interval() const { return m_ping_interval; }
	std::vector<Worker_config>& get_worker_config() { return m_worker_config; }
	std::vector<Stats_printer_config>& get_stats_printer_config() { return m_stats_printer_config; }
	std::string const& get_miner_falcon_pubkey() const { return m_miner_falcon_pubkey; }
	std::string const& get_miner_falcon_privkey() const { return m_miner_falcon_privkey; }
	bool has_miner_falcon_keys() const { return !m_miner_falcon_pubkey.empty() && !m_miner_falcon_privkey.empty(); }
	bool get_enable_disposable_falcon() const { return m_enable_disposable_falcon; }
	// Legacy method name (deprecated - kept for backward compatibility)
	bool get_enable_block_signing() const { return m_enable_disposable_falcon; }
	
	// Tritium GenesisHash and session management
	std::string const& get_tritium_genesis() const { return m_tritium_genesis; }
	bool has_tritium_genesis() const { return !m_tritium_genesis.empty(); }
	std::uint16_t get_keepalive_interval() const { return m_keepalive_interval; }
	bool get_enable_chacha20_wrapping() const { return m_enable_chacha20_wrapping; }
	bool is_localhost_mining() const;
	
	// TLS/HTTPS configuration
	bool get_enable_tls() const { return m_enable_tls; }
	std::string const& get_tls_ca_cert_path() const { return m_tls_ca_cert_path; }
	bool get_tls_verify_peer() const { return m_tls_verify_peer; }
	std::string const& get_tls_server_name() const { return m_tls_server_name; }
	
	// Mutual TLS (client certificate) configuration
	bool has_tls_client_certificate() const { return !m_tls_client_cert_path.empty() && !m_tls_client_key_path.empty(); }
	std::string const& get_tls_client_cert_path() const { return m_tls_client_cert_path; }
	std::string const& get_tls_client_key_path() const { return m_tls_client_key_path; }
	std::string const& get_tls_client_key_password() const { return m_tls_client_key_password; }
	
	// Mining configuration for stateless mining (MINER_SET_REWARD protocol)
	MiningConfig const& get_mining() const { return m_mining; }
	bool has_reward_address() const { return !m_mining.m_reward_address.empty(); }
	std::string const& get_reward_address() const { return m_mining.m_reward_address; }
	
	// Setters for TOML parser
	void set_wallet_ip(const std::string& ip) { m_wallet_ip = ip; }
	void set_port(std::uint16_t port) { m_port = port; }
	void set_local_ip(const std::string& ip) { m_local_ip = ip; }
	void set_mining_mode(Mining_mode mode) { m_mining_mode = mode; }
	void set_tritium_genesis(const std::string& genesis) { m_tritium_genesis = genesis; }
	void set_reward_address(const std::string& address) { m_mining.m_reward_address = address; }
	void set_worker_count(std::uint32_t count);
	void set_keepalive_interval(std::uint16_t interval) { m_keepalive_interval = interval; }
	void set_log_level(std::uint8_t level) { m_log_level = level; }
	void set_logfile(const std::string& logfile) { m_logfile = logfile; }
	
	// Advanced timing setters
	void set_connection_retry_interval(std::uint16_t interval) { m_connection_retry_interval = interval; }
	void set_print_statistics_interval(std::uint16_t interval) { m_print_statistics_interval = interval; }
	void set_ping_interval(std::uint16_t interval) { m_ping_interval = interval; }
	void set_get_height_interval(std::uint16_t interval) { m_get_height_interval = interval; }
	
	// Falcon authentication setters
	void set_miner_falcon_pubkey(const std::string& pubkey) { m_miner_falcon_pubkey = pubkey; }
	void set_miner_falcon_privkey(const std::string& privkey) { m_miner_falcon_privkey = privkey; }
	void set_enable_disposable_falcon(bool enable) { m_enable_disposable_falcon = enable; }
	// Legacy method name (deprecated - kept for backward compatibility)
	void set_enable_block_signing(bool enable) { m_enable_disposable_falcon = enable; }
	
	// ChaCha20 and TLS setters
	void set_enable_chacha20_wrapping(bool enable) { m_enable_chacha20_wrapping = enable; }
	void set_enable_tls(bool enable) { m_enable_tls = enable; }
	void set_tls_ca_cert_path(const std::string& path) { m_tls_ca_cert_path = path; }
	void set_tls_verify_peer(bool verify) { m_tls_verify_peer = verify; }
	void set_tls_server_name(const std::string& name) { m_tls_server_name = name; }
	void set_tls_client_cert_path(const std::string& path) { m_tls_client_cert_path = path; }
	void set_tls_client_key_path(const std::string& path) { m_tls_client_key_path = path; }
	void set_tls_client_key_password(const std::string& password) { m_tls_client_key_password = password; }

private:

	bool read_stats_printer_config(nlohmann::json& j);
	bool read_worker_config(nlohmann::json& j);
	void print_global_config() const;
	void print_worker_config() const;

	std::shared_ptr<spdlog::logger> m_logger;
	std::uint16_t m_version;
	std::string  m_wallet_ip;
	std::uint16_t m_port;
	std::string m_local_ip;
	Mining_mode	 m_mining_mode;
	std::uint8_t m_log_level;
	std::string  m_logfile;

	// stats printers
	std::vector<Stats_printer_config> m_stats_printer_config;

	// workers
	std::vector<Worker_config> m_worker_config;

	// advanced configs
	std::uint16_t m_connection_retry_interval;
	std::uint16_t m_print_statistics_interval;
	std::uint16_t m_get_height_interval;
	std::uint16_t m_ping_interval;

	// Falcon miner authentication keys (optional)
	std::string m_miner_falcon_pubkey;
	std::string m_miner_falcon_privkey;
	
	// Unified Falcon Signature Protocol options
	bool m_enable_disposable_falcon;  // Disposable Falcon signing (ALWAYS ON - core protocol, 0 blockchain overhead)
	
	// Tritium GenesisHash and adaptive cache management (Phase 2 enhancement)
	std::string m_tritium_genesis;  // Tritium account genesis hash (32 bytes hex) for reward binding
	std::uint16_t m_keepalive_interval;  // Keep-alive ping interval in hours (default: 24)
	bool m_enable_chacha20_wrapping;  // Enable ChaCha20 wrapping of Falcon pubkey (auto for remote, optional for localhost)
	
	// TLS/HTTPS configuration (auto-enabled for remote connections)
	bool m_enable_tls;  // Enable TLS/SSL for remote connections (default: auto-detect)
	std::string m_tls_ca_cert_path;  // Path to CA certificate bundle (empty = system default)
	bool m_tls_verify_peer;  // Verify peer certificate (default: true)
	std::string m_tls_server_name;  // Server name for SNI and verification (default: wallet_ip)
	
	// Mutual TLS (client certificate) configuration
	std::string m_tls_client_cert_path;  // Path to client certificate (PEM format)
	std::string m_tls_client_key_path;  // Path to client private key (PEM format)
	std::string m_tls_client_key_password;  // Password for client private key (optional)
	
	// Mining configuration for stateless mining (MINER_SET_REWARD protocol)
	MiningConfig m_mining;

};
}
}
#endif 