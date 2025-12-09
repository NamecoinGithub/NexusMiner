
#include "config/config.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <iostream>
#include <sstream>

using json = nlohmann::json;

namespace nexusminer
{
namespace config
{
	// NXS address validation constants
	// Base58 encoded NXS addresses are typically 49-52 characters
	constexpr size_t NXS_ADDRESS_MIN_LENGTH = 40;  // Minimum expected length
	constexpr size_t NXS_ADDRESS_MAX_LENGTH = 60;  // Maximum expected length

	Config::Config(std::shared_ptr<spdlog::logger> logger)
		: m_logger{std::move(logger)}
		, m_version{1}
		, m_wallet_ip{ "127.0.0.1" }
		, m_port{ 8323 }  // Phase 2: Default to miningport (stateless miner LLP port)
		, m_local_ip{"0.0.0.0"}  // Changed: Works for all scenarios (localhost, VPN, remote)
		, m_mining_mode{ Mining_mode::HASH}
		, m_log_level{2}	// info level
		, m_logfile{""}		// no logfile usage, default
		, m_connection_retry_interval{5}
		, m_print_statistics_interval{5}
		, m_get_height_interval{2}
		, m_ping_interval{10}
		, m_miner_falcon_pubkey{""}
		, m_miner_falcon_privkey{""}
		, m_enable_block_signing{false}
		, m_tritium_genesis{""}
		, m_keepalive_interval{24}  // Default: 1 ping per day
		, m_enable_chacha20_wrapping{false}  // Default: auto-detect based on connection
		, m_enable_tls{false}  // Default: auto-detect based on connection
		, m_tls_ca_cert_path{""}  // Default: use system CA bundle
		, m_tls_verify_peer{true}  // Default: always verify peer
		, m_tls_server_name{""}  // Default: use wallet_ip
		, m_tls_client_cert_path{""}  // Default: no client certificate
		, m_tls_client_key_path{""}  // Default: no client key
		, m_tls_client_key_password{""}  // Default: no password
	{
	}

	bool Config::read_config(std::string const& miner_config_file)
	{
		// Determine file format based on extension
		std::string extension;
		size_t dot_pos = miner_config_file.rfind('.');
		if (dot_pos != std::string::npos)
		{
			extension = miner_config_file.substr(dot_pos);
		}
		
		// If file has .config extension, use TOML parser
		if (extension == ".config")
		{
			m_logger->info("Detected TOML config format (.config)");
			bool result = read_toml_config(miner_config_file);
			if (result)
			{
				print_global_config();
				print_worker_config();
			}
			return result;
		}
		
		// For .conf or any other extension, use JSON parser (backward compatibility)
		m_logger->info("Using JSON config format (.conf)");
		return read_json_config(miner_config_file);
	}

	bool Config::read_toml_config(std::string const& miner_config_file)
	{
		// Call the external TOML parser
		return nexusminer::config::read_toml_config(miner_config_file, *this, m_logger);
	}

	bool Config::read_json_config(std::string const& miner_config_file)
	{
	//	m_logger->info("Reading config file {}", miner_config_file);

		std::ifstream config_file(miner_config_file);
		if (!config_file.is_open())
		{
			m_logger->critical("Unable to read {}", miner_config_file);
			return false;
		}

		try
		{
			json j = json::parse(config_file);
			j.at("version").get_to(m_version);
			if (m_version < CONFIG_VERSION)
			{
				auto const config_version = CONFIG_VERSION;
				m_logger->critical("Config version too old. Must be version : {}", config_version);
				return false;
			}

			j.at("wallet_ip").get_to(m_wallet_ip);
			j.at("port").get_to(m_port);
			if (j.count("local_ip") != 0)
			{
				j.at("local_ip").get_to(m_local_ip);
			}

			std::string mining_mode = j["mining_mode"];
			std::for_each(mining_mode.begin(), mining_mode.end(), [](char& c) {
				c = ::tolower(c);
				});

			if (mining_mode == "prime")
			{
				m_mining_mode = Mining_mode::PRIME;
			}
			else
			{
				m_mining_mode = Mining_mode::HASH;
			}

			// read stats printer config
			if (!read_stats_printer_config(j))
			{
				return false;
			}

			// read worker config
			if (!read_worker_config(j))
			{
				return false;
			}

			// advanced configs
			if (j.count("connection_retry_interval") != 0)
			{
				j.at("connection_retry_interval").get_to(m_connection_retry_interval);
			}
			if (j.count("print_statistics_interval") != 0)
			{
				j.at("print_statistics_interval").get_to(m_print_statistics_interval);
			}
			if (j.count("get_height_interval") != 0)
			{
				j.at("get_height_interval").get_to(m_get_height_interval);
			}
			if (j.count("ping_interval") != 0)
			{
				j.at("ping_interval").get_to(m_ping_interval);
			}

			if (j.count("log_level") != 0)
			{
				j.at("log_level").get_to(m_log_level);
			}

			if (j.count("logfile") != 0)
			{
				j.at("logfile").get_to(m_logfile);
			}

			// Falcon miner authentication keys (optional)
			if (j.count("miner_falcon_pubkey") != 0)
			{
				j.at("miner_falcon_pubkey").get_to(m_miner_falcon_pubkey);
			}
			if (j.count("miner_falcon_privkey") != 0)
			{
				j.at("miner_falcon_privkey").get_to(m_miner_falcon_privkey);
			}
			
			// Unified Falcon Signature Protocol options (optional)
			m_enable_block_signing = false;  // Default: disabled for performance
			if (j.count("enable_block_signing") != 0)
			{
				j.at("enable_block_signing").get_to(m_enable_block_signing);
			}
			
			// Tritium GenesisHash and adaptive cache management (Phase 2 enhancement)
			if (j.count("tritium_genesis") != 0)
			{
				j.at("tritium_genesis").get_to(m_tritium_genesis);
				// Validate hex format
				if (!m_tritium_genesis.empty() && m_tritium_genesis.length() != TRITIUM_GENESIS_HEX_LENGTH)
				{
					m_logger->warn("tritium_genesis must be {} hex characters (32 bytes). Ignoring invalid value.", 
					              TRITIUM_GENESIS_HEX_LENGTH);
					m_tritium_genesis.clear();
				}
			}
			
			// Keep-alive interval in hours (default: 24 hours = 1 ping/day)
			m_keepalive_interval = 24;  // Default
			if (j.count("keepalive_interval") != 0)
			{
				j.at("keepalive_interval").get_to(m_keepalive_interval);
				// Clamp to reasonable range: 1-168 hours (1 hour - 1 week)
				if (m_keepalive_interval < 1) m_keepalive_interval = 1;
				if (m_keepalive_interval > 168) m_keepalive_interval = 168;
			}
			
			// ChaCha20 wrapping (default: false, auto-enabled for remote connections)
			m_enable_chacha20_wrapping = false;  // Default
			if (j.count("enable_chacha20_wrapping") != 0)
			{
				j.at("enable_chacha20_wrapping").get_to(m_enable_chacha20_wrapping);
			}
			
			// TLS/HTTPS configuration (default: false, auto-enabled for remote connections)
			m_enable_tls = false;  // Default
			if (j.count("enable_tls") != 0)
			{
				j.at("enable_tls").get_to(m_enable_tls);
			}
			
			// TLS CA certificate path (empty = use system default)
			if (j.count("tls_ca_cert_path") != 0)
			{
				j.at("tls_ca_cert_path").get_to(m_tls_ca_cert_path);
			}
			
			// TLS peer verification (default: true)
			m_tls_verify_peer = true;  // Default: always verify
			if (j.count("tls_verify_peer") != 0)
			{
				j.at("tls_verify_peer").get_to(m_tls_verify_peer);
			}
			
			// TLS server name for SNI (default: use wallet_ip)
			if (j.count("tls_server_name") != 0)
			{
				j.at("tls_server_name").get_to(m_tls_server_name);
			}
			else
			{
				// Default: use wallet_ip as server name
				m_tls_server_name = m_wallet_ip;
			}
			
			// Mutual TLS (client certificate) configuration
			if (j.count("tls_client_cert_path") != 0)
			{
				j.at("tls_client_cert_path").get_to(m_tls_client_cert_path);
			}
			
			if (j.count("tls_client_key_path") != 0)
			{
				j.at("tls_client_key_path").get_to(m_tls_client_key_path);
			}
			
			if (j.count("tls_client_key_password") != 0)
			{
				j.at("tls_client_key_password").get_to(m_tls_client_key_password);
			}
			
			// Parse mining configuration for stateless mining (MINER_SET_REWARD protocol)
			if (j.contains("mining"))
			{
				auto& mining = j["mining"];
				
				if (mining.contains("reward_address"))
				{
					m_mining.m_reward_address = mining["reward_address"].get<std::string>();
					m_logger->info("Mining reward address configured: {}", m_mining.m_reward_address);
					
					// Validate address format (should be base58 encoded, ~50 chars for NXS addresses)
					if (m_mining.m_reward_address.length() < NXS_ADDRESS_MIN_LENGTH || 
					    m_mining.m_reward_address.length() > NXS_ADDRESS_MAX_LENGTH)
					{
						m_logger->warn("mining.reward_address appears unusual length ({}) - verify address format", 
						              m_mining.m_reward_address.length());
					}
				}
				else
				{
					m_logger->debug("mining.reward_address not specified - stateless reward binding disabled");
				}
			}
			else
			{
				m_logger->debug("No mining configuration block - stateless reward binding disabled");
			}

			print_global_config();
			print_worker_config();
			return true;
		}
		catch (std::exception& e)
		{
			m_logger->critical("Failed to parse config file. Exception: {}", e.what());
			return false;
		}
	}

	bool Config::read_stats_printer_config(nlohmann::json& j)
	{
		for (auto& stats_printers_json : j["stats_printers"])
		{
			for(auto& stats_printer_config_json : stats_printers_json)
			{
				Stats_printer_config stats_printer_config;
				auto stats_printer_mode = stats_printer_config_json["mode"];

				if(stats_printer_mode == "console")
				{
					stats_printer_config.m_mode = Stats_printer_mode::CONSOLE;
					stats_printer_config.m_printer_mode = Stats_printer_config_console{};
				}
				else if(stats_printer_mode == "file")
				{
					stats_printer_config.m_mode = Stats_printer_mode::FILE;
					stats_printer_config.m_printer_mode = Stats_printer_config_file{stats_printer_config_json["filename"]};
				}
				else
				{
					// invalid config
					return false;
				}

				m_stats_printer_config.push_back(stats_printer_config);		
			}
		}
		return true;	
	}

	bool Config::read_worker_config(nlohmann::json& j)
	{
		for (auto& workers_json : j["workers"])
		{
			for(auto& worker_config_json : workers_json)
			{
				Worker_config worker_config;
				worker_config.m_id = worker_config_json["id"];

				auto& worker_mode_json = worker_config_json["mode"];

				if(worker_mode_json["hardware"] == "cpu")
				{
					worker_config.m_mode = Worker_mode::CPU;
					Worker_config_cpu cpu_config{};
					
					// Read optional thread count (default: 1)
					if (worker_mode_json.count("threads") != 0) {
						cpu_config.m_threads = worker_mode_json["threads"];
					}
					
					// Read optional affinity mask (default: 0, no affinity)
					if (worker_mode_json.count("affinity_mask") != 0) {
						cpu_config.m_affinity_mask = worker_mode_json["affinity_mask"];
					}
					
					// NEW: Parse power controls with validation
					if (worker_mode_json.count("priority") != 0) {
						auto priority = worker_mode_json["priority"].get<std::uint8_t>();
						if (priority <= 4) {
							cpu_config.m_priority_level = priority;
						} else {
							m_logger->warn("CPU priority must be 0-4, got {}. Using default (2).", priority);
						}
					}
					if (worker_mode_json.count("power_limit_percent") != 0) {
						auto power_limit = worker_mode_json["power_limit_percent"].get<std::uint8_t>();
						if (power_limit >= 50 && power_limit <= 100) {
							cpu_config.m_power_limit_percent = power_limit;
						} else {
							m_logger->warn("CPU power_limit_percent must be 50-100, got {}. Using default (100).", power_limit);
						}
					}
					if (worker_mode_json.count("hyperthreading") != 0)
						cpu_config.m_enable_hyperthreading = worker_mode_json["hyperthreading"];
					if (worker_mode_json.count("efficiency_cores") != 0)
						cpu_config.m_enable_efficiency_cores = worker_mode_json["efficiency_cores"];
					if (worker_mode_json.count("target_hashrate") != 0)
						cpu_config.m_target_hashrate = worker_mode_json["target_hashrate"];
					
					worker_config.m_worker_mode = cpu_config;
				}
				else if(worker_mode_json["hardware"] == "gpu")
				{
					worker_config.m_mode = Worker_mode::GPU;
					Worker_config_gpu gpu_config;
					gpu_config.m_device = worker_mode_json["device"];
					
					// NEW: Parse power controls with validation
					if (worker_mode_json.count("power_limit_percent") != 0) {
						auto power_limit = worker_mode_json["power_limit_percent"].get<std::uint8_t>();
						if (power_limit >= 50 && power_limit <= 100) {
							gpu_config.m_power_limit_percent = power_limit;
						} else {
							m_logger->warn("GPU power_limit_percent must be 50-100, got {}. Using default (100).", power_limit);
						}
					}
					if (worker_mode_json.count("core_clock_offset") != 0) {
						auto offset = worker_mode_json["core_clock_offset"].get<std::int16_t>();
						if (offset >= -500 && offset <= 500) {
							gpu_config.m_core_clock_offset = offset;
						} else {
							m_logger->warn("GPU core_clock_offset must be -500 to +500 MHz, got {}. Using default (0).", offset);
						}
					}
					if (worker_mode_json.count("memory_clock_offset") != 0) {
						auto offset = worker_mode_json["memory_clock_offset"].get<std::int16_t>();
						if (offset >= -1000 && offset <= 1000) {
							gpu_config.m_memory_clock_offset = offset;
						} else {
							m_logger->warn("GPU memory_clock_offset must be -1000 to +1000 MHz, got {}. Using default (0).", offset);
						}
					}
					if (worker_mode_json.count("fan_speed") != 0) {
						auto fan_speed = worker_mode_json["fan_speed"].get<std::uint8_t>();
						if (fan_speed <= 100) {
							gpu_config.m_fan_speed_percent = fan_speed;
						} else {
							m_logger->warn("GPU fan_speed must be 0-100, got {}. Using default (0=auto).", fan_speed);
						}
					}
					if (worker_mode_json.count("target_hashrate") != 0)
						gpu_config.m_target_hashrate = worker_mode_json["target_hashrate"];
					
					worker_config.m_worker_mode = gpu_config;
				}
				else if(worker_mode_json["hardware"] == "fpga")
				{
					worker_config.m_mode = Worker_mode::FPGA;
					worker_config.m_worker_mode = Worker_config_fpga{worker_mode_json["serial_port"]};
				}
				else
				{
					// invalid config
					return false;
				}

				m_worker_config.push_back(worker_config);		
			}
		}
		return true;	
	}

	void Config::print_worker_config() const
	{
		std::stringstream ss;
		ss << m_worker_config.size() << " workers configured" << std::endl;
		for (auto const& worker : m_worker_config)
		{
			std::string mode{};
			switch (worker.m_mode)
			{
			case Worker_mode::CPU: 
				mode = "CPU"; 
				// Display CPU-specific config
				if (std::holds_alternative<Worker_config_cpu>(worker.m_worker_mode)) {
					auto const& cpu_cfg = std::get<Worker_config_cpu>(worker.m_worker_mode);
					ss << worker.m_id << " mode: " << mode;
					if (cpu_cfg.m_threads != 1) {  // Only show if non-default
						ss << ", threads: " << cpu_cfg.m_threads;
					}
					if (cpu_cfg.m_affinity_mask != 0) {  // Only show if non-default
						ss << ", affinity: 0x" << std::hex << cpu_cfg.m_affinity_mask << std::dec;
					}
					ss << std::endl;
				} else {
					ss << worker.m_id << " mode: " << mode << std::endl;
				}
				continue;  // Skip the generic line below
			case Worker_mode::GPU: mode = "GPU"; break;
			case Worker_mode::FPGA: mode = "FPGA"; break;
			}
			ss << worker.m_id << " mode: " << mode << std::endl;
		}

		m_logger->info(ss.str());
	}

	void Config::print_global_config() const
	{
		std::stringstream ss;
		ss << "Mining " << (m_mining_mode == config::Mining_mode::HASH ? "HASH" : "PRIME") << " Channel in SOLO mode";

		m_logger->info(ss.str());
	}
	
	bool Config::is_localhost_mining() const
	{
		// Check if wallet_ip is localhost
		return (m_wallet_ip == "127.0.0.1" || 
		        m_wallet_ip == "localhost" || 
		        m_wallet_ip == "::1" ||
		        m_wallet_ip == "0.0.0.0");
	}
}
}