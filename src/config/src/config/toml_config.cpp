
#include "config/config.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>

namespace nexusminer
{
namespace config
{

// Simple TOML parser for NexusMiner configuration files
// This is a lightweight implementation that handles the specific TOML subset we use

class TomlParser
{
public:
    TomlParser(std::shared_ptr<spdlog::logger> logger) : m_logger(logger) {}

    bool parse(const std::string& filepath, Config& config);

private:
    std::shared_ptr<spdlog::logger> m_logger;
    
    std::string trim(const std::string& str);
    std::string unquote(const std::string& str);
    bool parse_bool(const std::string& value);
    int64_t parse_int(const std::string& value);
    double parse_float(const std::string& value);
    
    bool parse_worker(std::istream& file, const std::string& first_line, Worker_config& worker);
    bool parse_stats_printer(std::istream& file, const std::string& first_line, Stats_printer_config& printer);
};

std::string TomlParser::trim(const std::string& str)
{
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string TomlParser::unquote(const std::string& str)
{
    std::string trimmed = trim(str);
    if (trimmed.length() >= 2 && 
        ((trimmed.front() == '"' && trimmed.back() == '"') ||
         (trimmed.front() == '\'' && trimmed.back() == '\'')))
    {
        return trimmed.substr(1, trimmed.length() - 2);
    }
    return trimmed;
}

bool TomlParser::parse_bool(const std::string& value)
{
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower == "true" || lower == "1" || lower == "yes";
}

int64_t TomlParser::parse_int(const std::string& value)
{
    try {
        return std::stoll(trim(value));
    } catch (...) {
        return 0;
    }
}

double TomlParser::parse_float(const std::string& value)
{
    try {
        return std::stod(trim(value));
    } catch (...) {
        return 0.0;
    }
}

bool TomlParser::parse(const std::string& filepath, Config& config)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        m_logger->critical("Unable to read TOML config file: {}", filepath);
        return false;
    }

    m_logger->info("Reading TOML config file: {}", filepath);

    std::string line;
    std::string current_section;
    std::string current_table;
    
    // Temporary storage for worker/printer parsing
    Worker_config current_worker;
    Stats_printer_config current_printer;
    bool in_worker = false;
    bool in_printer = false;
    bool has_mining_section = false;

    while (std::getline(file, line))
    {
        std::string trimmed = trim(line);
        
        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        // Check for array of tables [[section]]
        if (trimmed.length() >= 4 && trimmed.substr(0, 2) == "[[" && trimmed.back() == ']')
        {
            // End previous worker/printer if any
            if (in_worker)
            {
                config.get_worker_config().push_back(current_worker);
                current_worker = Worker_config();
            }
            if (in_printer)
            {
                config.get_stats_printer_config().push_back(current_printer);
                current_printer = Stats_printer_config();
            }
            
            size_t end = trimmed.rfind("]]");
            if (end != std::string::npos)
            {
                current_section = trimmed.substr(2, end - 2);
                
                if (current_section == "workers")
                {
                    in_worker = true;
                    in_printer = false;
                }
                else if (current_section == "stats_printers")
                {
                    in_printer = true;
                    in_worker = false;
                }
            }
            continue;
        }

        // Check for table [section]
        if (trimmed[0] == '[' && trimmed.back() == ']')
        {
            // End previous worker/printer if any
            if (in_worker)
            {
                config.get_worker_config().push_back(current_worker);
                current_worker = Worker_config();
                in_worker = false;
            }
            if (in_printer)
            {
                config.get_stats_printer_config().push_back(current_printer);
                current_printer = Stats_printer_config();
                in_printer = false;
            }
            
            current_table = trimmed.substr(1, trimmed.length() - 2);
            if (current_table == "mining")
            {
                has_mining_section = true;
            }
            continue;
        }

        // Parse key = value
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos)
        {
            std::string key = trim(line.substr(0, eq_pos));
            std::string value = trim(line.substr(eq_pos + 1));
            
            // Remove inline comments
            size_t comment_pos = value.find('#');
            if (comment_pos != std::string::npos && 
                (comment_pos == 0 || value[comment_pos - 1] != '\\'))
            {
                // Check if # is inside a string
                size_t quote1 = value.find('"');
                size_t quote2 = value.rfind('"');
                if (!(quote1 != std::string::npos && quote2 != std::string::npos && 
                      quote1 < comment_pos && comment_pos < quote2))
                {
                    value = trim(value.substr(0, comment_pos));
                }
            }

            // Handle based on context
            if (in_worker)
            {
                if (key == "id")
                    current_worker.m_id = unquote(value);
                else if (key == "hardware")
                {
                    std::string hw = unquote(value);
                    std::transform(hw.begin(), hw.end(), hw.begin(), ::tolower);
                    
                    if (hw == "cpu")
                    {
                        current_worker.m_mode = Worker_mode::CPU;
                        current_worker.m_worker_mode = Worker_config_cpu{};
                    }
                    else if (hw == "gpu")
                    {
                        current_worker.m_mode = Worker_mode::GPU;
                        current_worker.m_worker_mode = Worker_config_gpu{};
                    }
                    else if (hw == "fpga")
                    {
                        current_worker.m_mode = Worker_mode::FPGA;
                        current_worker.m_worker_mode = Worker_config_fpga{};
                    }
                }
                else if (current_worker.m_mode == Worker_mode::CPU)
                {
                    auto& cpu = std::get<Worker_config_cpu>(current_worker.m_worker_mode);
                    if (key == "threads")
                        cpu.m_threads = static_cast<uint16_t>(parse_int(value));
                    else if (key == "affinity_mask")
                        cpu.m_affinity_mask = static_cast<uint64_t>(parse_int(value));
                    else if (key == "priority")
                        cpu.m_priority_level = static_cast<uint8_t>(parse_int(value));
                    else if (key == "power_limit_percent")
                        cpu.m_power_limit_percent = static_cast<uint8_t>(parse_int(value));
                    else if (key == "hyperthreading")
                        cpu.m_enable_hyperthreading = parse_bool(value);
                    else if (key == "efficiency_cores")
                        cpu.m_enable_efficiency_cores = parse_bool(value);
                    else if (key == "target_hashrate")
                        cpu.m_target_hashrate = static_cast<uint32_t>(parse_int(value));
                }
                else if (current_worker.m_mode == Worker_mode::GPU)
                {
                    auto& gpu = std::get<Worker_config_gpu>(current_worker.m_worker_mode);
                    if (key == "device")
                        gpu.m_device = static_cast<uint8_t>(parse_int(value));
                    else if (key == "power_limit_percent")
                        gpu.m_power_limit_percent = static_cast<uint8_t>(parse_int(value));
                    else if (key == "core_clock_offset")
                        gpu.m_core_clock_offset = static_cast<int16_t>(parse_int(value));
                    else if (key == "memory_clock_offset")
                        gpu.m_memory_clock_offset = static_cast<int16_t>(parse_int(value));
                    else if (key == "fan_speed")
                        gpu.m_fan_speed_percent = static_cast<uint8_t>(parse_int(value));
                    else if (key == "target_hashrate")
                        gpu.m_target_hashrate = static_cast<uint32_t>(parse_int(value));
                }
                else if (current_worker.m_mode == Worker_mode::FPGA)
                {
                    auto& fpga = std::get<Worker_config_fpga>(current_worker.m_worker_mode);
                    if (key == "serial_port")
                        fpga.serial_port = unquote(value);
                }
            }
            else if (in_printer)
            {
                if (key == "mode")
                {
                    std::string mode = unquote(value);
                    std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
                    
                    if (mode == "console")
                    {
                        current_printer.m_mode = Stats_printer_mode::CONSOLE;
                        current_printer.m_printer_mode = Stats_printer_config_console{};
                    }
                    else if (mode == "file")
                    {
                        current_printer.m_mode = Stats_printer_mode::FILE;
                        current_printer.m_printer_mode = Stats_printer_config_file{};
                    }
                }
                else if (key == "filename" && current_printer.m_mode == Stats_printer_mode::FILE)
                {
                    std::get<Stats_printer_config_file>(current_printer.m_printer_mode).file_name = unquote(value);
                }
            }
            else if (current_table == "mining")
            {
                if (key == "reward_address")
                {
                    // Use the Config's internal method indirectly
                    // We need to set this through the config object
                    // For now, store and let config handle it
                    config.set_reward_address(unquote(value));
                }
            }
            else
            {
                // Global settings
                if (key == "version")
                {
                    uint16_t version = static_cast<uint16_t>(parse_int(value));
                    if (version < CONFIG_VERSION)
                    {
                        m_logger->critical("Config version too old. Must be version: {}", CONFIG_VERSION);
                        return false;
                    }
                }
                else if (key == "wallet_ip")
                    config.set_wallet_ip(unquote(value));
                else if (key == "port")
                    config.set_port(static_cast<uint16_t>(parse_int(value)));
                else if (key == "local_ip")
                    config.set_local_ip(unquote(value));
                else if (key == "mining_mode")
                {
                    std::string mode = unquote(value);
                    std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
                    config.set_mining_mode(mode == "prime" ? Mining_mode::PRIME : Mining_mode::HASH);
                }
                else if (key == "log_level")
                    config.set_log_level(static_cast<uint8_t>(parse_int(value)));
                else if (key == "logfile")
                    config.set_logfile(unquote(value));
                else if (key == "connection_retry_interval")
                    config.set_connection_retry_interval(static_cast<uint16_t>(parse_int(value)));
                else if (key == "print_statistics_interval")
                    config.set_print_statistics_interval(static_cast<uint16_t>(parse_int(value)));
                else if (key == "get_height_interval")
                    config.set_get_height_interval(static_cast<uint16_t>(parse_int(value)));
                else if (key == "ping_interval")
                    config.set_ping_interval(static_cast<uint16_t>(parse_int(value)));
                else if (key == "miner_falcon_pubkey")
                    config.set_miner_falcon_pubkey(unquote(value));
                else if (key == "miner_falcon_privkey")
                    config.set_miner_falcon_privkey(unquote(value));
                else if (key == "enable_block_signing")
                    config.set_enable_block_signing(parse_bool(value));
                else if (key == "tritium_genesis")
                    config.set_tritium_genesis(unquote(value));
                else if (key == "keepalive_interval")
                    config.set_keepalive_interval(static_cast<uint16_t>(parse_int(value)));
                else if (key == "enable_chacha20_wrapping")
                    config.set_enable_chacha20_wrapping(parse_bool(value));
                else if (key == "enable_tls")
                    config.set_enable_tls(parse_bool(value));
                else if (key == "tls_ca_cert_path")
                    config.set_tls_ca_cert_path(unquote(value));
                else if (key == "tls_verify_peer")
                    config.set_tls_verify_peer(parse_bool(value));
                else if (key == "tls_server_name")
                    config.set_tls_server_name(unquote(value));
                else if (key == "tls_client_cert_path")
                    config.set_tls_client_cert_path(unquote(value));
                else if (key == "tls_client_key_path")
                    config.set_tls_client_key_path(unquote(value));
                else if (key == "tls_client_key_password")
                    config.set_tls_client_key_password(unquote(value));
            }
        }
    }

    // Add final worker/printer if any
    if (in_worker && !current_worker.m_id.empty())
    {
        config.get_worker_config().push_back(current_worker);
    }
    if (in_printer)
    {
        config.get_stats_printer_config().push_back(current_printer);
    }

    // Validate required fields
    if (config.get_worker_config().empty())
    {
        m_logger->critical("No workers configured in TOML config file");
        return false;
    }

    if (config.get_stats_printer_config().empty())
    {
        // Add default console printer if none specified
        Stats_printer_config default_printer;
        default_printer.m_mode = Stats_printer_mode::CONSOLE;
        default_printer.m_printer_mode = Stats_printer_config_console{};
        config.get_stats_printer_config().push_back(default_printer);
    }

    return true;
}

// Function to read TOML config - called from Config class
bool read_toml_config(const std::string& filepath, Config& config, std::shared_ptr<spdlog::logger> logger)
{
    TomlParser parser(logger);
    return parser.parse(filepath, config);
}

} // namespace config
} // namespace nexusminer
