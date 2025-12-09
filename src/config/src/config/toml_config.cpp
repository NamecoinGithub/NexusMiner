#include "config/toml_config.hpp"
#include "config/config.hpp"
#include "config/types.hpp"
#include "config/worker_config.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace nexusminer
{
namespace config
{
    // Constants for keepalive interval validation
    constexpr int MIN_KEEPALIVE_HOURS = 1;
    constexpr int MAX_KEEPALIVE_HOURS = 168;  // 1 week
    
    TomlConfig::TomlConfig(std::shared_ptr<spdlog::logger> logger)
        : m_logger(std::move(logger))
    {
    }

    bool TomlConfig::parse_file(const std::string& filename, Config& config)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            m_logger->critical("Unable to open TOML config file: {}", filename);
            return false;
        }

        std::string current_section;
        std::string line;
        int line_number = 0;
        
        // Track worker configuration
        int worker_count = 0;
        int cpu_threads = 1;  // Default threads per worker
        bool efficiency_cores = true;  // Default

        try
        {
            while (std::getline(file, line))
            {
                line_number++;
                line = trim(line);

                // Skip empty lines and comments
                if (line.empty() || is_comment(line))
                {
                    continue;
                }

                // Check for section headers
                std::string section_name;
                if (is_section(line, section_name))
                {
                    current_section = section_name;
                    continue;
                }

                // Parse key-value pairs
                std::string key, value;
                if (!parse_key_value(line, key, value))
                {
                    m_logger->warn("Invalid line {} in {}: {}", line_number, filename, line);
                    continue;
                }

                // Process based on current section
                if (current_section == "wallet")
                {
                    if (key == "ip")
                    {
                        config.set_wallet_ip(parse_string_value(value));
                    }
                    else if (key == "port")
                    {
                        config.set_port(static_cast<std::uint16_t>(parse_int_value(value)));
                    }
                }
                else if (current_section == "mining")
                {
                    if (key == "channel")
                    {
                        int channel = parse_int_value(value);
                        if (channel == 1)
                        {
                            config.set_mining_mode(Mining_mode::PRIME);
                        }
                        else if (channel == 2)
                        {
                            config.set_mining_mode(Mining_mode::HASH);
                        }
                        else
                        {
                            m_logger->warn("Invalid mining channel: {}. Use 1 for PRIME or 2 for HASH", channel);
                        }
                    }
                    else if (key == "genesis")
                    {
                        std::string genesis = parse_string_value(value);
                        if (!genesis.empty() && genesis.length() != TRITIUM_GENESIS_HEX_LENGTH)
                        {
                            m_logger->warn("tritium_genesis must be {} hex characters (32 bytes). Ignoring invalid value.", 
                                          TRITIUM_GENESIS_HEX_LENGTH);
                        }
                        else
                        {
                            config.set_tritium_genesis(genesis);
                        }
                    }
                    else if (key == "reward_address")
                    {
                        std::string address = parse_string_value(value);
                        config.set_reward_address(address);
                        m_logger->info("Mining reward address configured: {}", address);
                    }
                }
                else if (current_section == "workers")
                {
                    if (key == "count")
                    {
                        worker_count = parse_int_value(value);
                    }
                }
                else if (current_section == "cpu")
                {
                    if (key == "threads")
                    {
                        cpu_threads = parse_int_value(value);
                    }
                    else if (key == "efficiency_cores")
                    {
                        efficiency_cores = parse_bool_value(value);
                    }
                }
                else if (current_section == "network")
                {
                    if (key == "local_ip")
                    {
                        config.set_local_ip(parse_string_value(value));
                    }
                    else if (key == "keepalive_interval")
                    {
                        int interval = parse_int_value(value);
                        // Clamp to reasonable range
                        if (interval < MIN_KEEPALIVE_HOURS) interval = MIN_KEEPALIVE_HOURS;
                        if (interval > MAX_KEEPALIVE_HOURS) interval = MAX_KEEPALIVE_HOURS;
                        config.set_keepalive_interval(static_cast<std::uint16_t>(interval));
                    }
                }
                else if (current_section == "logging")
                {
                    if (key == "level")
                    {
                        int level = parse_int_value(value);
                        if (level >= 0 && level <= 3)
                        {
                            config.set_log_level(static_cast<std::uint8_t>(level));
                        }
                    }
                }
            }

            // Create worker configurations after parsing all settings
            if (worker_count > 0)
            {
                // Clear existing workers
                config.m_worker_config.clear();
                
                // Create CPU workers with configured settings
                for (int i = 0; i < worker_count; ++i)
                {
                    Worker_config worker_config;
                    worker_config.m_id = "cpu" + std::to_string(i);
                    worker_config.m_mode = Worker_mode::CPU;
                    
                    Worker_config_cpu cpu_config{};
                    cpu_config.m_threads = static_cast<std::uint16_t>(cpu_threads);
                    cpu_config.m_affinity_mask = 0;  // No affinity by default
                    cpu_config.m_enable_efficiency_cores = efficiency_cores;
                    
                    worker_config.m_worker_mode = cpu_config;
                    config.m_worker_config.push_back(worker_config);
                }
            }

            return true;
        }
        catch (const std::exception& e)
        {
            m_logger->critical("Error parsing TOML config at line {}: {}", line_number, e.what());
            return false;
        }
    }

    std::string TomlConfig::trim(const std::string& str)
    {
        size_t first = str.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            return "";
        
        size_t last = str.find_last_not_of(" \t\r\n");
        return str.substr(first, last - first + 1);
    }

    bool TomlConfig::is_comment(const std::string& line)
    {
        return !line.empty() && line[0] == '#';
    }

    bool TomlConfig::is_section(const std::string& line, std::string& section_name)
    {
        if (line.empty() || line[0] != '[')
            return false;

        size_t end = line.find(']');
        if (end == std::string::npos)
            return false;

        section_name = trim(line.substr(1, end - 1));
        return true;
    }

    bool TomlConfig::parse_key_value(const std::string& line, std::string& key, std::string& value)
    {
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos)
            return false;

        key = trim(line.substr(0, eq_pos));
        value = trim(line.substr(eq_pos + 1));
        
        return !key.empty() && !value.empty();
    }

    std::string TomlConfig::parse_string_value(const std::string& value)
    {
        std::string result = trim(value);
        
        // Remove quotes if present
        if (result.size() >= 2 && 
            ((result.front() == '"' && result.back() == '"') ||
             (result.front() == '\'' && result.back() == '\'')))
        {
            result = result.substr(1, result.size() - 2);
        }
        
        return result;
    }

    int TomlConfig::parse_int_value(const std::string& value)
    {
        std::string cleaned = trim(value);
        
        // Remove quotes if present
        if (cleaned.size() >= 2 && 
            ((cleaned.front() == '"' && cleaned.back() == '"') ||
             (cleaned.front() == '\'' && cleaned.back() == '\'')))
        {
            cleaned = cleaned.substr(1, cleaned.size() - 2);
        }
        
        try
        {
            return std::stoi(cleaned);
        }
        catch (...)
        {
            return 0;
        }
    }

    bool TomlConfig::parse_bool_value(const std::string& value)
    {
        std::string cleaned = trim(value);
        std::transform(cleaned.begin(), cleaned.end(), cleaned.begin(), ::tolower);
        
        // Remove quotes if present
        if (cleaned.size() >= 2 && 
            ((cleaned.front() == '"' && cleaned.back() == '"') ||
             (cleaned.front() == '\'' && cleaned.back() == '\'')))
        {
            cleaned = cleaned.substr(1, cleaned.size() - 2);
            std::transform(cleaned.begin(), cleaned.end(), cleaned.begin(), ::tolower);
        }
        
        return cleaned == "true" || cleaned == "1" || cleaned == "yes";
    }

} // namespace config
} // namespace nexusminer
