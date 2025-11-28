#include "config/simplified_config.hpp"
#include "config/config.hpp"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>

using json = nlohmann::json;

namespace nexusminer
{
namespace config
{

// JSON serialization helpers
NLOHMANN_JSON_SERIALIZE_ENUM(Preset_level, {
    {Preset_level::BEGINNER, "beginner"},
    {Preset_level::INTERMEDIATE, "intermediate"},
    {Preset_level::ADVANCED, "advanced"},
    {Preset_level::CUSTOM, "custom"}
})

NLOHMANN_JSON_SERIALIZE_ENUM(Power_profile, {
    {Power_profile::EFFICIENCY, "efficiency"},
    {Power_profile::BALANCED, "balanced"},
    {Power_profile::PERFORMANCE, "performance"},
    {Power_profile::CUSTOM, "custom"}
})

Simplified_config::Simplified_config(std::shared_ptr<spdlog::logger> logger)
    : m_logger{std::move(logger)}
    , m_data{}
{
}

bool Simplified_config::load(std::string const& config_file)
{
    std::ifstream file(config_file);
    if (!file.is_open())
    {
        m_logger->error("Unable to open simplified config file: {}", config_file);
        return false;
    }

    try
    {
        json j = json::parse(file);
        
        // Check for simplified config marker
        if (j.count("config_version") == 0)
        {
            m_logger->error("Not a simplified config file (missing config_version)");
            return false;
        }
        
        m_data.config_version = j.value("config_version", "2.0");
        
        // Parse preset level
        if (j.count("preset") != 0)
        {
            m_data.preset = j["preset"].get<Preset_level>();
        }
        
        // Connection settings
        m_data.wallet_ip = j.value("wallet_ip", "127.0.0.1");
        m_data.port = j.value("port", 8323);
        m_data.mining_mode = j.value("mining_mode", "HASH");
        
        // Pool settings
        if (j.count("pool") != 0)
        {
            Simplified_pool pool;
            pool.address = j["pool"].value("address", "");
            pool.display_name = j["pool"].value("display_name", "");
            m_data.pool = pool;
        }
        
        // Global optimization settings
        if (j.count("power_profile") != 0)
        {
            m_data.global_power_profile = j["power_profile"].get<Power_profile>();
        }
        m_data.global_power_limit_percent = j.value("power_limit_percent", 100);
        m_data.global_target_hashrate = j.value("target_hashrate", 0);
        
        // Workers
        m_data.workers.clear();
        if (j.count("workers") != 0)
        {
            for (auto& worker_json : j["workers"])
            {
                Simplified_worker worker;
                worker.id = worker_json.value("id", "worker");
                worker.hardware_type = worker_json.value("hardware", "cpu");
                
                // GPU settings
                if (worker.hardware_type == "gpu" && worker_json.count("gpu") != 0)
                {
                    GPU_optimization gpu;
                    auto& gpu_json = worker_json["gpu"];
                    gpu.device_id = gpu_json.value("device", 0);
                    gpu.power_limit_percent = gpu_json.value("power_limit_percent", 100);
                    gpu.core_clock_offset = gpu_json.value("core_clock_offset", 0);
                    gpu.memory_clock_offset = gpu_json.value("memory_clock_offset", 0);
                    gpu.fan_speed_percent = gpu_json.value("fan_speed", 0);
                    gpu.target_hashrate = gpu_json.value("target_hashrate", 0);
                    gpu.target_power_watts = gpu_json.value("target_power", 0);
                    if (gpu_json.count("power_profile") != 0)
                    {
                        gpu.power_profile = gpu_json["power_profile"].get<Power_profile>();
                    }
                    worker.gpu_settings = gpu;
                }
                
                // CPU settings
                if (worker.hardware_type == "cpu" && worker_json.count("cpu") != 0)
                {
                    CPU_optimization cpu;
                    auto& cpu_json = worker_json["cpu"];
                    cpu.thread_count = cpu_json.value("threads", 0);
                    cpu.affinity_mask = cpu_json.value("affinity_mask", 0);
                    cpu.priority_level = cpu_json.value("priority", 2);
                    cpu.power_limit_percent = cpu_json.value("power_limit_percent", 100);
                    cpu.enable_hyperthreading = cpu_json.value("hyperthreading", true);
                    cpu.enable_efficiency_cores = cpu_json.value("efficiency_cores", false);
                    cpu.target_hashrate = cpu_json.value("target_hashrate", 0);
                    worker.cpu_settings = cpu;
                }
                
                // FPGA settings
                if (worker.hardware_type == "fpga")
                {
                    worker.fpga_serial_port = worker_json.value("serial_port", "");
                }
                
                m_data.workers.push_back(worker);
            }
        }
        
        // Logging settings
        m_data.enable_console_logging = j.value("console_logging", true);
        m_data.enable_file_logging = j.value("file_logging", false);
        m_data.log_file = j.value("log_file", "miner.log");
        m_data.log_level = j.value("log_level", 2);
        m_data.stats_interval_seconds = j.value("stats_interval", 10);
        
        // Falcon authentication
        m_data.falcon_pubkey = j.value("falcon_pubkey", "");
        m_data.falcon_privkey = j.value("falcon_privkey", "");
        m_data.enable_block_signing = j.value("enable_block_signing", false);
        
        m_logger->info("Loaded simplified config from {}", config_file);
        return true;
    }
    catch (std::exception const& e)
    {
        m_logger->error("Failed to parse simplified config: {}", e.what());
        return false;
    }
}

bool Simplified_config::save(std::string const& config_file) const
{
    json j;
    
    // Metadata
    j["config_version"] = m_data.config_version;
    j["preset"] = m_data.preset;
    
    // Connection settings
    j["wallet_ip"] = m_data.wallet_ip;
    j["port"] = m_data.port;
    j["mining_mode"] = m_data.mining_mode;
    
    // Pool settings
    if (m_data.pool.has_value())
    {
        j["pool"]["address"] = m_data.pool->address;
        j["pool"]["display_name"] = m_data.pool->display_name;
    }
    
    // Global optimization
    j["power_profile"] = m_data.global_power_profile;
    j["power_limit_percent"] = m_data.global_power_limit_percent;
    j["target_hashrate"] = m_data.global_target_hashrate;
    
    // Workers
    j["workers"] = json::array();
    for (auto const& worker : m_data.workers)
    {
        json worker_json;
        worker_json["id"] = worker.id;
        worker_json["hardware"] = worker.hardware_type;
        
        if (worker.gpu_settings.has_value())
        {
            auto const& gpu = worker.gpu_settings.value();
            worker_json["gpu"]["device"] = gpu.device_id;
            worker_json["gpu"]["power_limit_percent"] = gpu.power_limit_percent;
            worker_json["gpu"]["core_clock_offset"] = gpu.core_clock_offset;
            worker_json["gpu"]["memory_clock_offset"] = gpu.memory_clock_offset;
            worker_json["gpu"]["fan_speed"] = gpu.fan_speed_percent;
            worker_json["gpu"]["target_hashrate"] = gpu.target_hashrate;
            worker_json["gpu"]["target_power"] = gpu.target_power_watts;
            worker_json["gpu"]["power_profile"] = gpu.power_profile;
        }
        
        if (worker.cpu_settings.has_value())
        {
            auto const& cpu = worker.cpu_settings.value();
            worker_json["cpu"]["threads"] = cpu.thread_count;
            worker_json["cpu"]["affinity_mask"] = cpu.affinity_mask;
            worker_json["cpu"]["priority"] = cpu.priority_level;
            worker_json["cpu"]["power_limit_percent"] = cpu.power_limit_percent;
            worker_json["cpu"]["hyperthreading"] = cpu.enable_hyperthreading;
            worker_json["cpu"]["efficiency_cores"] = cpu.enable_efficiency_cores;
            worker_json["cpu"]["target_hashrate"] = cpu.target_hashrate;
        }
        
        if (worker.hardware_type == "fpga")
        {
            worker_json["serial_port"] = worker.fpga_serial_port;
        }
        
        j["workers"].push_back(worker_json);
    }
    
    // Logging
    j["console_logging"] = m_data.enable_console_logging;
    j["file_logging"] = m_data.enable_file_logging;
    j["log_file"] = m_data.log_file;
    j["log_level"] = m_data.log_level;
    j["stats_interval"] = m_data.stats_interval_seconds;
    
    // Falcon authentication
    if (!m_data.falcon_pubkey.empty())
    {
        j["falcon_pubkey"] = m_data.falcon_pubkey;
    }
    if (!m_data.falcon_privkey.empty())
    {
        j["falcon_privkey"] = m_data.falcon_privkey;
    }
    j["enable_block_signing"] = m_data.enable_block_signing;
    
    // Write to file
    std::ofstream file(config_file);
    if (!file.is_open())
    {
        m_logger->error("Unable to create config file: {}", config_file);
        return false;
    }
    
    file << j.dump(4);
    m_logger->info("Saved simplified config to {}", config_file);
    return true;
}

bool Simplified_config::to_full_config(Config& config) const
{
    // Note: Config uses internal read_config which reads from file.
    // This method is for conceptual conversion - the actual loading
    // is handled by creating a temp JSON and having Config read it,
    // or by directly setting Config's internal fields if they were exposed.
    
    // For this implementation, we export to a temp JSON file and have
    // Config read it. This ensures compatibility with the existing system.
    std::string temp_file = "/tmp/nexusminer_temp_config.conf";
    
    if (!export_to_json(temp_file))
    {
        return false;
    }
    
    return config.read_config(temp_file);
}

bool Simplified_config::import_from_json(std::string const& json_config_file)
{
    std::ifstream file(json_config_file);
    if (!file.is_open())
    {
        m_logger->error("Unable to open JSON config file: {}", json_config_file);
        return false;
    }

    try
    {
        json j = json::parse(file);
        
        // Map legacy JSON fields to simplified config
        m_data.config_version = "2.0";
        m_data.preset = Preset_level::CUSTOM;
        
        m_data.wallet_ip = j.value("wallet_ip", "127.0.0.1");
        m_data.port = j.value("port", 8323);
        m_data.mining_mode = j.value("mining_mode", "HASH");
        
        // Pool settings
        if (j.count("pool") != 0)
        {
            Simplified_pool pool;
            pool.address = j["pool"].value("username", "");
            pool.display_name = j["pool"].value("display_name", "");
            m_data.pool = pool;
        }
        
        // Import workers
        m_data.workers.clear();
        if (j.count("workers") != 0)
        {
            for (auto& workers_json : j["workers"])
            {
                for (auto& worker_json : workers_json)
                {
                    Simplified_worker worker;
                    worker.id = worker_json.value("id", "worker");
                    
                    auto& mode_json = worker_json["mode"];
                    worker.hardware_type = mode_json.value("hardware", "cpu");
                    
                    if (worker.hardware_type == "gpu")
                    {
                        GPU_optimization gpu;
                        gpu.device_id = mode_json.value("device", 0);
                        worker.gpu_settings = gpu;
                    }
                    else if (worker.hardware_type == "cpu")
                    {
                        CPU_optimization cpu;
                        cpu.thread_count = mode_json.value("threads", 1);
                        cpu.affinity_mask = mode_json.value("affinity_mask", 0);
                        worker.cpu_settings = cpu;
                    }
                    else if (worker.hardware_type == "fpga")
                    {
                        worker.fpga_serial_port = mode_json.value("serial_port", "");
                    }
                    
                    m_data.workers.push_back(worker);
                }
            }
        }
        
        // Logging settings
        m_data.log_level = j.value("log_level", 2);
        m_data.log_file = j.value("logfile", "miner.log");
        m_data.stats_interval_seconds = j.value("print_statistics_interval", 10);
        
        // Check for stats printers
        if (j.count("stats_printers") != 0)
        {
            for (auto& printers : j["stats_printers"])
            {
                for (auto& printer : printers)
                {
                    if (printer["mode"] == "console")
                    {
                        m_data.enable_console_logging = true;
                    }
                    else if (printer["mode"] == "file")
                    {
                        m_data.enable_file_logging = true;
                    }
                }
            }
        }
        
        // Falcon authentication
        m_data.falcon_pubkey = j.value("miner_falcon_pubkey", "");
        m_data.falcon_privkey = j.value("miner_falcon_privkey", "");
        m_data.enable_block_signing = j.value("enable_block_signing", false);
        
        m_logger->info("Imported configuration from JSON file: {}", json_config_file);
        return true;
    }
    catch (std::exception const& e)
    {
        m_logger->error("Failed to import JSON config: {}", e.what());
        return false;
    }
}

bool Simplified_config::export_to_json(std::string const& json_config_file) const
{
    json j;
    
    // Version
    j["version"] = 1;
    
    // Connection settings
    j["wallet_ip"] = m_data.wallet_ip;
    j["port"] = m_data.port;
    j["local_ip"] = "127.0.0.1";
    j["mining_mode"] = m_data.mining_mode;
    
    // Pool settings
    if (m_data.pool.has_value())
    {
        j["pool"]["username"] = m_data.pool->address;
        j["pool"]["display_name"] = m_data.pool->display_name;
    }
    
    // Advanced settings
    j["connection_retry_interval"] = 5;
    j["get_height_interval"] = 2;
    j["ping_interval"] = 10;
    j["log_level"] = m_data.log_level;
    j["logfile"] = m_data.log_file;
    j["print_statistics_interval"] = m_data.stats_interval_seconds;
    
    // Stats printers
    j["stats_printers"] = json::array();
    if (m_data.enable_console_logging)
    {
        json printer;
        printer["stats_printer"]["mode"] = "console";
        j["stats_printers"].push_back(printer);
    }
    if (m_data.enable_file_logging)
    {
        json printer;
        printer["stats_printer"]["mode"] = "file";
        printer["stats_printer"]["filename"] = m_data.log_file;
        j["stats_printers"].push_back(printer);
    }
    
    // Workers
    j["workers"] = json::array();
    for (auto const& worker : m_data.workers)
    {
        json worker_json;
        worker_json["worker"]["id"] = worker.id;
        worker_json["worker"]["mode"]["hardware"] = worker.hardware_type;
        
        if (worker.hardware_type == "gpu" && worker.gpu_settings.has_value())
        {
            worker_json["worker"]["mode"]["device"] = worker.gpu_settings->device_id;
        }
        else if (worker.hardware_type == "cpu" && worker.cpu_settings.has_value())
        {
            auto const& cpu = worker.cpu_settings.value();
            if (cpu.thread_count > 0)
            {
                worker_json["worker"]["mode"]["threads"] = cpu.thread_count;
            }
            if (cpu.affinity_mask != 0)
            {
                worker_json["worker"]["mode"]["affinity_mask"] = cpu.affinity_mask;
            }
        }
        else if (worker.hardware_type == "fpga")
        {
            worker_json["worker"]["mode"]["serial_port"] = worker.fpga_serial_port;
        }
        
        j["workers"].push_back(worker_json);
    }
    
    // Falcon authentication
    if (!m_data.falcon_pubkey.empty())
    {
        j["miner_falcon_pubkey"] = m_data.falcon_pubkey;
    }
    if (!m_data.falcon_privkey.empty())
    {
        j["miner_falcon_privkey"] = m_data.falcon_privkey;
    }
    j["enable_block_signing"] = m_data.enable_block_signing;
    
    // Write to file
    std::ofstream file(json_config_file);
    if (!file.is_open())
    {
        m_logger->error("Unable to create JSON config file: {}", json_config_file);
        return false;
    }
    
    file << j.dump(4);
    m_logger->info("Exported configuration to JSON file: {}", json_config_file);
    return true;
}

void Simplified_config::create_preset(Preset_level level, std::string const& mining_mode, 
                                      std::string const& hardware_type)
{
    m_data = Simplified_config_data{};  // Reset to defaults
    m_data.preset = level;
    m_data.mining_mode = mining_mode;
    
    switch (level)
    {
        case Preset_level::BEGINNER:
            apply_beginner_preset(mining_mode, hardware_type);
            break;
        case Preset_level::INTERMEDIATE:
            apply_intermediate_preset(mining_mode, hardware_type);
            break;
        case Preset_level::ADVANCED:
            apply_advanced_preset(mining_mode, hardware_type);
            break;
        case Preset_level::CUSTOM:
            // Custom preset - use defaults
            break;
    }
    
    m_logger->info("Created {} preset for {} mining with {} hardware", 
                   level == Preset_level::BEGINNER ? "beginner" :
                   level == Preset_level::INTERMEDIATE ? "intermediate" :
                   level == Preset_level::ADVANCED ? "advanced" : "custom",
                   mining_mode, hardware_type);
}

void Simplified_config::apply_beginner_preset(std::string const& mining_mode, 
                                              std::string const& hardware_type)
{
    // Beginner preset: Safe defaults, minimal configuration
    m_data.wallet_ip = "127.0.0.1";
    m_data.port = (mining_mode == "PRIME") ? 50000 : 8323;  // Pool port for prime, solo for hash
    m_data.global_power_profile = Power_profile::EFFICIENCY;
    m_data.global_power_limit_percent = 80;  // Safe power limit
    m_data.enable_console_logging = true;
    m_data.enable_file_logging = false;
    m_data.log_level = 2;  // Info level
    m_data.stats_interval_seconds = 30;  // Less frequent updates
    
    // Create a single worker
    Simplified_worker worker;
    worker.id = "worker0";
    worker.hardware_type = hardware_type;
    
    if (hardware_type == "gpu")
    {
        GPU_optimization gpu;
        gpu.device_id = 0;
        gpu.power_limit_percent = 80;  // Conservative power limit
        gpu.power_profile = Power_profile::EFFICIENCY;
        worker.gpu_settings = gpu;
    }
    else if (hardware_type == "cpu")
    {
        CPU_optimization cpu;
        cpu.thread_count = 0;  // Auto-detect (will use half of cores for safety)
        cpu.priority_level = 1;  // Below normal priority
        cpu.power_limit_percent = 80;
        cpu.enable_hyperthreading = false;  // Disable for stability
        worker.cpu_settings = cpu;
    }
    
    m_data.workers.push_back(worker);
}

void Simplified_config::apply_intermediate_preset(std::string const& mining_mode,
                                                  std::string const& hardware_type)
{
    // Intermediate preset: Balanced performance and power
    m_data.wallet_ip = "127.0.0.1";
    m_data.port = 8323;
    m_data.global_power_profile = Power_profile::BALANCED;
    m_data.global_power_limit_percent = 90;
    m_data.enable_console_logging = true;
    m_data.enable_file_logging = true;
    m_data.log_level = 2;
    m_data.stats_interval_seconds = 15;
    
    Simplified_worker worker;
    worker.id = "worker0";
    worker.hardware_type = hardware_type;
    
    if (hardware_type == "gpu")
    {
        GPU_optimization gpu;
        gpu.device_id = 0;
        gpu.power_limit_percent = 90;
        gpu.power_profile = Power_profile::BALANCED;
        worker.gpu_settings = gpu;
    }
    else if (hardware_type == "cpu")
    {
        CPU_optimization cpu;
        cpu.thread_count = 0;  // Auto-detect (will use 75% of cores)
        cpu.priority_level = 2;  // Normal priority
        cpu.power_limit_percent = 90;
        cpu.enable_hyperthreading = true;
        worker.cpu_settings = cpu;
    }
    
    m_data.workers.push_back(worker);
}

void Simplified_config::apply_advanced_preset(std::string const& mining_mode,
                                              std::string const& hardware_type)
{
    // Advanced preset: Maximum performance configuration
    m_data.wallet_ip = "127.0.0.1";
    m_data.port = 8323;
    m_data.global_power_profile = Power_profile::PERFORMANCE;
    m_data.global_power_limit_percent = 100;
    m_data.enable_console_logging = true;
    m_data.enable_file_logging = true;
    m_data.log_level = 1;  // Debug level for advanced users
    m_data.stats_interval_seconds = 5;
    
    Simplified_worker worker;
    worker.id = "worker0";
    worker.hardware_type = hardware_type;
    
    if (hardware_type == "gpu")
    {
        GPU_optimization gpu;
        gpu.device_id = 0;
        gpu.power_limit_percent = 100;
        gpu.power_profile = Power_profile::PERFORMANCE;
        // Advanced users can tune core/memory clocks
        gpu.core_clock_offset = 0;
        gpu.memory_clock_offset = 0;
        worker.gpu_settings = gpu;
    }
    else if (hardware_type == "cpu")
    {
        CPU_optimization cpu;
        cpu.thread_count = 0;  // Auto-detect (will use all cores)
        cpu.priority_level = 4;  // High priority
        cpu.power_limit_percent = 100;
        cpu.enable_hyperthreading = true;
        cpu.enable_efficiency_cores = true;
        worker.cpu_settings = cpu;
    }
    
    m_data.workers.push_back(worker);
}

bool Simplified_config::validate() const
{
    m_validation_errors.clear();
    std::stringstream errors;
    bool valid = true;
    
    // Check wallet IP
    if (m_data.wallet_ip.empty())
    {
        errors << "wallet_ip is required\n";
        valid = false;
    }
    
    // Check port
    if (m_data.port == 0)
    {
        errors << "port must be greater than 0\n";
        valid = false;
    }
    
    // Check mining mode
    std::string mode_lower = m_data.mining_mode;
    std::transform(mode_lower.begin(), mode_lower.end(), mode_lower.begin(), ::tolower);
    if (mode_lower != "hash" && mode_lower != "prime")
    {
        errors << "mining_mode must be 'HASH' or 'PRIME'\n";
        valid = false;
    }
    
    // Check workers
    if (m_data.workers.empty())
    {
        errors << "At least one worker is required\n";
        valid = false;
    }
    
    for (size_t i = 0; i < m_data.workers.size(); ++i)
    {
        auto const& worker = m_data.workers[i];
        
        if (worker.id.empty())
        {
            errors << "Worker " << i << " must have an id\n";
            valid = false;
        }
        
        if (worker.hardware_type != "cpu" && 
            worker.hardware_type != "gpu" && 
            worker.hardware_type != "fpga")
        {
            errors << "Worker " << worker.id << " has invalid hardware type\n";
            valid = false;
        }
        
        if (worker.hardware_type == "fpga" && worker.fpga_serial_port.empty())
        {
            errors << "FPGA worker " << worker.id << " requires serial_port\n";
            valid = false;
        }
        
        // Validate power limits
        if (worker.gpu_settings.has_value())
        {
            if (worker.gpu_settings->power_limit_percent < 50 || 
                worker.gpu_settings->power_limit_percent > 100)
            {
                errors << "GPU power limit must be between 50-100%\n";
                valid = false;
            }
        }
        
        if (worker.cpu_settings.has_value())
        {
            if (worker.cpu_settings->power_limit_percent < 50 || 
                worker.cpu_settings->power_limit_percent > 100)
            {
                errors << "CPU power limit must be between 50-100%\n";
                valid = false;
            }
        }
    }
    
    // Check FPGA not used with PRIME mining
    if (mode_lower == "prime")
    {
        for (auto const& worker : m_data.workers)
        {
            if (worker.hardware_type == "fpga")
            {
                errors << "FPGA is not supported for PRIME mining\n";
                valid = false;
                break;
            }
        }
    }
    
    m_validation_errors = errors.str();
    return valid;
}

std::string Simplified_config::get_validation_errors() const
{
    return m_validation_errors;
}

bool Simplified_config::is_simplified_config(std::string const& config_file)
{
    std::ifstream file(config_file);
    if (!file.is_open())
    {
        return false;
    }
    
    try
    {
        json j = json::parse(file);
        // Check for simplified config marker (config_version field)
        return j.count("config_version") != 0;
    }
    catch (...)
    {
        return false;
    }
}

std::pair<std::uint8_t, std::uint32_t> Simplified_config::calculate_golden_ratio_settings(
    std::string const& hardware_type,
    std::uint32_t current_hashrate,
    std::uint16_t current_power)
{
    // Golden Ratio optimization: Find the optimal balance between
    // hash rate and power consumption
    //
    // The "golden ratio" in mining refers to the optimal efficiency point
    // where reducing power slightly doesn't significantly impact hash rate,
    // but running at maximum power gives diminishing returns.
    //
    // For most GPUs, this is typically around 70-80% power limit
    // For CPUs, this varies more widely based on thermal throttling
    
    const double golden_ratio = 1.618033988749895;
    
    if (current_power == 0 || current_hashrate == 0)
    {
        // Return default balanced settings
        return {80, 0};  // 80% power, auto hashrate
    }
    
    double efficiency = static_cast<double>(current_hashrate) / static_cast<double>(current_power);
    
    // Calculate optimal power based on Golden Ratio principle
    // We aim for approximately 80% of max power for optimal efficiency
    std::uint8_t optimal_power_percent = static_cast<std::uint8_t>(100.0 / golden_ratio + 18);
    
    // Estimate target hashrate based on typical scaling
    // Most hardware shows ~90% hash rate at 80% power
    std::uint32_t optimal_hashrate = static_cast<std::uint32_t>(current_hashrate * 0.9);
    
    // Clamp values
    if (optimal_power_percent < 50) optimal_power_percent = 50;
    if (optimal_power_percent > 100) optimal_power_percent = 100;
    
    return {optimal_power_percent, optimal_hashrate};
}

} // namespace config
} // namespace nexusminer
