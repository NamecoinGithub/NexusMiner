#ifndef NEXUSMINER_CONFIG_SIMPLIFIED_CONFIG_HPP
#define NEXUSMINER_CONFIG_SIMPLIFIED_CONFIG_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>

namespace spdlog { class logger; }

namespace nexusminer
{
namespace config
{

// Forward declaration
class Config;

// Preset skill levels for different user experience
enum class Preset_level : uint8_t
{
    BEGINNER = 0,   // Simple setup with safe defaults
    INTERMEDIATE,   // Balance between simplicity and control
    ADVANCED,       // Full control over all parameters
    CUSTOM          // User-defined configuration
};

// GPU power profile for balancing performance and consumption
enum class Power_profile : uint8_t
{
    EFFICIENCY = 0, // Prioritize power efficiency (Golden Ratio optimized)
    BALANCED,       // Balance between power and performance
    PERFORMANCE,    // Maximum performance
    CUSTOM          // User-defined power settings
};

// Hardware optimization settings for GPU
struct GPU_optimization
{
    std::uint8_t device_id{0};                      // GPU device index
    std::uint8_t power_limit_percent{100};          // Power limit as percentage (50-100%)
    std::uint8_t core_clock_offset{0};              // Core clock offset in MHz (0 = default)
    std::uint8_t memory_clock_offset{0};            // Memory clock offset in MHz (0 = default)
    std::uint8_t fan_speed_percent{0};              // Fan speed percentage (0 = auto)
    Power_profile power_profile{Power_profile::BALANCED};
    
    // Golden Ratio optimization targets
    std::uint32_t target_hashrate{0};               // Target hashrate (0 = auto)
    std::uint16_t target_power_watts{0};            // Target power consumption (0 = auto)
    double efficiency_ratio{0.0};                   // Current efficiency (hash/watt)
};

// Hardware optimization settings for CPU
struct CPU_optimization
{
    std::uint16_t thread_count{0};                  // Number of threads to use (0 = auto-detect)
    std::uint64_t affinity_mask{0};                 // CPU core affinity mask (0 = no affinity)
    std::uint8_t priority_level{2};                 // Thread priority (0=low, 1=below_normal, 2=normal, 3=above_normal, 4=high)
    std::uint8_t power_limit_percent{100};          // CPU power limit percentage
    bool enable_hyperthreading{true};               // Use hyperthreading/SMT cores
    bool enable_efficiency_cores{false};            // Use efficiency cores (hybrid CPUs)
    
    // Optimization targets
    std::uint32_t target_hashrate{0};               // Target hashrate (0 = auto)
};

// Simplified worker definition
struct Simplified_worker
{
    std::string id{};                               // Worker identifier
    std::string hardware_type{};                    // "cpu", "gpu", or "fpga"
    
    // Hardware-specific settings
    std::optional<GPU_optimization> gpu_settings;
    std::optional<CPU_optimization> cpu_settings;
    std::string fpga_serial_port{};                 // For FPGA workers
};

// Pool connection settings (simplified)
struct Simplified_pool
{
    std::string address{};                          // NXS wallet address
    std::string display_name{};                     // Display name for pool
};

// Main simplified configuration structure
struct Simplified_config_data
{
    // Metadata
    std::string config_version{"2.0"};              // Simplified config version
    Preset_level preset{Preset_level::BEGINNER};    // User skill level preset
    
    // Connection settings
    std::string wallet_ip{"127.0.0.1"};            // Wallet/pool IP or hostname
    std::uint16_t port{8323};                       // Connection port
    std::string mining_mode{"HASH"};                // "HASH" or "PRIME"
    
    // Pool settings (optional)
    std::optional<Simplified_pool> pool;
    
    // Workers
    std::vector<Simplified_worker> workers;
    
    // Global optimization settings
    Power_profile global_power_profile{Power_profile::BALANCED};
    std::uint8_t global_power_limit_percent{100};   // Global power limit
    std::uint32_t global_target_hashrate{0};        // Global target hashrate (0 = max)
    
    // Logging settings (simplified)
    bool enable_console_logging{true};
    bool enable_file_logging{false};
    std::string log_file{"miner.log"};
    std::uint8_t log_level{2};                      // 0=trace, 1=debug, 2=info, 3=warn, 4=error
    
    // Statistics
    std::uint16_t stats_interval_seconds{10};
    
    // Falcon authentication (for solo mining)
    std::string falcon_pubkey{};
    std::string falcon_privkey{};
    bool enable_block_signing{false};
};

/**
 * @brief Simplified configuration parser and factory
 * 
 * This class handles loading, saving, and converting simplified .config files
 * to the internal Config format used by NexusMiner.
 */
class Simplified_config
{
public:
    explicit Simplified_config(std::shared_ptr<spdlog::logger> logger);
    
    /**
     * @brief Load a simplified .config file
     * @param config_file Path to the .config file
     * @return true if loading was successful
     */
    bool load(std::string const& config_file);
    
    /**
     * @brief Save current configuration to a .config file
     * @param config_file Path to save the .config file
     * @return true if saving was successful
     */
    bool save(std::string const& config_file) const;
    
    /**
     * @brief Convert simplified config to the full Config object
     * @param config Reference to Config object to populate
     * @return true if conversion was successful
     */
    bool to_full_config(Config& config) const;
    
    /**
     * @brief Import from a legacy JSON config file
     * @param json_config_file Path to legacy .conf file
     * @return true if import was successful
     */
    bool import_from_json(std::string const& json_config_file);
    
    /**
     * @brief Export to a legacy JSON config file
     * @param json_config_file Path to save legacy .conf file
     * @return true if export was successful
     */
    bool export_to_json(std::string const& json_config_file) const;
    
    /**
     * @brief Create a preset configuration
     * @param level The preset level (beginner, intermediate, advanced)
     * @param mining_mode "HASH" or "PRIME"
     * @param hardware_type Primary hardware type ("cpu", "gpu", "fpga")
     */
    void create_preset(Preset_level level, std::string const& mining_mode, 
                      std::string const& hardware_type);
    
    /**
     * @brief Validate the current configuration
     * @return true if configuration is valid
     */
    bool validate() const;
    
    /**
     * @brief Get validation errors if any
     * @return String describing validation errors
     */
    std::string get_validation_errors() const;
    
    // Getters
    Simplified_config_data const& get_data() const { return m_data; }
    Simplified_config_data& get_data() { return m_data; }
    
    /**
     * @brief Check if a file is a simplified .config format
     * @param config_file Path to the config file
     * @return true if file is simplified .config format
     */
    static bool is_simplified_config(std::string const& config_file);
    
    /**
     * @brief Get recommended settings for Golden Ratio optimization
     * @param hardware_type "cpu" or "gpu"
     * @param current_hashrate Current hash rate
     * @param current_power Current power consumption
     * @return Optimized power settings
     */
    static std::pair<std::uint8_t, std::uint32_t> calculate_golden_ratio_settings(
        std::string const& hardware_type,
        std::uint32_t current_hashrate,
        std::uint16_t current_power);

private:
    std::shared_ptr<spdlog::logger> m_logger;
    Simplified_config_data m_data;
    mutable std::string m_validation_errors;
    
    // Helper methods
    void apply_beginner_preset(std::string const& mining_mode, std::string const& hardware_type);
    void apply_intermediate_preset(std::string const& mining_mode, std::string const& hardware_type);
    void apply_advanced_preset(std::string const& mining_mode, std::string const& hardware_type);
};

} // namespace config
} // namespace nexusminer

#endif // NEXUSMINER_CONFIG_SIMPLIFIED_CONFIG_HPP
