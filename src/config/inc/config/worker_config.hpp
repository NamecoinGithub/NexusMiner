#ifndef NEXUSMINER_CONFIG_WORKER_CONFIG_HPP
#define NEXUSMINER_CONFIG_WORKER_CONFIG_HPP

#include <string>
#include <variant>
#include "config/types.hpp"

namespace nexusminer
{
namespace config
{
struct Worker_config_cpu
{
	// Number of CPU threads to use for mining (default: 1)
	// Note: Multi-threading within a worker is planned for future implementation
	std::uint16_t m_threads{1};
	
	// CPU affinity mask for thread pinning (default: 0, no affinity)
	// Note: CPU affinity is planned for future implementation
	std::uint64_t m_affinity_mask{0};
	
	// NEW: CPU power controls
	std::uint8_t m_priority_level{2};             // 0=low, 1=below_normal, 2=normal, 3=above_normal, 4=high
	std::uint8_t m_power_limit_percent{100};      // 50-100%
	bool m_enable_hyperthreading{true};
	bool m_enable_efficiency_cores{false};        // For hybrid CPUs (P-cores/E-cores)
	std::uint32_t m_target_hashrate{0};           // 0=max
};

struct Worker_config_fpga
{
	std::string serial_port{};

};

struct Worker_config_gpu
{
	std::uint8_t m_device{0};
	
	// NEW: GPU power controls
	std::uint8_t m_power_limit_percent{100};      // 50-100%
	std::int16_t m_core_clock_offset{0};          // MHz offset
	std::int16_t m_memory_clock_offset{0};        // MHz offset
	std::uint8_t m_fan_speed_percent{0};          // 0=auto, 1-100%
	std::uint32_t m_target_hashrate{0};           // 0=max
};

class Worker_config
{
public:

	std::string m_id{};
	std::uint16_t m_internal_id{0U};
	Worker_mode m_mode{Worker_mode::CPU};
	std::variant<Worker_config_cpu, Worker_config_fpga, Worker_config_gpu>
		m_worker_mode;
};

}
}
#endif