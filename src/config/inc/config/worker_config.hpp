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
};

struct Worker_config_fpga
{
	std::string serial_port{};

};

struct Worker_config_gpu
{
	std::uint16_t m_device;
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