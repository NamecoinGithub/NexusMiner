#ifndef NEXUSMINER_WORKER_MANAGER_HPP
#define NEXUSMINER_WORKER_MANAGER_HPP

#include "network/connection.hpp"
#include "network/socket.hpp"
#include "network/types.hpp"
#include <spdlog/spdlog.h>
#include "chrono/timer_factory.hpp"
#include "timer_manager.hpp"
#include "stats/stats_printer.hpp"

#include <memory>
#include <deque>

namespace asio { class io_context; }

namespace nexusminer 
{
namespace config { class Config; }
namespace stats { class Collector; }
namespace protocol { class Protocol; }
class Worker;

class Worker_manager : public std::enable_shared_from_this<Worker_manager>
{
public:

    using Config = config::Config;

    Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config, 
        chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket);

    bool connect(network::Endpoint const& wallet_endpoint);

    // stop the component and destroy all workers
    void stop();
    
    // Worker control methods for degraded mode (public for timer access)
    void check_template_health();

private:

    void process_data(network::Shared_payload&& receive_buffer);

    void create_stats_printers();
    void create_workers();
    
    // Worker control methods for degraded mode
    void stop_all_workers();
    void retry_template_request();

    void retry_connect(network::Endpoint const& wallet_endpoint);

	std::shared_ptr<::asio::io_context> m_io_context;
    Config& m_config;
	network::Socket::Sptr m_socket;
	network::Connection::Sptr m_connection;
    std::shared_ptr<spdlog::logger> m_logger;
    std::shared_ptr<stats::Collector> m_stats_collector;
    Timer_manager m_timer_manager;
    std::shared_ptr<protocol::Protocol> m_miner_protocol;
    
    // Degraded mode flag - set when mining is stopped due to invalid template
    bool m_degraded_mode;
    
    // Persistent receive accumulator for TCP stream reassembly
    // Using deque for O(1) front removal when consuming packets
    std::deque<uint8_t> m_rx_accumulator;

    // Connection retry state for exponential backoff
    uint32_t m_connection_retry_count{0};
    uint32_t m_current_retry_delay_seconds{0};  // 0 = use config default on first retry

    std::vector<std::shared_ptr<stats::Printer>> m_stats_printers;
    std::vector<std::shared_ptr<Worker>> m_workers;
};
}

#endif
