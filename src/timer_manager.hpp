#ifndef NEXUSMINER_TIMER_MANAGER_HPP
#define NEXUSMINER_TIMER_MANAGER_HPP

#include "chrono/timer_factory.hpp"
#include "chrono/timer.hpp"

#include <memory>
#include <vector>

namespace nexusminer 
{
namespace network
{
    class Endpoint;
    class Connection;
}
namespace protocol
{
    class Solo;
}
namespace stats
{
    class Printer;
    class Collector;
}
class Worker_manager;
class Worker;


class Timer_manager
{
public:

    Timer_manager(chrono::Timer_factory::Sptr timer_factory);

    void start_connection_retry_timer(std::uint16_t timer_interval, std::weak_ptr<Worker_manager> worker_manager, 
        network::Endpoint const& wallet_endpoint);
    void start_get_height_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection);
    void start_ping_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection);
    void start_stats_collector_timer(std::uint16_t timer_interval, std::vector<std::shared_ptr<Worker>> workers, 
        std::shared_ptr<stats::Collector> stats_collector);
    void start_stats_printer_timer(std::uint16_t timer_interval, std::vector<std::shared_ptr<stats::Printer>> stats_printers);
    
    // Template Staleness Prevention (LLL-TAO PR #131 Client-Side Integration)
    void start_get_round_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection,
        std::weak_ptr<protocol::Solo> solo_protocol);
    
    // Template Health Monitoring (Template Validation & Worker Protection)
    void start_template_health_timer(std::uint16_t timer_interval, std::weak_ptr<Worker_manager> worker_manager);

    void stop();

private:

    chrono::Timer::Handler connection_retry_handler(std::weak_ptr<Worker_manager> worker_manager, 
        network::Endpoint const& wallet_endpoint);
    chrono::Timer::Handler get_height_handler(std::uint16_t get_height_interval, std::weak_ptr<network::Connection> connection);
    chrono::Timer::Handler ping_handler(std::uint16_t ping_interval, std::weak_ptr<network::Connection> connection);
    chrono::Timer::Handler stats_collector_handler(std::uint16_t stats_collector_interval, std::vector<std::shared_ptr<Worker>> workers, 
        std::shared_ptr<stats::Collector> stats_collector);
    chrono::Timer::Handler stats_printer_handler(std::uint16_t stats_printer_interval, std::vector<std::shared_ptr<stats::Printer>> stats_printers);
    chrono::Timer::Handler get_round_handler(std::uint16_t get_round_interval, std::weak_ptr<network::Connection> connection,
        std::weak_ptr<protocol::Solo> solo_protocol);
    chrono::Timer::Handler template_health_handler(std::uint16_t health_check_interval, 
        std::weak_ptr<Worker_manager> worker_manager);

    chrono::Timer_factory::Sptr m_timer_factory;
    chrono::Timer::Uptr m_connection_retry_timer;
    chrono::Timer::Uptr m_get_height_timer;
    chrono::Timer::Uptr m_ping_timer;
    chrono::Timer::Uptr m_stats_collector_timer;
    chrono::Timer::Uptr m_stats_printer_timer;
    chrono::Timer::Uptr m_get_round_timer;  // Template Staleness Prevention
    chrono::Timer::Uptr m_template_health_timer;  // Template Health Monitoring
};
}

#endif
