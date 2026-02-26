#include "timer_manager.hpp"
#include "network/endpoint.hpp"
#include "network/connection.hpp"
#include "packet.hpp"
#include "worker_manager.hpp"
#include "stats/stats_collector.hpp"
#include "stats/stats_printer.hpp"
#include "worker.hpp"
#include "protocol/solo.hpp"
#include <spdlog/spdlog.h>

namespace nexusminer
{
Timer_manager::Timer_manager(chrono::Timer_factory::Sptr timer_factory)
: m_timer_factory{std::move(timer_factory)}
, m_logger{spdlog::get("logger")}
{
    m_connection_retry_timer = m_timer_factory->create_timer();
    m_ping_timer = m_timer_factory->create_timer();
    m_secondary_ping_timer = m_timer_factory->create_timer();
    m_stats_collector_timer = m_timer_factory->create_timer();
    m_stats_printer_timer = m_timer_factory->create_timer();
    m_get_round_timer = m_timer_factory->create_timer();  // Template Staleness Prevention
    m_template_health_timer = m_timer_factory->create_timer();  // Template Health Monitoring
    m_secondary_connection_retry_timer = m_timer_factory->create_timer();  // SIM Link secondary
    m_lane_health_check_timer = m_timer_factory->create_timer();  // SIM Link lane health log
}

void Timer_manager::start_connection_retry_timer(std::uint16_t timer_interval, std::weak_ptr<Worker_manager> worker_manager, 
    network::Endpoint const& wallet_endpoint)
{
    m_connection_retry_timer->start(chrono::Seconds(timer_interval), 
        connection_retry_handler(std::move(worker_manager), wallet_endpoint));
}

void Timer_manager::start_ping_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection)
{
    m_ping_timer->start(chrono::Seconds(timer_interval), ping_handler(timer_interval, std::move(connection)));
}

void Timer_manager::start_secondary_ping_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection)
{
    m_secondary_ping_timer->start(chrono::Seconds(timer_interval), secondary_ping_handler(timer_interval, std::move(connection)));
}

void Timer_manager::start_stats_collector_timer(std::uint16_t timer_interval, std::vector<std::shared_ptr<Worker>> workers, 
    std::shared_ptr<stats::Collector> stats_collector)
{
    m_stats_collector_timer->start(chrono::Seconds(timer_interval), stats_collector_handler(timer_interval, workers, 
        std::move(stats_collector)));
}

void Timer_manager::start_stats_printer_timer(std::uint16_t timer_interval, std::vector<std::shared_ptr<stats::Printer>> stats_printers)
{
    m_stats_printer_timer->start(chrono::Seconds(timer_interval), stats_printer_handler(timer_interval, std::move(stats_printers)));
}

void Timer_manager::start_get_round_timer(std::uint16_t timer_interval, std::weak_ptr<network::Connection> connection,
    std::weak_ptr<protocol::Solo> solo_protocol)
{
    m_get_round_timer->start(chrono::Seconds(timer_interval), get_round_handler(timer_interval, std::move(connection), std::move(solo_protocol)));
}

void Timer_manager::stop()
{
    m_connection_retry_timer->cancel();
    m_ping_timer->cancel();
    m_secondary_ping_timer->cancel();
    m_stats_collector_timer->cancel();
    m_stats_printer_timer->cancel();
    m_get_round_timer->cancel();  // Template Staleness Prevention
    m_secondary_connection_retry_timer->cancel();  // SIM Link secondary lane
    m_lane_health_check_timer->cancel();  // SIM Link lane health log
}

chrono::Timer::Handler Timer_manager::connection_retry_handler(std::weak_ptr<Worker_manager> worker_manager,
    network::Endpoint const& wallet_endpoint)
{
    return[worker_manager, wallet_endpoint](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        auto worker_manager_shared = worker_manager.lock();
        if(worker_manager_shared)
        {
            worker_manager_shared->connect(wallet_endpoint);
        }
    }; 
}

chrono::Timer::Handler Timer_manager::ping_handler(std::uint16_t ping_interval, std::weak_ptr<network::Connection> connection)
{
    return[this, connection, ping_interval](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        auto connection_shared = connection.lock();
        if (connection_shared)
        {
            Packet packet{ static_cast<uint8_t>(Packet::PING) };
            connection_shared->transmit(packet.get_bytes());

            // restart timer
            m_ping_timer->start(chrono::Seconds(ping_interval), ping_handler(ping_interval, std::move(connection_shared)));
        }
    };
}

chrono::Timer::Handler Timer_manager::secondary_ping_handler(std::uint16_t ping_interval, std::weak_ptr<network::Connection> connection)
{
    return[this, connection, ping_interval](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        auto connection_shared = connection.lock();
        if (connection_shared)
        {
            Packet packet{ static_cast<uint8_t>(Packet::PING) };
            connection_shared->transmit(packet.get_bytes());

            // restart timer
            m_secondary_ping_timer->start(chrono::Seconds(ping_interval), secondary_ping_handler(ping_interval, std::move(connection_shared)));
        }
    };
}

chrono::Timer::Handler Timer_manager::stats_collector_handler(std::uint16_t stats_collector_interval, 
    std::vector<std::shared_ptr<Worker>> workers, std::shared_ptr<stats::Collector> stats_collector)
{
    return[this, workers, stats_collector_interval, stats_collector = std::move(stats_collector)](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        for(auto& worker : workers)
        {
            worker->update_statistics(*stats_collector);
        }
        // restart timer
        m_stats_collector_timer->start(chrono::Seconds(stats_collector_interval), 
            stats_collector_handler(stats_collector_interval, workers, std::move(stats_collector)));
    }; 
}

chrono::Timer::Handler Timer_manager::stats_printer_handler(std::uint16_t stats_printer_interval, 
    std::vector<std::shared_ptr<stats::Printer>> stats_printers)
{
    return[this, stats_printer_interval, stats_printers = std::move(stats_printers)](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        for(auto& stats_printer : stats_printers)
        {
            stats_printer->print();
        }

        // restart timer
         m_stats_printer_timer->start(chrono::Seconds(stats_printer_interval), stats_printer_handler(stats_printer_interval, 
            std::move(stats_printers)));
    }; 
}

chrono::Timer::Handler Timer_manager::get_round_handler(std::uint16_t get_round_interval, std::weak_ptr<network::Connection> connection,
    std::weak_ptr<protocol::Solo> solo_protocol)
{
    return [this, connection, solo_protocol, get_round_interval](bool canceled)
    {
        if (canceled)	// don't do anything if the timer has been canceled
        {
            return;
        }

        auto connection_shared = connection.lock();
        auto protocol_shared = solo_protocol.lock();
        
        if(connection_shared && protocol_shared)
        {
            // Intelligent polling: only send if protocol says it's time
            if (protocol_shared->should_send_get_round())
            {
                // GET_ROUND is the sanity-check probe; GET_BLOCK is the recovery action.
                // Relationship:
                //   GET_ROUND → height probe → if stale/no-template → GET_BLOCK (recovery)
                //   GET_BLOCK → template request → BLOCK_DATA response → resume mining
                // GET_ROUND does NOT itself deliver a template; it is only the trigger for GET_BLOCK.
                auto payload = protocol_shared->send_get_round();
                if (payload && !payload->empty()) {
                    connection_shared->transmit(payload);
                }

                // After sending the GET_ROUND probe, check if we also need a fresh template.
                // This covers the case where push notifications were missed while POLLING_ENABLED.
                if (!protocol_shared->has_valid_template()) {
                    if (m_logger) {
                        m_logger->info("[Timer GET_ROUND] No valid template — using GET_ROUND result to trigger GET_BLOCK recovery");
                    }
                    auto recovery = protocol_shared->send_recovery_work_request();
                    if (recovery && !recovery->empty()) {
                        connection_shared->transmit(recovery);
                    }
                }
            }

            // Restart timer - use weak_ptr to avoid move invalidation
            // Timer wakes up frequently (1s) but protocol controls actual sending
            m_get_round_timer->start(chrono::Seconds(get_round_interval), 
                get_round_handler(get_round_interval, connection, solo_protocol));
        }
    }; 
}

void Timer_manager::start_template_health_timer(std::uint16_t timer_interval, std::weak_ptr<Worker_manager> worker_manager)
{
    m_template_health_timer->start(chrono::Seconds(timer_interval), 
        template_health_handler(timer_interval, std::move(worker_manager)));
}

chrono::Timer::Handler Timer_manager::template_health_handler(std::uint16_t health_check_interval, 
    std::weak_ptr<Worker_manager> worker_manager)
{
    return [this, health_check_interval, worker_manager](bool canceled)
    {
        if (canceled)  // don't do anything if the timer has been canceled
        {
            return;
        }

        auto worker_manager_shared = worker_manager.lock();
        
        if (worker_manager_shared)
        {
            // Check template health
            worker_manager_shared->check_template_health();

            // Restart timer
            m_template_health_timer->start(chrono::Seconds(health_check_interval), 
                template_health_handler(health_check_interval, worker_manager));
        }
    }; 
}

void Timer_manager::start_secondary_connection_retry_timer(std::uint16_t timer_interval,
    std::weak_ptr<Worker_manager> worker_manager,
    network::Endpoint const& secondary_endpoint)
{
    m_secondary_connection_retry_timer->start(chrono::Seconds(timer_interval),
        secondary_connection_retry_handler(std::move(worker_manager), secondary_endpoint));
}

void Timer_manager::start_lane_health_check_timer(std::uint16_t timer_interval,
    std::weak_ptr<Worker_manager> worker_manager)
{
    m_lane_health_check_timer->start(chrono::Seconds(timer_interval),
        lane_health_check_handler(timer_interval, std::move(worker_manager)));
}

chrono::Timer::Handler Timer_manager::secondary_connection_retry_handler(
    std::weak_ptr<Worker_manager> worker_manager,
    network::Endpoint const& secondary_endpoint)
{
    return [worker_manager, secondary_endpoint](bool canceled)
    {
        if (canceled)
        {
            return;
        }

        auto wm = worker_manager.lock();
        if (wm)
        {
            wm->connect_secondary(secondary_endpoint);
        }
    };
}

chrono::Timer::Handler Timer_manager::lane_health_check_handler(std::uint16_t health_check_interval,
    std::weak_ptr<Worker_manager> worker_manager)
{
    return [this, health_check_interval, worker_manager](bool canceled)
    {
        if (canceled)
        {
            return;
        }

        auto wm = worker_manager.lock();
        if (wm)
        {
            wm->log_lane_health();

            m_lane_health_check_timer->start(chrono::Seconds(health_check_interval),
                lane_health_check_handler(health_check_interval, worker_manager));
        }
    };
}

}
