#include "worker_manager.hpp"
#include "cpu/worker_hash.hpp"

#include "fpga/worker_hash.hpp"
#ifdef GPU_CUDA_ENABLED
#include "gpu/worker_hash.hpp"
#endif
#if defined(PRIME_ENABLED) && defined(GPU_ENABLED)
#include "gpu/worker_prime.hpp"
#endif
#ifdef PRIME_ENABLED
#include "cpu/worker_prime.hpp"
#endif
#include "packet.hpp"
#include "config/config.hpp"
#include "config/types.hpp"
#include "LLP/block.hpp"
#include "stats/stats_printer_console.hpp"
#include "stats/stats_printer_file.hpp"
#include "stats/stats_collector.hpp"
#include "miner_keys.hpp"
#include "protocol/solo.hpp"
#include <variant>

namespace nexusminer
{
Worker_manager::Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config, 
    chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket)
: m_io_context{std::move(io_context)}
, m_config{config}
, m_socket{std::move(socket)}
, m_logger{spdlog::get("logger")}
, m_stats_collector{std::make_shared<stats::Collector>(m_config)}
, m_timer_manager{std::move(timer_factory)}
{
    // Solo mining requires Falcon authentication - no legacy fallback
    auto solo_protocol = std::make_shared<protocol::Solo>(m_config.get_mining_mode() == config::Mining_mode::PRIME ? 1U : 2U, m_stats_collector);
    
    // Falcon miner authentication is mandatory for solo mining
    if (!m_config.has_miner_falcon_keys())
    {
        m_logger->error("[Worker_manager] CRITICAL: Falcon authentication keys are required for solo mining");
        m_logger->error("[Worker_manager] Legacy authentication has been removed. Please configure Falcon keys:");
        m_logger->error("[Worker_manager]   1. Generate keys: ./NexusMiner --create-keys");
        m_logger->error("[Worker_manager]   2. Add keys to miner.conf (falcon_miner_pubkey and falcon_miner_privkey)");
        m_logger->error("[Worker_manager]   3. Whitelist your public key on the node:");
        m_logger->error("[Worker_manager]      - Config file: Add 'minerallowkey=<pubkey>' to nexus.conf");
        m_logger->error("[Worker_manager]      - Command line: Start nexus with -minerallowkey=<pubkey>");
        m_logger->error("[Worker_manager] See docs/falcon_authentication.md for detailed instructions");
        throw std::runtime_error("Falcon authentication keys are required for solo mining");
    }
        
        m_logger->info("[Worker_manager] Configuring Falcon miner authentication");
        
        std::vector<uint8_t> pubkey, privkey;
        if (!keys::from_hex(m_config.get_miner_falcon_pubkey(), pubkey) ||
            !keys::from_hex(m_config.get_miner_falcon_privkey(), privkey))
        {
            m_logger->error("[Worker_manager] CRITICAL: Failed to parse Falcon keys from config - invalid hex format");
            m_logger->error("[Worker_manager] Keys must be valid hexadecimal strings");
            m_logger->error("[Worker_manager] Use ./NexusMiner --create-keys to generate valid keys");
            throw std::runtime_error("Invalid Falcon key format in configuration");
        }
        
        solo_protocol->set_miner_keys(pubkey, privkey);
        solo_protocol->set_address(m_config.get_local_ip());
        
        // Configure Tritium GenesisHash if provided
        if (m_config.has_tritium_genesis()) {
            std::vector<uint8_t> genesis;
            if (keys::from_hex(m_config.get_tritium_genesis(), genesis)) {
                solo_protocol->set_tritium_genesis(genesis);
                m_logger->info("[Worker_manager] Tritium GenesisHash configured for reward binding");
            } else {
                m_logger->warn("[Worker_manager] Failed to parse Tritium GenesisHash - invalid hex format");
            }
        }
        
        // Configure keepalive interval
        solo_protocol->set_keepalive_interval(m_config.get_keepalive_interval());
        m_logger->info("[Worker_manager] Keepalive interval: {} hours", m_config.get_keepalive_interval());
        
        // Configure ChaCha20 wrapping (auto-enable for remote, optional for localhost)
        bool enable_chacha20 = m_config.get_enable_chacha20_wrapping();
        if (!enable_chacha20 && !m_config.is_localhost_mining()) {
            // Auto-enable for remote mining
            enable_chacha20 = true;
            m_logger->info("[Worker_manager] ChaCha20 wrapping AUTO-ENABLED for remote mining");
        }
        solo_protocol->enable_chacha20_wrapping(enable_chacha20);
        m_logger->info("[Worker_manager] ChaCha20 wrapping: {}", enable_chacha20 ? "ENABLED" : "DISABLED");
        
        // Configure optional block signing
        if (m_config.get_enable_block_signing()) {
            solo_protocol->enable_block_signing(true);
            m_logger->info("[Worker_manager] Block signing ENABLED for enhanced validation");
            m_logger->warn("[Worker_manager] Note: Block signing adds ~690 bytes to each submission");
        } else {
            m_logger->info("[Worker_manager] Block signing DISABLED (default for performance)");
        }
        
        // Configure reward address for stateless mining (MINER_SET_REWARD protocol)
        if (m_config.has_reward_address()) {
            solo_protocol->set_reward_address(m_config.get_reward_address());
            m_logger->info("[Worker_manager] Reward address configured: {}", m_config.get_reward_address());
        } else {
            m_logger->debug("[Worker_manager] No reward address configured - using node default");
        }
        
        m_logger->info("[Worker_manager] Falcon keys loaded from config");
        m_logger->info("[Worker_manager] Auth address: {}", m_config.get_local_ip());
        
        /* ========== REGISTER TEMPLATE DISTRIBUTION HANDLER ========== */
        /* Connects protocol layer (validated templates) to worker layer (mining threads) */
        /* This lambda is called by the template feed handler (PR #62) when templates arrive */
        solo_protocol->set_block_handler(
            [this](const ::LLP::CBlock& block, uint32_t nBits) {
                m_logger->info("[Worker_manager] ═══════════════════════════════════════");
                m_logger->info("[Worker_manager] DISTRIBUTING TEMPLATE TO {} WORKERS", m_workers.size());
                m_logger->info("[Worker_manager]   Height:     {}", block.nHeight);
                m_logger->info("[Worker_manager]   Channel:    {} ({})", 
                              block.nChannel,
                              (block.nChannel == 1) ? "prime" : "hash");
                m_logger->info("[Worker_manager]   Difficulty: 0x{:08x}", nBits);
                m_logger->info("[Worker_manager]   Merkle:     {}", 
                              block.hashMerkleRoot.ToString().substr(0, 16) + "...");
                m_logger->info("[Worker_manager] ═══════════════════════════════════════");
                
                /* Safety check - workers should be created by now */
                if (m_workers.empty()) {
                    m_logger->error("[Worker_manager] CRITICAL: No workers available for mining!");
                    m_logger->error("[Worker_manager]   Workers may not be initialized yet");
                    m_logger->error("[Worker_manager]   Template will be lost - mining cannot start");
                    return;
                }
                
                /* Distribute template to all worker threads */
                size_t workers_fed = 0;
                for (auto& worker : m_workers) {
                    if (worker) {
                        worker->set_block(block, nBits, [this](auto id, auto block_data)
                        {
                            if (m_connection)
                                m_connection->transmit(m_miner_protocol->submit_block(
                                    block_data->merkle_root.GetBytes(), block_data->nNonce));
                            else
                            {
                                m_logger->error("No connection. Can't submit block.");
                            }
                        });
                        workers_fed++;
                        m_logger->debug("[Worker_manager] Template sent to worker {}/{}", 
                                       workers_fed, m_workers.size());
                    } else {
                        m_logger->warn("[Worker_manager] Skipping null worker at index {}", workers_fed);
                    }
                }
                
                if (workers_fed > 0) {
                    m_logger->info("[Worker_manager] ✓ Template distributed to {} workers - MINING STARTED", 
                                  workers_fed);
                } else {
                    m_logger->error("[Worker_manager] FAILED: No workers received template!");
                }
            }
        );
        
        m_logger->info("[Worker_manager] Template distribution handler registered");
        
        m_miner_protocol = solo_protocol;
  
    create_stats_printers();
    create_workers();
}

void Worker_manager::create_stats_printers()
{
    bool printer_console_created = false;
    bool printer_file_created = false;
    for(auto& stats_printer_config : m_config.get_stats_printer_config())
    {
        switch(stats_printer_config.m_mode)
        {
            case config::Stats_printer_mode::FILE:
            {
                if(!printer_file_created)
                {
                    printer_file_created = true;
                    auto& stats_printer_config_file = std::get<config::Stats_printer_config_file>(stats_printer_config.m_printer_mode);
                    m_stats_printers.push_back(std::make_shared<stats::Printer_file<stats::Printer_solo>>(stats_printer_config_file.file_name,
                        m_config.get_mining_mode(), m_config.get_worker_config(), *m_stats_collector));
                }
                break;
            }
            case config::Stats_printer_mode::CONSOLE:    // falltrough
            default:
            {
                if(!printer_console_created)
                {
                    printer_console_created = true;
                    m_stats_printers.push_back(std::make_shared<stats::Printer_console<stats::Printer_solo>>(m_config.get_mining_mode(),
                        m_config.get_worker_config(), *m_stats_collector));
                }
                break;
            }
        }
    }

    if(m_stats_printers.empty())
    {
        m_logger->warn("No stats printer configured.");
    }
}

void Worker_manager::create_workers()
{
    auto internal_id = 0U;
    for(auto& worker_config : m_config.get_worker_config())
    {
        worker_config.m_internal_id = internal_id;
        switch(worker_config.m_mode)
        {
            case config::Worker_mode::FPGA:
            {
                if (m_config.get_mining_mode() == config::Mining_mode::PRIME)
                {
                    m_logger->error("FPGA worker is not supported for PRIME mining!");
                }
                else
                {
                    m_workers.push_back(std::make_shared<fpga::Worker_hash>(m_io_context, worker_config));
                }
                break;
            }
            case config::Worker_mode::GPU:
            {
#ifdef GPU_ENABLED
                if (m_config.get_mining_mode() == config::Mining_mode::PRIME)
                {
#ifdef PRIME_ENABLED
                    m_workers.push_back(std::make_shared<gpu::Worker_prime>(m_io_context, worker_config));
#else
                    m_logger->error("NexusMiner not built 'WITH_PRIME' -> no worker created!");
#endif
                }
#if defined(GPU_CUDA_ENABLED) && !defined(PRIME_ENABLED)
                else
                {
                    m_workers.push_back(std::make_shared<gpu::Worker_hash>(m_io_context, worker_config));
                }                
#elif defined(GPU_AMD_ENABLED) && !defined(PRIME_ENABLED)
                m_logger->error("NexusMiner 'WITH_GPU_AMD' but not 'WITH_PRIME'.  Hash mode on AMD is not supported. -> no worker created!");
#endif
#else
                m_logger->error("NexusMiner not built 'WITH_GPU_CUDA' or 'WITH_GPU_AMD' -> no worker created!");
#endif
                break;
            }
            case config::Worker_mode::CPU:    // falltrough
            default:
            {
                if (m_config.get_mining_mode() == config::Mining_mode::PRIME)
                {
#ifdef PRIME_ENABLED
                    m_workers.push_back(std::make_shared<cpu::Worker_prime>(m_io_context, worker_config));
#else
                    m_logger->error("NexusMiner not built 'WITH_PRIME' -> no worker created!");
#endif
                }
                else
                {
                    m_workers.push_back(std::make_shared<cpu::Worker_hash>(m_io_context, worker_config));
                }
                break;
            }
        }
        internal_id++;
    }
}

void Worker_manager::stop()
{
    m_timer_manager.stop();

    // close connection
    m_connection.reset();

    // destroy workers
    for(auto& worker : m_workers)
    {
        worker.reset();
    }
}

void Worker_manager::retry_connect(network::Endpoint const& wallet_endpoint)
{           
    m_connection = nullptr;		// close connection (socket etc)
    m_miner_protocol->reset();
    stats::Global global_stats{};
    global_stats.m_connection_retries = 1;
    m_stats_collector->update_global_stats(global_stats);

    // retry connect
    auto const connection_retry_interval = m_config.get_connection_retry_interval();
    m_logger->info("Connection retry {} seconds", connection_retry_interval);
    m_timer_manager.start_connection_retry_timer(connection_retry_interval, shared_from_this(), wallet_endpoint);
}

bool Worker_manager::connect(network::Endpoint const& wallet_endpoint)
{
    std::string wallet_addr;
    wallet_endpoint.address(wallet_addr);
    uint16_t configured_port = wallet_endpoint.port();
    
    m_logger->info("[Solo] Connecting to wallet {}:{}", wallet_addr, configured_port);
    m_logger->info("[Solo] Port Configuration: Using port {} from miner.conf", configured_port);
    m_logger->debug("[Solo] Connection initiated to endpoint: {}", wallet_endpoint.to_string());
    
    std::weak_ptr<Worker_manager> weak_self = shared_from_this();
    auto connection = m_socket->connect(wallet_endpoint, [weak_self, wallet_endpoint](auto result, auto receive_buffer)
    {
        auto self = weak_self.lock();
        if(self)
        {
            if (result == network::Result::connection_declined ||
                result == network::Result::connection_aborted ||
                result == network::Result::connection_closed ||
                result == network::Result::connection_error)
            {
                self->m_logger->error("[Solo] Connection to wallet {} not successful. Result: {} - This may indicate wallet lock, sync issues, or network problems", 
                    wallet_endpoint.to_string(), network::Result::code_to_string(result));
                self->retry_connect(wallet_endpoint);
            }
            else if (result == network::Result::connection_ok)
            {
                // Log successful connection with actual port information
                auto const& remote_ep = self->m_connection->remote_endpoint();
                auto const& local_ep = self->m_connection->local_endpoint();
                
                std::string remote_addr, local_addr;
                remote_ep.address(remote_addr);
                local_ep.address(local_addr);
                
                uint16_t actual_remote_port = remote_ep.port();
                uint16_t actual_local_port = local_ep.port();
                
                self->m_logger->info("[Solo] Connected to wallet {}", wallet_endpoint.to_string());
                self->m_logger->info("[Solo] Dynamic Port Detection: Successfully connected to {}:{}", 
                    remote_addr, actual_remote_port);
                self->m_logger->info("[Solo] Local endpoint: {}:{}", local_addr, actual_local_port);
                self->m_logger->debug("[Solo] Port Validation: Connection established on LLP port {}", 
                    actual_remote_port);

                // login
                self->m_connection->transmit(self->m_miner_protocol->login([self, wallet_endpoint](bool login_result)
                {
                    if(!login_result)
                    {
                        self->retry_connect(wallet_endpoint);
                        return;
                    }

                    auto const print_statistics_interval = self->m_config.get_print_statistics_interval();
                    self->m_timer_manager.start_stats_collector_timer(print_statistics_interval, self->m_workers, self->m_stats_collector);
                    self->m_timer_manager.start_stats_printer_timer(print_statistics_interval, self->m_stats_printers);

                    // Solo mining uses stateless protocol with mandatory Falcon authentication (no GET_HEIGHT)
                    self->m_logger->info("[Solo Phase 2] Stateless mining mode - GET_HEIGHT timer disabled");
                    self->m_logger->info("[Solo Phase 2] Work requests handled via GET_BLOCK after successful auth");
                    // Note: Block handler already registered in Worker_manager constructor
                }));
            }
            else
            {
                if (!self->m_connection)
                {
                    self->m_logger->error("No connection to wallet.");
                    self->retry_connect(wallet_endpoint);
                }
                // data received
                self->process_data(std::move(receive_buffer));
            }
        }
    });

    if(!connection)
    {
        return false;
    }

    m_connection = std::move(connection);
    return true;
}

void Worker_manager::process_data(network::Shared_payload&& receive_buffer)
{
    auto remaining_size = receive_buffer->size();
    do
    {
        auto packet = extract_packet_from_buffer(receive_buffer, remaining_size, receive_buffer->size() - remaining_size);
        if (!packet.is_valid())
        {
            m_logger->debug("Received packet is invalid. Header: {0}", packet.m_header);
            continue;
        }

        if (packet.m_header == Packet::PING)
        {
            m_logger->trace("PING received");
        }
        else
        {
            // solo/pool specific messages
            m_miner_protocol->process_messages(std::move(packet), m_connection);
        }
    }
    while (remaining_size != 0);
}

}