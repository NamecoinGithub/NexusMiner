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
#include <iomanip>
#include <sstream>
#include <deque>

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
        
        // ChaCha20 encryption is ALWAYS ON (core security) - no configuration needed
        // Explicit call kept for code clarity and to ensure proper initialization logging
        solo_protocol->enable_chacha20_wrapping(true);
        m_logger->info("[Worker_manager] ChaCha20 encryption: ENABLED (ALWAYS ON - core security)");
        
        // Disposable Falcon signing is ALWAYS ON (core protocol) - no configuration needed
        // Explicit call kept for code clarity and to ensure proper initialization logging
        solo_protocol->enable_disposable_falcon(true);
        m_logger->info("[Worker_manager] Disposable Falcon signing: ENABLED (ALWAYS ON - core protocol, 0 blockchain overhead)");
        
        // Physical Falcon signatures remain configurable (optional feature)
        // This is separate from Disposable Falcon and controlled via enable_physical_falcon()
        // Default: OFF for lazy miner economics (61% blockchain savings)
        
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
                for (size_t i = 0; i < m_workers.size(); ++i) {
                    auto& worker = m_workers[i];
                    if (worker) {
                        worker->set_block(block, nBits, [this](auto id, auto block_data)
                        {
                            if (!m_connection)
                            {
                                m_logger->error("[Worker_manager] No connection. Can't submit block.");
                                return;
                            }
                            
                            // Get the mining template interface to prepare full block submission
                            auto* solo_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
                            if (!solo_protocol)
                            {
                                m_logger->error("[Worker_manager] Failed to cast protocol to Solo protocol");
                                return;
                            }
                            
                            auto* template_interface = solo_protocol->get_template_interface();
                            if (!template_interface)
                            {
                                m_logger->error("[Worker_manager] Template interface not available");
                                return;
                            }
                            
                            // ✅ NEW: Final staleness check before submission (Template Staleness Prevention)
                            uint64_t template_age = template_interface->get_template_age();
                            if (template_interface->is_template_stale())
                            {
                                m_logger->error("[Worker_manager] ❌ Solution found but template is STALE!");
                                m_logger->error("[Worker_manager]    Age: {}s (max: 60s)", template_age);
                                m_logger->error("[Worker_manager]    Solution will likely be rejected - discarding");
                                template_interface->discard_template("Stale before submission");
                                
                                // Request fresh template
                                m_logger->info("[Worker_manager] Requesting fresh template via GET_BLOCK");
                                auto* solo_conn_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
                                if (solo_conn_protocol && m_connection) {
                                    auto work_payload = solo_conn_protocol->get_work();
                                    if (work_payload && !work_payload->empty()) {
                                        m_connection->transmit(work_payload);
                                    }
                                }
                                return;
                            }
                            
                            m_logger->info("[Worker_manager] 💎 Solution found! Template age: {}s (valid)", template_age);
                            
                            // Prepare full block submission (216 or 220 bytes depending on format)
                            // This reconstructs the full block from the current template with the
                            // mined merkle root and nonce
                            m_logger->info("[Worker_manager] Preparing full block submission");
                            m_logger->info("[Worker_manager]   Height: {}", block_data->nHeight);
                            m_logger->info("[Worker_manager]   Nonce:  0x{:016x}", block_data->nNonce);
                            
                            auto full_block_bytes = template_interface->prepare_block_submission(
                                block_data->merkle_root.GetBytes(), 
                                block_data->nNonce);
                            
                            if (full_block_bytes.empty())
                            {
                                m_logger->error("[Worker_manager] Failed to prepare block submission - empty payload");
                                m_logger->error("[Worker_manager]   This indicates template or block data is invalid");
                                return;
                            }
                            
                            m_logger->info("[Worker_manager] Full block serialized: {} bytes", full_block_bytes.size());
                            m_logger->info("[Worker_manager] Submitting block to protocol layer...");
                            
                            // Submit the full block (not just merkle root)
                            m_connection->transmit(m_miner_protocol->submit_block(
                                full_block_bytes, block_data->nNonce));
                        });
                        workers_fed++;
                        m_logger->debug("[Worker_manager] Template sent to worker {}/{}", 
                                       workers_fed, m_workers.size());
                    } else {
                        m_logger->warn("[Worker_manager] Skipping null worker at index {}", i);
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
                    
                    // Start GET_ROUND intelligent polling timer (LLL-TAO PR #131 + Intelligent Polling)
                    // Timer wakes up every 1 second, but protocol decides if GET_ROUND should actually be sent
                    // This implements exponential backoff (5s → 60s) and event-driven polling
                    constexpr uint16_t GET_ROUND_TIMER_INTERVAL = 1;  // Wake up every 1 second to check
                    auto solo_protocol_ptr = std::dynamic_pointer_cast<protocol::Solo>(self->m_miner_protocol);
                    if (solo_protocol_ptr) {
                        self->m_timer_manager.start_get_round_timer(GET_ROUND_TIMER_INTERVAL, self->m_connection, solo_protocol_ptr);
                        self->m_logger->info("[Solo Poll] Intelligent polling timer started (check interval: {}s, adaptive: 5s-60s)", 
                                            GET_ROUND_TIMER_INTERVAL);
                        self->m_logger->info("[Solo Poll] Uses exponential backoff + event-driven polling to minimize node spam");
                    } else {
                        self->m_logger->error("[Solo Poll] Failed to cast protocol to Solo - polling timer not started");
                    }
                    
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
    // Append newly received data to accumulator
    if (receive_buffer && !receive_buffer->empty())
    {
        std::size_t old_size = m_rx_accumulator.size();
        m_rx_accumulator.insert(m_rx_accumulator.end(), 
                               receive_buffer->begin(), 
                               receive_buffer->end());
        
        m_logger->trace("[RX] Received {} bytes, accumulator: {} -> {} bytes", 
                       receive_buffer->size(), old_size, m_rx_accumulator.size());
        
        // Warn if accumulator is growing large (possible stuck parsing or slow drain)
        constexpr std::size_t WARN_THRESHOLD = 100 * 1024; // 100KB
        if (m_rx_accumulator.size() > WARN_THRESHOLD && old_size <= WARN_THRESHOLD)
        {
            m_logger->warn("[RX] Accumulator growing large: {} bytes - possible parsing issue", 
                          m_rx_accumulator.size());
        }
    }
    
    // Get protocol lane from connection
    ProtocolLane lane = m_connection ? m_connection->get_protocol_lane() : ProtocolLane::UNKNOWN;
    
    if (lane == ProtocolLane::UNKNOWN)
    {
        m_logger->error("[RX] FATAL: Protocol lane is UNKNOWN - cannot parse packets");
        m_logger->error("[RX] Remote endpoint: {}", 
                       m_connection ? m_connection->remote_endpoint().to_string() : "no connection");
        m_logger->error("[RX] Disconnecting due to unknown protocol lane");
        if (m_connection)
        {
            m_connection->close();
        }
        m_rx_accumulator.clear();
        return;
    }
    
    // Parse packets from accumulator
    std::size_t total_consumed = 0;
    while (!m_rx_accumulator.empty())
    {
        // Create a vector view of the deque for parsing (deque doesn't guarantee contiguous storage)
        std::vector<uint8_t> buffer_view(m_rx_accumulator.begin(), m_rx_accumulator.end());
        auto buffer_shared = std::make_shared<network::Payload>(std::move(buffer_view));
        
        ParseResult parse_result;
        std::size_t bytes_consumed = 0;
        
        // Use new lane-aware parser with explicit result
        auto packet = extract_packet_from_buffer_with_result(
            buffer_shared, bytes_consumed, 0, lane, parse_result);
        
        if (parse_result == ParseResult::NEED_MORE_DATA)
        {
            // Not enough data yet - keep bytes in accumulator and wait for more
            m_logger->trace("[RX] Need more data: {} bytes in accumulator (lane: {})", 
                           m_rx_accumulator.size(), get_lane_name(lane));
            break;
        }
        else if (parse_result == ParseResult::MALFORMED)
        {
            // Malformed packet - log loudly and disconnect
            m_logger->error("[RX] ========================================");
            m_logger->error("[RX] MALFORMED PACKET DETECTED!");
            m_logger->error("[RX] ========================================");
            m_logger->error("[RX] Lane: {} ({})", 
                           get_lane_name(lane), 
                           lane == ProtocolLane::LEGACY ? "8-bit header" : "16-bit header");
            m_logger->error("[RX] Expected header width: {} bytes", 
                           lane == ProtocolLane::LEGACY ? 1 : 2);
            m_logger->error("[RX] Accumulator size: {} bytes", m_rx_accumulator.size());
            m_logger->error("[RX] Remote endpoint: {}", 
                           m_connection ? m_connection->remote_endpoint().to_string() : "no connection");
            
            // Log first few bytes for diagnostics
            std::size_t bytes_to_log = std::min<std::size_t>(16, m_rx_accumulator.size());
            if (bytes_to_log > 0)
            {
                std::ostringstream hex_dump;
                hex_dump << std::hex << std::setfill('0');
                for (std::size_t i = 0; i < bytes_to_log; ++i)
                {
                    if (i > 0) hex_dump << " ";
                    hex_dump << std::setw(2) << static_cast<unsigned>(m_rx_accumulator[i]);
                }
                m_logger->error("[RX] First {} bytes: {}", bytes_to_log, hex_dump.str());
            }
            
            m_logger->error("[RX] DISCONNECTING due to malformed packet");
            m_logger->error("[RX] ========================================");
            
            // Disconnect immediately
            if (m_connection)
            {
                m_connection->close();
            }
            
            // Clear accumulator
            m_rx_accumulator.clear();
            return;
        }
        else // ParseResult::SUCCESS
        {
            // Successfully parsed packet
            m_logger->trace("[RX] Parsed packet: header=0x{:04x}, length={}, consumed={} bytes", 
                           packet.m_header, packet.m_length, bytes_consumed);
            
            // Remove consumed bytes from front of deque (O(1) operation)
            for (std::size_t i = 0; i < bytes_consumed; ++i)
            {
                m_rx_accumulator.pop_front();
            }
            total_consumed += bytes_consumed;
            
            // Process the packet
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
    }
    
    if (total_consumed > 0)
    {
        m_logger->trace("[RX] Total consumed {} bytes, {} bytes remaining in accumulator", 
                       total_consumed, m_rx_accumulator.size());
    }
}

}