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
#include "mining/client_block.h"
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

// Template age timeout constants (seconds) - unified for both Prime and Hash channels.
// In the push-driven protocol the node pushes a fresh template on every unified tip advance
// (including hash blocks every ~18s).  If 200s elapse with no push, the connection is
// likely dead regardless of channel — hence a single emergency threshold for both.
// WARNING at 150s gives operators a 50s window to notice the approaching emergency.
namespace {
    constexpr uint64_t TEMPLATE_AGE_WARNING_SECONDS = 150;          // warn 50s before emergency
    constexpr uint64_t TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS = 200; // matches MiningTemplateInterface::MAX_TEMPLATE_AGE
}

Worker_manager::Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config, 
    chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket)
: m_io_context{std::move(io_context)}
, m_config{config}
, m_socket{std::move(socket)}
, m_logger{spdlog::get("logger")}
, m_stats_collector{std::make_shared<stats::Collector>(m_config)}
, m_timer_manager{std::move(timer_factory)}
, m_degraded_mode{false}
{
    // Solo mining requires Falcon authentication - no legacy fallback
    auto solo_protocol = std::make_shared<protocol::Solo>(m_config.get_mining_mode() == config::Mining_mode::PRIME ? 1U : 2U,
        m_stats_collector, m_io_context);
    
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
                m_logger->info("[Worker_manager]   Merkle:     {}...", 
                              block.hashMerkleRoot.ToString().substr(0, 16));
                m_logger->info("[Worker_manager]   PrevHash:   {}...",
                              block.hashPrevBlock.ToString().substr(0, 20));
                m_logger->info("[Worker_manager] ═══════════════════════════════════════");
                
                // ═══════════════════════════════════════════════════════════════
                // AUTO-RECOVERY: Clear degraded mode on valid template arrival
                // ═══════════════════════════════════════════════════════════════
                if (m_degraded_mode) {
                    m_logger->info("[Worker_manager] ✅ RECOVERY: Valid template received!");
                    m_logger->info("[Worker_manager]    Clearing degraded mode");
                    m_logger->info("[Worker_manager]    Resuming normal mining operations");
                    m_degraded_mode = false;
                    
                    // Update stats to reflect recovery
                    auto global_stats = m_stats_collector->get_global_stats();
                    global_stats.m_degraded_mode = false;
                    m_stats_collector->update_global_stats(global_stats);
                }
                
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
                            m_logger->info("════════════════════════════════════════════════════════");
                            m_logger->info("💎 BLOCK FOUND CALLBACK INVOKED!");
                            m_logger->info("   Worker ID:  {}", id);
                            m_logger->info("   Height:     {}", block_data->nHeight);
                            m_logger->info("   Nonce:      0x{:016x}", block_data->nNonce);
                            m_logger->info("════════════════════════════════════════════════════════");
                            
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

                            // Check 1 — Channel Height (PRIMARY: has another miner found this block?)
                            // Use HeightTracker snapshot as single source of truth for staleness
                            auto ht_snap = solo_protocol->get_height_tracker_snapshot();
                            bool channel_stale = ht_snap.is_template_stale();

                            // Check 2 — Age (SECONDARY: safety net for missed push notifications)
                            // 200s matches the push-driven era MAX_TEMPLATE_AGE
                            constexpr uint64_t SUBMISSION_MAX_AGE_SECONDS = 200;
                            bool age_stale = (template_age > SUBMISSION_MAX_AGE_SECONDS);

                            if (channel_stale || age_stale)
                            {
                                if (channel_stale) {
                                    m_logger->error("[Worker_manager] ❌ Solution found but channel height ADVANCED!");
                                    m_logger->error("[Worker_manager]    channel_height {} >= channel_target {}",
                                                   ht_snap.channel_height, ht_snap.channel_target);
                                    m_logger->error("[Worker_manager]    Another miner found this block first - discarding");
                                } else {
                                    m_logger->error("[Worker_manager] ❌ Solution found but template too old: {}s (max: {}s)",
                                                   template_age, SUBMISSION_MAX_AGE_SECONDS);
                                    m_logger->error("[Worker_manager]    Push notifications likely missed - discarding");
                                }
                                template_interface->discard_template(channel_stale ? "Channel height advanced before submission"
                                                                                   : "Age exceeded 600s before submission");
                                
                                // ====== LANE-GATED STALE TEMPLATE REFRESH ======
                                // Lane-aware recovery: only use legacy polling on legacy lane
                                ProtocolLane lane = m_connection->get_protocol_lane();
                                uint16_t remote_port = m_connection->remote_endpoint().port();
                                
                                m_logger->info("[Worker_manager] Stale template recovery on {} lane (port {})", 
                                              get_lane_name(lane), remote_port);
                                
                                if (lane == ProtocolLane::LEGACY) {
                                    // Legacy lane: Request fresh template via GET_BLOCK polling
                                    m_logger->info("[Worker_manager] → Sending GET_BLOCK request (legacy polling)");
                                    auto* solo_conn_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
                                    if (solo_conn_protocol && m_connection) {
                                        auto work_payload = solo_conn_protocol->get_work();
                                        if (work_payload && !work_payload->empty()) {
                                            m_connection->transmit(work_payload);
                                        }
                                    }
                                } else if (lane == ProtocolLane::STATELESS) {
                                    // Stateless lane: Re-send STATELESS_MINER_READY to prompt node state machine
                                    m_logger->info("[Worker_manager] → Re-sending STATELESS_MINER_READY (no polling)");
                                    m_logger->info("[Worker_manager]   Prompts node to push fresh STATELESS_GET_BLOCK");
                                    auto* solo_conn_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
                                    if (solo_conn_protocol && m_connection) {
                                        auto miner_ready_payload = solo_conn_protocol->send_miner_ready();
                                        if (miner_ready_payload && !miner_ready_payload->empty()) {
                                            m_connection->transmit(miner_ready_payload);
                                        }
                                    }
                                } else {
                                    m_logger->error("[Worker_manager] → Unknown protocol lane - cannot recover");
                                }
                                return;
                            }
                            
                            m_logger->info("[Worker_manager] 💎 Solution found! Age: {}s, Channel height valid ✅ - SUBMITTING", template_age);
                            
                            // Gap 2: Log hashPrevBlock before submission (SUBMIT AUDIT).
                            // Cross-reference: node Guard 2 checks pBlock->hashPrevBlock == hashBestChain.
                            // If node rejects "stale block", compare this log against node's hashBestChain.
                            {
                                auto const* submit_tmpl = template_interface->get_current_template();
                                if (submit_tmpl) {
                                    auto prev_bytes = submit_tmpl->block.hashPrevBlock.GetBytes();
                                    std::string prev_hex;
                                    for (size_t i = 0; i < std::min(prev_bytes.size(), size_t(8)); ++i) {
                                        char buf[3];
                                        snprintf(buf, sizeof(buf), "%02x", prev_bytes[i]);
                                        prev_hex += buf;
                                    }
                                    m_logger->info("[SUBMIT AUDIT]   block.hashPrevBlock = {}... (tip anchor — node Guard 2 will verify this == hashBestChain)", prev_hex);
                                }
                            }

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
        
        /* ========== REGISTER VALIDATION FAILURE HANDLER ========== */
        /* This handler is called when template validation fails */
        /* It stops workers and requests a fresh template */
        auto* template_interface = solo_protocol->get_template_interface();
        if (template_interface) {
            template_interface->set_validation_failure_handler(
                [this](const protocol::MiningTemplateInterface::ValidationResult& result) {
                    m_logger->error("[Worker_manager] ════════════════════════════════════════");
                    m_logger->error("[Worker_manager] ⚠️  TEMPLATE VALIDATION FAILED");
                    m_logger->error("[Worker_manager]    Reason: {}", result.error_message);
                    m_logger->error("[Worker_manager] ════════════════════════════════════════");
                    
                    // Stop all workers
                    stop_all_workers();
                    
                    // Request fresh template
                    retry_template_request();
                }
            );
            m_logger->info("[Worker_manager] Validation failure handler registered");
        } else {
            m_logger->warn("[Worker_manager] Template interface not available - validation failure handler not registered");
        }
        
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
    // Save endpoint so retry_template_request() can force a full reconnect if needed
    m_wallet_endpoint = wallet_endpoint;

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
                // BUGFIX: The socket API documents that the handler may fire synchronously
                // inside connect() before m_connection = std::move(connection) is reached
                // at the bottom of Worker_manager::connect(). This occurs when
                // local_ip = "0.0.0.0" causes an immediate loopback connect completion.
                // Guard against null m_connection and defer via io_context post.
                if (!self->m_connection)
                {
                    self->m_logger->warn("[Solo] Synchronous connect callback detected - "
                                         "m_connection not yet assigned, deferring to io_context");
                    ::asio::post(*self->m_io_context, [self, wallet_endpoint]()
                    {
                        // By the time this runs, m_connection has been assigned by the
                        // return path of Worker_manager::connect(). Retry the connect
                        // sequence to trigger the full connection_ok flow properly.
                        self->retry_connect(wallet_endpoint);
                    });
                    return;
                }

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
                if (auto solo_protocol = std::dynamic_pointer_cast<protocol::Solo>(self->m_miner_protocol))
                {
                    solo_protocol->set_protocol_lane(self->m_connection->get_protocol_lane());
                }

                self->m_connection->transmit(self->m_miner_protocol->login([self, wallet_endpoint](bool login_result)
                {
                    if(!login_result)
                    {
                        self->retry_connect(wallet_endpoint);
                        return;
                    }

                    // Fresh connection established — reset template retry counter
                    self->m_template_retry_count = 0;

                    auto const print_statistics_interval = self->m_config.get_print_statistics_interval();
                    self->m_timer_manager.start_stats_collector_timer(print_statistics_interval, self->m_workers, self->m_stats_collector);
                    self->m_timer_manager.start_stats_printer_timer(print_statistics_interval, self->m_stats_printers);

                    // Solo mining uses stateless protocol with mandatory Falcon authentication (no GET_HEIGHT)
                    self->m_logger->info("[Solo Phase 2] Stateless mining mode - GET_HEIGHT timer disabled");
                    self->m_logger->info("[Solo Phase 2] Work requests handled via GET_BLOCK after successful auth");
                    
                    // ====== GET_ROUND POLLING (All Lanes) ======
                    // GET_ROUND polling is DISABLED by default.
                    // Push notifications are primary, template health monitor (300s) is safety net.
                    // Timer still runs to support optional sanity-check polling if enabled.
                    ProtocolLane lane = self->m_connection->get_protocol_lane();
                    uint16_t remote_port = self->m_connection->remote_endpoint().port();
                    
                    self->m_logger->info("[Worker_manager Lane] Reading protocol lane from connection");
                    self->m_logger->info("[Worker_manager Lane]   Lane: {} (port {})", get_lane_name(lane), remote_port);
                    self->m_logger->info("[Worker_manager Lane]   Verifying lane agreement with Solo protocol layer");
                    
                    {
                        // Start GET_ROUND timer for ALL lanes
                        // Polling is disabled by default (push notifications are primary).
                        // Timer still runs but should_send_get_round() returns false when disabled.
                        constexpr uint16_t GET_ROUND_TIMER_INTERVAL = 1;  // Wake up every 1 second to check
                        auto solo_protocol_ptr = std::dynamic_pointer_cast<protocol::Solo>(self->m_miner_protocol);
                        if (solo_protocol_ptr) {
                            self->m_timer_manager.start_get_round_timer(GET_ROUND_TIMER_INTERVAL, self->m_connection, solo_protocol_ptr);
                            self->m_logger->info("[Solo Poll] ✓ GET_ROUND timer started on {} lane (port {})",
                                get_lane_name(lane), remote_port);
                            self->m_logger->info("[Solo Poll]   Polling: disabled (push notifications are primary, health monitor is safety net)");
                        } else {
                            self->m_logger->error("[Solo Poll] Failed to cast protocol to Solo - polling timer not started");
                        }
                    }
                    
                    // ====== START TEMPLATE HEALTH MONITOR ======
                    // Periodic check for template age timeout (every 30 seconds)
                    constexpr uint16_t TEMPLATE_HEALTH_INTERVAL = 30;
                    self->m_timer_manager.start_template_health_timer(TEMPLATE_HEALTH_INTERVAL, self);
                    self->m_logger->info("[Worker_manager] Template health monitor started (30s interval)");
                    
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
        // For performance: deque doesn't guarantee contiguous storage, but in practice
        // most implementations do provide it. We copy to vector for parsing to ensure
        // compatibility with the parsing function that expects contiguous storage.
        // TODO: Consider refactoring extract_packet_from_buffer_with_result to work
        // with iterators instead of requiring contiguous storage.
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
            
            // Check if this is the known zero-payload BLOCK_DATA pattern (00 00 00 00)
            // caused by the node sending a legacy-format empty response on the stateless lane.
            // This is a node-side bug (should send BLOCK_REJECTED instead), but we handle it
            // gracefully by requesting a new template rather than disconnecting and triggering
            // potentially thousands of reconnect retries.
            bool is_zero_payload_block_data = (m_rx_accumulator.size() >= 4 &&
                m_rx_accumulator[0] == 0x00 && m_rx_accumulator[1] == 0x00 &&
                m_rx_accumulator[2] == 0x00 && m_rx_accumulator[3] == 0x00 &&
                lane == ProtocolLane::STATELESS);

            if (is_zero_payload_block_data)
            {
                m_logger->warn("[RX] Detected zero-payload BLOCK_DATA from node (node-side bug)");
                m_logger->warn("[RX] Treating as template-not-ready — requesting new template instead of disconnecting");
                m_rx_accumulator.clear();
                if (m_miner_protocol && m_connection)
                {
                    retry_template_request();
                }
                return;
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
            
            // Remove consumed bytes from front of deque (O(bytes_consumed) operation)
            m_rx_accumulator.erase(m_rx_accumulator.begin(), 
                                   m_rx_accumulator.begin() + bytes_consumed);
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

// ═══════════════════════════════════════════════════════════════════════
// Worker Control Methods (Degraded Mode Support)
// ═══════════════════════════════════════════════════════════════════════

void Worker_manager::stop_all_workers()
{
    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    m_logger->warn("[Worker_manager] ⚠️  STOPPING ALL WORKERS (DEGRADED MODE)");
    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    
    // Set degraded mode flag
    m_degraded_mode = true;
    
    // Update stats to reflect degraded mode
    auto global_stats = m_stats_collector->get_global_stats();
    global_stats.m_degraded_mode = true;
    m_stats_collector->update_global_stats(global_stats);
    
    // Note: We don't actually need to stop the worker threads here.
    // Workers will naturally stop when they finish their current work
    // because we won't feed them any new templates until recovery.
    // The degraded mode flag is what matters for the UI display.
    
    m_logger->warn("[Worker_manager] Mining stopped - waiting for valid template");
    m_logger->warn("[Worker_manager] Workers will idle until recovery");
}

void Worker_manager::retry_template_request()
{
    m_logger->info("[Worker_manager] Requesting fresh template...");
    
    if (!m_connection) {
        m_logger->error("[Worker_manager] No connection available to request template");
        return;
    }
    
    auto* solo_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
    if (!solo_protocol) {
        m_logger->error("[Worker_manager] Failed to cast protocol to Solo protocol");
        return;
    }

    // Push-cooldown guard (push-driven era): if the node pushed a template within the last
    // 200 s the node is operating normally — skip GET_BLOCK to avoid unnecessary polling.
    // Only if no push has arrived for 200 s (dead-connection indicator) do we fall back.
    if (solo_protocol->was_push_received_recently()) {
        m_logger->debug("[TemplateHealth] Push received recently — no GET_BLOCK needed; node is pushing normally");
        // Node is responsive — reset the consecutive retry counter
        m_template_retry_count = 0;
        return;
    }

    // Retry cap: after MAX_TEMPLATE_RETRIES consecutive failed template requests, force a
    // full TCP reconnect.  This prevents the miner from looping thousands of times at the
    // application level when the node is genuinely unreachable after a block rejection.
    ++m_template_retry_count;
    if (m_template_retry_count > MAX_TEMPLATE_RETRIES)
    {
        m_logger->error("[Worker_manager] Max template retries ({}) exceeded — forcing reconnect",
                        MAX_TEMPLATE_RETRIES);
        m_template_retry_count = 0;
        retry_connect(m_wallet_endpoint);
        return;
    }

    m_logger->info("[Worker_manager] Template retry {}/{}", m_template_retry_count, MAX_TEMPLATE_RETRIES);

    // Get protocol lane from connection
    ProtocolLane lane = m_connection->get_protocol_lane();
    uint16_t remote_port = m_connection->remote_endpoint().port();
    
    m_logger->info("[Worker_manager] Requesting template on {} lane (port {})", 
                  get_lane_name(lane), remote_port);
    
    if (lane == ProtocolLane::LEGACY) {
        // Legacy lane: Request via GET_BLOCK
        m_logger->info("[Worker_manager] → Sending GET_BLOCK request (legacy polling)");
        auto work_payload = solo_protocol->get_work();
        if (work_payload && !work_payload->empty()) {
            m_connection->transmit(work_payload);
        } else {
            // Could be rate limited — not an error
            m_logger->debug("[Worker_manager] GET_BLOCK skipped (rate limited or not ready)");
        }
    } else if (lane == ProtocolLane::STATELESS) {
        // Stateless lane: Re-send STATELESS_MINER_READY
        m_logger->info("[Worker_manager] → Re-sending STATELESS_MINER_READY");
        auto miner_ready_payload = solo_protocol->send_miner_ready();
        if (miner_ready_payload && !miner_ready_payload->empty()) {
            m_connection->transmit(miner_ready_payload);
        }
    } else {
        m_logger->error("[Worker_manager] → Unknown protocol lane - cannot request template");
    }
}

void Worker_manager::check_template_health()
{
    auto* solo_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get());
    if (!solo_protocol) {
        return;
    }
    
    auto* template_interface = solo_protocol->get_template_interface();
    if (!template_interface) {
        return;
    }
    
    if (!template_interface->has_valid_template()) {
        return;
    }
    
    uint64_t template_age = template_interface->get_template_age();
    uint8_t channel = template_interface->get_channel();
    std::string channel_name = (channel == mining::CHANNEL_PRIME) ? "Prime" : "Hash";

    // Channel height-based staleness detection (primary check — HeightTracker is the single
    // source of truth).  Template is stale when channel_height >= channel_target (both non-zero).
    {
        auto ht_snap = solo_protocol->get_height_tracker_snapshot();

        if (ht_snap.is_template_stale()) {
            m_logger->warn("[Worker_manager] ⚠️  {} channel advanced: channel_height {} >= channel_target {} — age {}s",
                channel_name, ht_snap.channel_height, ht_snap.channel_target, template_age);
            m_logger->info("[Worker_manager]    Requesting fresh template (channel height-based staleness)");

            template_interface->discard_template("Channel height-based staleness (channel advanced)");
            stop_all_workers();
            retry_template_request();
            return;
        }
    }

    // Age-based warning: 150s gives a 50s window before the 200s emergency fires.
    // Both channels use the same threshold — in the push-driven protocol the node pushes
    // on every unified tip advance (~18s apart via hash blocks), so 150s without a push
    // is unusual for either channel.
    if (template_age > TEMPLATE_AGE_WARNING_SECONDS && template_age <= TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {
        m_logger->warn("[Worker_manager] ⚠️  {} template age {}s (warning threshold {}s, emergency {}s)",
            channel_name, template_age, TEMPLATE_AGE_WARNING_SECONDS, TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS);
        m_logger->warn("[Worker_manager]    No push received for {}s — connection may be degrading", template_age);
    }

    // Age-based emergency (200s) — dead-connection detector for both channels.
    //
    // In the push-driven era the node pushes a fresh template within ~2s of every unified
    // tip advance.  Even during long Prime blocks, hash blocks keep advancing the unified
    // chain every ~18s, so a push should arrive well within 200s.
    //
    // If template_age > 200s the connection is almost certainly dead (missed push).
    // We then check HeightTracker to distinguish the two sub-cases for logging:
    //   • chain advanced  → push missed while chain moved  (clear emergency)
    //   • chain unchanged → push missed, chain stuck or truly no advance yet
    //     Either way the connection needs recovery — do NOT silently loop forever.
    if (template_age > TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {

        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
        bool chain_advanced = ht_snap.is_template_stale();

        if (chain_advanced) {
            m_logger->error("[Worker_manager] ❌ EMERGENCY ({} channel): template {}s old AND chain advanced!",
                            channel_name, template_age);
            m_logger->error("[Worker_manager]    channel_height {} >= channel_target {} — push notification missed",
                            ht_snap.channel_height, ht_snap.channel_target);
            m_logger->error("[Worker_manager]    Forcing hard recovery (discard + stop + retry)");
        } else {
            // Chain has not advanced in HeightTracker, but 200s without a push means the
            // connection is likely dead.  For Prime this could also be a genuinely long block,
            // but 200s without any hash-block push is still a dead-connection signal.
            m_logger->error("[Worker_manager] ❌ EMERGENCY ({} channel): template {}s old — no push received",
                            channel_name, template_age);
            m_logger->error("[Worker_manager]    channel_height {} / channel_target {} (chain not yet advanced in tracker)",
                            ht_snap.channel_height, ht_snap.channel_target);
            if (channel == mining::CHANNEL_PRIME) {
                m_logger->error("[Worker_manager]    Prime blocks are long, but 200s without ANY push (hash or prime) indicates a dead connection");
            }
            m_logger->error("[Worker_manager]    Forcing hard recovery (discard + stop + retry)");
        }

        template_interface->discard_template("Emergency: age " + std::to_string(template_age) +
                                             "s exceeded " + std::to_string(TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) + "s limit");
        stop_all_workers();
        retry_template_request();
    }
}

}
