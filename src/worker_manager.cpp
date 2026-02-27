#include "worker_manager.hpp"
#include "colin_agent.hpp"
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
#include <thread>

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

    // Recovery window: if no template arrives within this many seconds after a
    // GET_BLOCK recovery is initiated, the health monitor escalates to hard recovery.
    constexpr int64_t RECOVERY_WINDOW_SECONDS = 60;

    // Minimum interval between successive GET_BLOCK sends by the health monitor
    // during an active recovery.  Prevents rapid-fire GETs while still allowing
    // periodic retries if the first attempt is not answered.
    constexpr int64_t RECOVERY_RESEND_INTERVAL_SECONDS = 10;

    // Minimum interval between successive hard escalations (stop workers + hard recovery).
    // Prevents re-escalation before the new epoch's GET_BLOCK has had time to be answered.
    // 60s recovery window + 30s margin = 90s.
    constexpr int64_t MIN_ESCALATION_INTERVAL_SECONDS = 90;

    // Multiplier on RECOVERY_RESEND_INTERVAL_SECONDS for the per-epoch no-re-escalate window.
    // 3 × 10s = 30s gives the new epoch's GET_BLOCK at least 3 resend intervals to be answered
    // before another escalation is permitted.
    constexpr int64_t EPOCH_NO_ESCALATE_MULTIPLIER = 3;

    // Keepalive ACK guard: if an ACK was received within this many seconds of the
    // emergency timeout, the TCP connection is demonstrably alive and we defer the
    // hard recovery to avoid spurious stops during slow-block scenarios.
    // 2× keepalive interval (keepalive every 45s → 90s guard).
    constexpr int64_t KEEPALIVE_ACK_RECENT_THRESHOLD_SECONDS = 90;

    // Colin agent: maximum acceptable seconds between keepalive ACK responses.
    // If no ACK is received for this long, the node may have dropped the session.
    constexpr int64_t KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS = 300;

    // Brief delay (milliseconds) after create_workers() before issuing GET_BLOCK.
    // Allows newly spawned worker threads to enter their receive loop before the node
    // responds to our GET_BLOCK with a fresh template, preventing set_block() from
    // racing thread initialization.  C++ thread startup is typically < 5ms; 50ms is ample.
    constexpr int WORKER_INIT_DELAY_MS = 50;
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
                // Recovery state is cleared AFTER successful template distribution
                // (see workers_fed > 0 branch below). Do not clear here — we must
                // confirm workers actually received the template first.
                // ═══════════════════════════════════════════════════════════════

                // Bug 1 fix: In degraded mode, workers may have been stopped and reset
                // by stop_all_workers().  Restart them now so set_block() below actually
                // starts mining threads; without this the template is silently dropped and
                // workers_fed falsely reads 0 keeping the miner in a doom loop.
                if (m_degraded_mode) {
                    bool has_alive_workers = std::any_of(m_workers.begin(), m_workers.end(),
                        [](const auto& w) { return bool(w); });
                    if (!has_alive_workers) {
                        m_logger->info("[Worker_manager] Degraded mode: restarting workers before feeding recovery template");
                        m_workers.clear();  // prevent duplication if any stale null entries remain
                        create_workers();
                    }
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
                            
                            if (!m_connection && !m_secondary_connection)
                            {
                                m_logger->error("[Worker_manager] No connection on any lane. Can't submit block.");
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
                            
                            // Submit the full block with SIM Link dual-lane fallback
                            submit_solution(full_block_bytes, block_data->nNonce);
                        });
                        if (worker->is_running()) {
                            workers_fed++;
                            m_logger->debug("[Worker_manager] Template sent to worker {}/{}", 
                                           workers_fed, m_workers.size());
                        } else {
                            m_logger->warn("[Worker_manager] Worker {} did not start after set_block() — not counted", i);
                        }
                    } else {
                        m_logger->warn("[Worker_manager] Skipping null worker at index {}", i);
                    }
                }
                
                if (workers_fed > 0) {
                    m_logger->info("[Worker_manager] ✓ Template distributed to {} workers - MINING STARTED", 
                                  workers_fed);
                    // ✅ Clear degraded mode and all recovery state now that a valid template
                    // has been successfully delivered to workers.  This is intentionally done
                    // AFTER distribution so we only exit degraded mode when workers actually
                    // received the template (not merely on template arrival).
                    if (m_recovery_pending) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - m_recovery_started_at).count();
                        m_logger->info("[Worker_manager] ✅ Recovery cleared — template distributed after {}s (epoch {})",
                                      elapsed, m_recovery_epoch);
                    }
                    clear_recovery_state();
                } else {
                    m_logger->error("[Worker_manager] FAILED: No workers received template!");
                    // Immediately request a new template — don't wait 30s for health monitor.
                    // stop_all_workers() sets m_degraded_mode=true so check_template_health()
                    // correctly retries at its 30s rate-cap if this request is also unanswered.
                    stop_all_workers();
                    retry_template_request(true);
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
                    
                    // Recreate workers so they are alive when the recovery template arrives
                    create_workers();
                    
                    // Request fresh template
                    retry_template_request(true);
                }
            );
            m_logger->info("[Worker_manager] Validation failure handler registered");
        } else {
            m_logger->warn("[Worker_manager] Template interface not available - validation failure handler not registered");
        }

        /* ========== REGISTER RECOVERY INITIATED HANDLER ========== */
        /* Called by Solo push handler when a channel-stale GET_BLOCK recovery fires */
        /* so Worker_manager can set recovery_pending and gate check_template_health(). */
        solo_protocol->set_recovery_initiated_handler(
            [this]() {
                mark_recovery_initiated("push_staleness");
            }
        );
        m_logger->info("[Worker_manager] Recovery handler registered");

        /* ========== REGISTER SESSION EXPIRED HANDLER ========== */
        /* Called by Solo keepalive handlers when a session_id mismatch is detected, */
        /* indicating a stale session after node restart. Triggers recovery so the   */
        /* miner reconnects and re-authenticates rather than mining on a dead session. */
        solo_protocol->set_session_expired_handler(
            [this]() {
                m_logger->warn("[Worker_manager] Session EXPIRED — initiating reconnect for re-authentication");
                mark_recovery_initiated("keepalive_session_mismatch");
                // Schedule a reconnect via io_context to avoid calling retry_connect()
                // from within a packet-receive callback (stack depth / reentrancy safety).
                if (m_io_context && m_connection) {
                    auto wallet_endpoint = m_connection->remote_endpoint();
                    ::asio::post(*m_io_context, [self = shared_from_this(), wallet_endpoint]() {
                        self->m_logger->warn("[Worker_manager] Closing stale session connection — reconnecting");
                        self->m_connection.reset();
                        self->retry_connect(wallet_endpoint);
                    });
                }
            }
        );
        m_logger->info("[Worker_manager] Session expired handler registered");
        
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

    if (m_colin_agent)
    {
        m_colin_agent->stop();
        m_colin_agent.reset();
    }

    // close connection
    m_connection.reset();
    m_secondary_connection.reset();

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

    ++m_connection_retry_count;

    // Exponential backoff: start at the configured interval, double each failure, cap at 60s
    constexpr uint32_t MAX_RETRY_DELAY_SECONDS = 60;
    auto const base_delay = static_cast<uint32_t>(m_config.get_connection_retry_interval());
    if (m_current_retry_delay_seconds == 0)
        m_current_retry_delay_seconds = base_delay;
    else
        m_current_retry_delay_seconds = std::min(m_current_retry_delay_seconds * 2, MAX_RETRY_DELAY_SECONDS);

    if (m_connection_retry_count > 10)
        m_logger->error("Connection retry #{} - {} consecutive failures", 
                        m_connection_retry_count, m_connection_retry_count);
    else
        m_logger->info("Connection retry {} seconds (attempt #{})", 
                       m_current_retry_delay_seconds, m_connection_retry_count);

    m_timer_manager.start_connection_retry_timer(m_current_retry_delay_seconds, shared_from_this(), wallet_endpoint);
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

                // SIM Link: mark primary lane dead; if secondary is alive it keeps workers running
                ProtocolLane primary_lane = self->m_connection
                    ? self->m_connection->get_protocol_lane()
                    : ProtocolLane::STATELESS;
                self->m_sim_link.on_lane_failed(primary_lane);

                if (self->m_sim_link.is_legacy_alive() || self->m_sim_link.is_stateless_alive()) {
                    self->m_logger->info("[SIM Link] Primary lane DEAD — secondary lane alive, workers continue mining");
                    // Bypass rate limiter on secondary for immediate template refresh
                    ProtocolLane surviving_lane = self->m_sim_link.is_stateless_alive()
                        ? ProtocolLane::STATELESS : ProtocolLane::LEGACY;
                    if (self->m_sim_link.consume_bypass(surviving_lane)) {
                        auto* sec_solo = dynamic_cast<protocol::Solo*>(self->m_secondary_protocol.get());
                        if (sec_solo && self->m_secondary_connection) {
                            // Node-side 6-second limit (LLL-TAO):
                            // The node enforces roughly 6000ms minimum between GET_BLOCK
                            // requests per session after the first recovery bypass.  We
                            // explicitly bypass miner-side once here, then normal flow
                            // resumes and node-side 6s remains authoritative.
                            sec_solo->bypass_get_block_rate_limit_once();
                            auto work_payload = sec_solo->send_recovery_work_request();
                            if (work_payload && !work_payload->empty()) {
                                self->m_logger->info("[SIM Link] One-shot bypass — GET_BLOCK sent on surviving {} lane",
                                    get_lane_name(surviving_lane));
                                self->m_secondary_connection->transmit(work_payload);
                            }
                        }
                    }
                }

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

                // Reset exponential backoff state on successful TCP connection
                self->m_connection_retry_count = 0;
                self->m_current_retry_delay_seconds = 0;

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

                    auto const print_statistics_interval = self->m_config.get_print_statistics_interval();
                    self->m_timer_manager.start_stats_collector_timer(print_statistics_interval, self->m_workers, self->m_stats_collector);
                    self->m_timer_manager.start_stats_printer_timer(print_statistics_interval, self->m_stats_printers);
                    self->m_timer_manager.start_ping_timer(self->m_config.get_ping_interval(), self->m_connection);

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
                    self->m_logger->info("[SIM Link] Primary lane ping timer started ({}s)", self->m_config.get_ping_interval());

                    // ====== SIM LINK: mark primary lane alive + start health check ======
                    {
                        ProtocolLane primary_lane = self->m_connection->get_protocol_lane();
                        self->m_sim_link.on_lane_recovered(primary_lane);

                        constexpr uint16_t LANE_HEALTH_INTERVAL = 30;  // log every 30s
                        self->m_timer_manager.start_lane_health_check_timer(LANE_HEALTH_INTERVAL, self);
                    }

                    // ====== COLIN: start diagnostic agent on first successful connect ======
                    if (!self->m_colin_agent && self->m_config.get_colin_enabled())
                    {
                        self->m_colin_agent = std::make_shared<ColinAgent>(
                            self->m_io_context,
                            &self->m_sim_link,
                            self->m_stats_collector,
                            self->m_logger,
                            self->m_config.get_colin_report_interval_seconds());
                        // Wire up PING_DIAG source so emit_report() can display node diagnostics
                        if (auto* s = dynamic_cast<protocol::Solo*>(self->m_miner_protocol.get()))
                        {
                            std::weak_ptr<protocol::Protocol> weak_proto = self->m_miner_protocol;
                            self->m_colin_agent->set_ping_source(
                                [weak_proto]() -> ::LLP::ReceivedPingFrame {
                                    auto proto = weak_proto.lock();
                                    if (!proto) return {};
                                    auto* solo_ptr = dynamic_cast<protocol::Solo*>(proto.get());
                                    return solo_ptr ? solo_ptr->last_received_ping() : ::LLP::ReceivedPingFrame{};
                                });
                            // Wire up HeightTracker so emit_report() can display all channel heights
                            // and the fork-score canary in the periodic diagnostic report.
                            self->m_colin_agent->set_height_tracker(&s->get_height_tracker());
                        }
                        self->m_colin_agent->start();
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

bool Worker_manager::connect_secondary(network::Endpoint const& secondary_endpoint)
{
    std::string secondary_addr;
    secondary_endpoint.address(secondary_addr);
    uint16_t secondary_port = secondary_endpoint.port();

    m_logger->info("[SIM Link] Connecting secondary lane to {}:{}", secondary_addr, secondary_port);

    // Build a secondary Solo protocol instance with the same keys/config as primary.
    // Independent auth/session state; same Falcon keys.
    auto secondary_solo = std::make_shared<protocol::Solo>(
        m_config.get_mining_mode() == config::Mining_mode::PRIME ? 1U : 2U,
        m_stats_collector, m_io_context);

    // Copy keys and config from primary
    {
        std::vector<uint8_t> pubkey, privkey;
        keys::from_hex(m_config.get_miner_falcon_pubkey(), pubkey);
        keys::from_hex(m_config.get_miner_falcon_privkey(), privkey);
        secondary_solo->set_miner_keys(pubkey, privkey);
        secondary_solo->set_address(m_config.get_local_ip());
        if (m_config.has_tritium_genesis()) {
            std::vector<uint8_t> genesis;
            if (keys::from_hex(m_config.get_tritium_genesis(), genesis))
                secondary_solo->set_tritium_genesis(genesis);
        }
        secondary_solo->set_keepalive_interval(m_config.get_keepalive_interval());
        secondary_solo->enable_chacha20_wrapping(true);
        secondary_solo->enable_disposable_falcon(true);
        if (m_config.has_reward_address())
            secondary_solo->set_reward_address(m_config.get_reward_address());
    }

    // Register template handler on the secondary protocol.
    // Templates from either lane are distributed to workers (same data, idempotent).
    // Block-found callback uses submit_solution() which selects the live lane.
    secondary_solo->set_block_handler(
        [this](const ::LLP::CBlock& block, std::uint32_t nBits) {
            m_logger->info("[SIM Link] Template received on secondary lane — distributing to {} workers",
                m_workers.size());
            // Distribute to workers. Workers mine on whichever template arrived last
            // (primary and secondary push the same template from the same node).
            for (auto& worker : m_workers) {
                if (!worker) continue;
                worker->set_block(block, nBits, [this](auto /*id*/, auto block_data) {
                    if (!block_data) return;
                    // Prefer secondary protocol's template interface for submission
                    // (it has the template from the secondary lane).
                    protocol::MiningTemplateInterface* tmpl_iface = nullptr;
                    if (auto* sec = dynamic_cast<protocol::Solo*>(m_secondary_protocol.get()))
                        tmpl_iface = sec->get_template_interface();
                    // Fallback to primary if secondary interface not available
                    if (!tmpl_iface) {
                        if (auto* pri = dynamic_cast<protocol::Solo*>(m_miner_protocol.get()))
                            tmpl_iface = pri->get_template_interface();
                    }
                    if (!tmpl_iface) return;
                    auto full_bytes = tmpl_iface->prepare_block_submission(
                        block_data->merkle_root.GetBytes(), block_data->nNonce);
                    if (!full_bytes.empty())
                        submit_solution(full_bytes, block_data->nNonce);
                });
            }
        });

    m_secondary_protocol = secondary_solo;

    std::weak_ptr<Worker_manager> weak_self = shared_from_this();
    auto connection = m_socket->connect(secondary_endpoint,
        [weak_self, secondary_endpoint](auto result, auto receive_buffer)
        {
            auto self = weak_self.lock();
            if (!self) return;

            if (result == network::Result::connection_declined ||
                result == network::Result::connection_aborted ||
                result == network::Result::connection_closed ||
                result == network::Result::connection_error)
            {
                self->m_logger->warn("[SIM Link] Secondary lane connection dropped ({}). Scheduling retry.",
                    network::Result::code_to_string(result));
                self->m_sim_link.on_lane_failed(
                    secondary_endpoint.port() == 9323 ? ProtocolLane::STATELESS : ProtocolLane::LEGACY);
                self->retry_secondary_connect(secondary_endpoint);
            }
            else if (result == network::Result::connection_ok)
            {
                if (!self->m_secondary_connection)
                {
                    // Synchronous connect callback guard — defer
                    ::asio::post(*self->m_io_context, [self, secondary_endpoint]()
                    {
                        self->retry_secondary_connect(secondary_endpoint);
                    });
                    return;
                }

                ProtocolLane sec_lane = self->m_secondary_connection->get_protocol_lane();
                std::string sec_addr;
                self->m_secondary_connection->remote_endpoint().address(sec_addr);
                uint16_t sec_port = self->m_secondary_connection->remote_endpoint().port();

                self->m_logger->info("[SIM Link] Secondary lane connected: {} lane {}:{}",
                    get_lane_name(sec_lane), sec_addr, sec_port);

                self->m_secondary_retry_count = 0;
                self->m_secondary_retry_delay_seconds = 0;

                if (auto sec_solo = std::dynamic_pointer_cast<protocol::Solo>(self->m_secondary_protocol))
                {
                    sec_solo->set_protocol_lane(sec_lane);
                }

                self->m_secondary_connection->transmit(
                    self->m_secondary_protocol->login(
                        [self, secondary_endpoint](bool login_result) {
                            if (!login_result) {
                                self->m_logger->warn("[SIM Link] Secondary lane login failed — retrying");
                                self->retry_secondary_connect(secondary_endpoint);
                                return;
                            }

                            ProtocolLane sec_lane = self->m_secondary_connection->get_protocol_lane();
                            self->m_sim_link.on_lane_recovered(sec_lane);

                            // If a bypass was armed (primary failed before secondary connected),
                            // request work immediately on the secondary lane.
                            if (self->m_sim_link.consume_bypass(sec_lane)) {
                                if (auto sec_solo = std::dynamic_pointer_cast<protocol::Solo>(self->m_secondary_protocol)) {
                                    // Node-side 6-second limit (LLL-TAO):
                                    // First recovery GET_BLOCK may bypass once; afterward
                                    // node resumes enforcing ~6000ms spacing.  This one-shot
                                    // bypass keeps template recovery immediate without creating
                                    // a tight retry loop.
                                    sec_solo->bypass_get_block_rate_limit_once();
                                    auto work_payload = sec_solo->send_recovery_work_request();
                                    if (work_payload && !work_payload->empty()) {
                                        self->m_logger->info("[SIM Link] One-shot bypass — GET_BLOCK sent on secondary lane");
                                        self->m_secondary_connection->transmit(work_payload);
                                    }
                                }
                            }

                            self->m_logger->info("[SIM Link] ✓ Secondary lane authenticated and ready — both lanes ALIVE");
                            self->m_timer_manager.start_secondary_ping_timer(self->m_config.get_ping_interval(), self->m_secondary_connection);
                            self->m_logger->info("[SIM Link] Secondary lane ping timer started ({}s)", self->m_config.get_ping_interval());
                        }));
            }
            else
            {
                if (!self->m_secondary_connection)
                {
                    self->m_logger->error("[SIM Link] No secondary connection.");
                    self->retry_secondary_connect(secondary_endpoint);
                }
                self->process_secondary_data(std::move(receive_buffer));
            }
        });

    if (!connection)
    {
        m_logger->warn("[SIM Link] Failed to initiate secondary connection socket");
        return false;
    }

    m_secondary_connection = std::move(connection);
    return true;
}

void Worker_manager::retry_secondary_connect(network::Endpoint const& secondary_endpoint)
{
    m_secondary_connection = nullptr;
    if (m_secondary_protocol) m_secondary_protocol->reset();

    ++m_secondary_retry_count;

    constexpr uint32_t MAX_SECONDARY_RETRY_DELAY_SECONDS = 60;
    auto const base_delay = static_cast<uint32_t>(m_config.get_connection_retry_interval());
    if (m_secondary_retry_delay_seconds == 0)
        m_secondary_retry_delay_seconds = base_delay;
    else
        m_secondary_retry_delay_seconds = std::min(m_secondary_retry_delay_seconds * 2,
                                                   MAX_SECONDARY_RETRY_DELAY_SECONDS);

    m_logger->info("[SIM Link] Secondary lane retry in {}s (attempt #{})",
        m_secondary_retry_delay_seconds, m_secondary_retry_count);

    m_timer_manager.start_secondary_connection_retry_timer(
        static_cast<uint16_t>(m_secondary_retry_delay_seconds), shared_from_this(), secondary_endpoint);
}

void Worker_manager::submit_solution(const std::vector<uint8_t>& full_block_bytes, uint64_t nNonce)
{
    // SIM Link block submission: try primary lane first, fall back to secondary.
    //
    // The packet format (stateless vs. legacy opcodes) differs per lane, so we
    // must use the protocol instance that matches the connection we transmit on.

    // ── Try primary lane ────────────────────────────────────────────────────
    if (m_connection && m_miner_protocol)
    {
        auto packet = m_miner_protocol->submit_block(full_block_bytes, nNonce);
        if (packet && !packet->empty())
        {
            m_connection->transmit(packet);
            return;
        }
    }

    // ── Fallback to secondary lane ──────────────────────────────────────────
    if (m_secondary_connection && m_secondary_protocol)
    {
        m_logger->warn("[SIM Link] Block submitted via SECONDARY (primary down)");
        auto packet = m_secondary_protocol->submit_block(full_block_bytes, nNonce);
        if (packet && !packet->empty())
        {
            m_secondary_connection->transmit(packet);
            return;
        }
    }

    m_logger->error("[SIM Link] Block submission failed — no live lane available!");
}

void Worker_manager::log_lane_health()
{
    bool primary_alive = static_cast<bool>(m_connection);
    bool secondary_alive = static_cast<bool>(m_secondary_connection);

    m_logger->info("[SIM Link] Lane health — Primary: {} | Secondary: {}",
        primary_alive   ? "ALIVE" : "DEAD",
        secondary_alive ? "ALIVE" : "DEAD");
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
            // Malformed packet - log loudly
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

            // Recovery: check if this looks like a zero-payload BLOCK_DATA from the node
            // (node bug: sends truncated/broken BLOCK_DATA when get_block() fails internally).
            // Pattern: all-zero bytes in accumulator = likely null/empty template response.
            bool is_recoverable = false;
            if (!m_rx_accumulator.empty() && m_rx_accumulator.size() <= 8)
            {
                bool all_zeros = true;
                for (auto b : m_rx_accumulator)
                    if (b != 0) { all_zeros = false; break; }
                if (all_zeros)
                    is_recoverable = true;
            }

            m_rx_accumulator.clear();

            if (is_recoverable)
            {
                m_logger->warn("[RX] All-zero malformed bytes — likely node sent empty/null BLOCK_DATA response");
                m_logger->warn("[RX] Attempting recovery: requesting new template without disconnecting");
                // Request a fresh template via the protocol layer instead of disconnecting
                if (auto* solo_protocol = dynamic_cast<protocol::Solo*>(m_miner_protocol.get()))
                {
                    if (lane == ProtocolLane::STATELESS)
                    {
                        auto ready_payload = solo_protocol->send_miner_ready();
                        if (ready_payload && !ready_payload->empty())
                            m_connection->transmit(ready_payload);
                    }
                    else
                    {
                        auto work_payload = solo_protocol->get_work();
                        if (work_payload && !work_payload->empty())
                            m_connection->transmit(work_payload);
                    }
                }
                break;
            }

            m_logger->error("[RX] DISCONNECTING due to malformed packet");
            m_logger->error("[RX] ========================================");
            
            // Disconnect immediately
            if (m_connection)
            {
                m_connection->close();
            }
            
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

void Worker_manager::process_secondary_data(network::Shared_payload&& receive_buffer)
{
    // Secondary-lane RX path: mirrors primary process_data() but uses the secondary
    // accumulator, secondary connection, and secondary protocol instance.
    if (receive_buffer && !receive_buffer->empty())
    {
        m_secondary_rx_accumulator.insert(m_secondary_rx_accumulator.end(),
                                          receive_buffer->begin(), receive_buffer->end());
    }

    ProtocolLane lane = m_secondary_connection
        ? m_secondary_connection->get_protocol_lane()
        : ProtocolLane::UNKNOWN;

    if (lane == ProtocolLane::UNKNOWN)
    {
        m_logger->error("[SIM Link RX] Secondary lane UNKNOWN — clearing accumulator");
        m_secondary_rx_accumulator.clear();
        return;
    }

    while (!m_secondary_rx_accumulator.empty())
    {
        std::vector<uint8_t> buffer_view(m_secondary_rx_accumulator.begin(),
                                         m_secondary_rx_accumulator.end());
        auto buffer_shared = std::make_shared<network::Payload>(std::move(buffer_view));

        ParseResult parse_result;
        std::size_t bytes_consumed = 0;
        auto packet = extract_packet_from_buffer_with_result(
            buffer_shared, bytes_consumed, 0, lane, parse_result);

        if (parse_result == ParseResult::NEED_MORE_DATA)
        {
            break;
        }
        else if (parse_result == ParseResult::MALFORMED)
        {
            m_logger->error("[SIM Link RX] MALFORMED packet on secondary lane — disconnecting secondary");
            m_secondary_rx_accumulator.clear();
            // Notify SIM link bookkeeper and schedule reconnect
            m_sim_link.on_lane_failed(lane);
            if (m_secondary_connection)
                m_secondary_connection->close();
            return;
        }
        else
        {
            m_secondary_rx_accumulator.erase(m_secondary_rx_accumulator.begin(),
                                              m_secondary_rx_accumulator.begin() + bytes_consumed);
            if (packet.m_header == Packet::PING)
            {
                m_logger->trace("[SIM Link RX] PING on secondary lane");
            }
            else
            {
                m_secondary_protocol->process_messages(std::move(packet), m_secondary_connection);
            }
        }
    }
}



// ═══════════════════════════════════════════════════════════════════════
// Worker Control Methods (Degraded Mode Support)
// ═══════════════════════════════════════════════════════════════════════

void Worker_manager::mark_recovery_initiated(const char* reason)
{
    auto now = std::chrono::steady_clock::now();
    if (m_recovery_pending) {
        // Already in a recovery epoch — do NOT reset the start time or increment the
        // epoch counter.  Multiple sources (push handler, health monitor) may both
        // call mark_recovery_initiated() for the same staleness event; only the first
        // call anchors the 60 s recovery window.  The reason parameter is logged here
        // for observability (operators can see all sources that noticed the staleness)
        // but the epoch is intentionally unchanged to avoid resetting the window clock.
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_recovery_started_at).count();
        m_logger->info("[Worker_manager] Recovery already pending (epoch {}, {}s elapsed, reason: {})",
                       m_recovery_epoch, elapsed, reason ? reason : "unknown");
        return;
    }
    ++m_recovery_epoch;
    m_recovery_pending = true;
    m_recovery_started_at = now;
    m_recovery_last_get_block_sent_at = {};         // cleared so first health-monitor check can resend
    m_recovery_last_get_block_transmitted_at = {};  // no confirmed transmission in new epoch yet
    m_recovery_get_block_transmitted = false;  // no confirmed transmission in new epoch yet
    m_logger->warn("[Worker_manager] ⚑ RECOVERY INITIATED — epoch {} (reason: {})",
                   m_recovery_epoch, reason ? reason : "unknown");
    m_logger->warn("[Worker_manager]   Health monitor will NOT stop workers during {} s recovery window",
                   RECOVERY_WINDOW_SECONDS);
}

void Worker_manager::clear_recovery_state()
{
    if (!m_degraded_mode && !m_recovery_pending)
        return;  // Nothing to clear

    m_logger->info("[Worker_manager] ✅ Recovery complete — clearing degraded mode");
    m_degraded_mode = false;
    m_recovery_pending = false;
    m_recovery_epoch = 0;
    m_recovery_started_at = {};
    m_recovery_last_get_block_sent_at = {};
    m_recovery_last_get_block_transmitted_at = {};
    m_recovery_get_block_transmitted = false;

    auto global_stats = m_stats_collector->get_global_stats();
    global_stats.m_degraded_mode = false;
    m_stats_collector->update_global_stats(global_stats);
    m_last_escalation_at = {};
}

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
    
    // Reset all worker instances so that the next create_workers() call starts fresh
    // without duplicating existing workers.  The shared_ptr reset() destroys the Worker
    // object (and joins its mining thread in the destructor), effectively stopping it.
    for (auto& worker : m_workers) {
        worker.reset();
    }
    m_workers.clear();

    m_logger->warn("[Worker_manager] Mining stopped - waiting for valid template");
    m_logger->warn("[Worker_manager] Workers stopped and cleared — will be restarted on recovery");
    m_logger->warn("[Worker_manager] ⬆  DEGRADED MODE ENTERED — recovery will be attempted via GET_BLOCK + MINER_READY");
}

void Worker_manager::retry_template_request(bool bForce)
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

    // When this is a forced recovery (bForce=true) and not already tracked as such,
    // mark a new recovery epoch so check_template_health() knows recovery is pending.
    if (bForce) {
        mark_recovery_initiated("health_monitor_or_validation");
    }

    // Push-cooldown guard (push-driven era): if the node pushed a template within the last
    // 200 s the node is operating normally — skip GET_BLOCK to avoid unnecessary polling.
    // Only if no push has arrived for 200 s (dead-connection indicator) do we fall back.
    if (solo_protocol->was_push_received_recently()) {
        if (!bForce) {
            // Periodic health-check path: push is coming, no need to poll.
            m_logger->debug("[TemplateHealth] Push received recently — no GET_BLOCK needed; node is pushing normally");
            return;
        }
        // Forced recovery path: template was discarded + workers stopped.
        // A push was received recently but the template never arrived (e.g. node-side
        // 0-payload race).  We MUST request a new template regardless.
        m_logger->warn("[Worker_manager] Recovery forced despite recent push — template was discarded, must re-request");
        m_logger->warn("[Worker_manager]   Reason: real staleness detected after discard_template() + stop_all_workers()");
    }

    // Get protocol lane from connection
    ProtocolLane lane = m_connection->get_protocol_lane();
    uint16_t remote_port = m_connection->remote_endpoint().port();
    
    m_logger->info("[Worker_manager] Requesting template on {} lane (port {})", 
                  get_lane_name(lane), remote_port);
    
    if (lane == ProtocolLane::LEGACY) {
        // Legacy lane: Request via GET_BLOCK
        m_logger->info("[Worker_manager] → Sending GET_BLOCK request (legacy polling)");
        // Use get_work_immediate() on forced recovery to bypass miner-side rate limiter.
        // Node PR #283 one-shot bypass handles the node-side.
        auto work_payload = bForce ? solo_protocol->get_work_immediate() : solo_protocol->get_work();
        if (work_payload && !work_payload->empty()) {
            m_connection->transmit(work_payload);
            m_recovery_last_get_block_sent_at = std::chrono::steady_clock::now();
            m_recovery_last_get_block_transmitted_at = m_recovery_last_get_block_sent_at;
            m_recovery_get_block_transmitted = true;
            m_logger->info("[Worker_manager] → GET_BLOCK sent (recovery epoch {})", m_recovery_epoch);
        } else {
            // Could be rate limited — not an error
            m_logger->warn("[Worker_manager]   GET_BLOCK suppressed (rate-limited or not authenticated) — recovery may be delayed");
        }
    } else if (lane == ProtocolLane::STATELESS) {
        // Stateless lane: Send GET_BLOCK first to actively request a template, then
        // re-send MINER_READY to re-subscribe to future push notifications.
        // Sending only MINER_READY is insufficient: the node may not push again until
        // the next block, leaving the miner permanently in "WAITING FOR VALID TEMPLATE".
        m_logger->info("[Worker_manager] → Sending GET_BLOCK request (stateless 0xD081)");
        // Use get_work_immediate() on forced recovery to bypass the miner-side 1s rate limiter.
        // The node enforces its own 6s minimum between GET_BLOCK responses (production) but
        // provides a one-shot bypass (LLL-TAO PR #283) for the first request after a push,
        // so forced recovery is served immediately without triggering node-side bans.
        auto work_payload = bForce ? solo_protocol->get_work_immediate() : solo_protocol->get_work();
        if (work_payload && !work_payload->empty()) {
            m_connection->transmit(work_payload);
            m_recovery_last_get_block_sent_at = std::chrono::steady_clock::now();
            m_recovery_last_get_block_transmitted_at = m_recovery_last_get_block_sent_at;
            m_recovery_get_block_transmitted = true;
            m_logger->info("[Worker_manager] → GET_BLOCK sent (recovery epoch {})", m_recovery_epoch);
        } else {
            m_logger->warn("[Worker_manager]   GET_BLOCK suppressed (rate-limited or not authenticated) — falling back to MINER_READY only");
        }
        // Also re-subscribe to push notifications so the miner receives future pushes.
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
        // In degraded mode with no valid template — retry recovery to prevent permanent lockout.
        // This handles the case where a previous recovery attempt (GET_BLOCK + MINER_READY) did
        // not produce a template (e.g. node rate-limited the request or connection was briefly lost).
        // Rate is naturally capped by the TEMPLATE_HEALTH_INTERVAL timer (30s), so retries fire
        // at most once per 30s.  The node-side 6-second guard handles any per-request rate control.
        if (m_degraded_mode) {
            m_logger->warn("[Worker_manager] ⚠️  DEGRADED MODE: no valid template — retrying recovery request");
            retry_template_request(true);
        }
        return;
    }
    
    uint64_t template_age = template_interface->get_template_age();
    uint8_t channel = template_interface->get_channel();
    std::string channel_name = (channel == mining::CHANNEL_PRIME) ? "Prime" : "Hash";

    // ── Belt-and-suspenders guard ────────────────────────────────────────────
    // If a valid template exists but m_degraded_mode is still set (e.g. because
    // clear_recovery_state() was somehow bypassed), clear it now so the stats
    // printer stops showing "MINING STOPPED" and the health monitor doesn't
    // keep triggering spurious recoveries on every 30 s tick.
    if (m_degraded_mode) {
        m_logger->warn("[Worker_manager] ⚠️  Valid template exists but m_degraded_mode=true — clearing stale flag");
        // Restart any workers that were stopped by stop_all_workers() so that
        // the re-feed below actually reaches live mining threads.
        bool has_alive_workers = std::any_of(m_workers.begin(), m_workers.end(),
            [](const auto& w) { return bool(w); });
        if (!has_alive_workers) {
            m_logger->info("[Worker_manager] Belt-and-suspenders: restarting workers before re-feeding template");
            create_workers();
        }
        clear_recovery_state();
        // Re-feed the template so any workers that may have missed it get a copy.
        template_interface->feed_current_template();
    }

    // Channel height-based staleness detection (primary check — HeightTracker is the single
    // source of truth).  Template is stale when channel_height >= channel_target (both non-zero).
    {
        auto ht_snap = solo_protocol->get_height_tracker_snapshot();

        if (ht_snap.is_template_stale()) {
            // ── Temporal guard (doom-loop prevention) ────────────────────────────────
            // Only stop workers and discard if the template is older than the last push.
            // If the template was received AFTER the last push, channel_target is already
            // updated for the new chain height — staleness is a false positive from the
            // push updating channel_height before the new template updates channel_target.
            //
            // Use HeightTracker timestamps: if last_template_update >= last_height_update,
            // the template already accounts for the most recent push — do NOT stop workers.
            //
            // STARTUP GUARD: if last_template_update == time_point{} (no template has ever
            // been received), treat the template as older than the push regardless of the
            // comparison result — a zero time_point can spuriously compare >= any push time.
            bool template_never_received = (ht_snap.last_template_update == std::chrono::steady_clock::time_point{});
            bool template_is_newer_than_push = (!template_never_received &&
                                                ht_snap.last_template_update >= ht_snap.last_height_update);
            if (template_is_newer_than_push) {
                m_logger->debug("[Worker_manager] {} is_template_stale() true but template (t={}) is newer than last push (t={}) — suppressing false-positive stop",
                    channel_name,
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_template_update.time_since_epoch()).count(),
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_height_update.time_since_epoch()).count());
                // Do not stop workers — the template is current. Request a refresh opportunistically.
                retry_template_request(false);
                return;
            }
            m_logger->warn("[Worker_manager] ⚠️  {} channel advanced: channel_height {} >= channel_target {} — age {}s",
                channel_name, ht_snap.channel_height, ht_snap.channel_target, template_age);
            m_logger->info("[Worker_manager]    Template (t={}) predates last push (t={}) — true staleness",
                std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_template_update.time_since_epoch()).count(),
                std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_height_update.time_since_epoch()).count());

            // ── Recovery state gate (doom-loop prevention) ───────────────────────────
            // mark_recovery_initiated is idempotent: if the push handler already set
            // m_recovery_pending (via m_recovery_handler callback), this is a no-op.
            // Otherwise it starts a new recovery epoch now.
            mark_recovery_initiated("health_monitor_channel_stale");

            auto now_ts = std::chrono::steady_clock::now();
            auto recovery_elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                now_ts - m_recovery_started_at).count();

            if (recovery_elapsed_s < RECOVERY_WINDOW_SECONDS) {
                // Within recovery window: workers keep mining; only resend GET_BLOCK if
                // RECOVERY_RESEND_INTERVAL has elapsed since the last confirmed transmission.
                // Use m_recovery_last_get_block_transmitted_at (only set when a GET_BLOCK was
                // actually transmitted) so that rate-limited attempts don't suppress retries.
                bool first_send = (m_recovery_last_get_block_transmitted_at == std::chrono::steady_clock::time_point{});
                auto since_last_s = first_send ? recovery_elapsed_s
                    : std::chrono::duration_cast<std::chrono::seconds>(
                          now_ts - m_recovery_last_get_block_transmitted_at).count();

                // Change C: doom-loop stall detection — warn if recovery has been running
                // for > 30 s without a single confirmed GET_BLOCK transmission.
                if (recovery_elapsed_s > 30 && !m_recovery_get_block_transmitted) {
                    m_logger->warn("[Worker_manager] ⚠️ RECOVERY STALL: {}s elapsed, NO GET_BLOCK has been transmitted yet "
                        "(all attempts rate-limited). Forcing immediate bypass...", recovery_elapsed_s);
                    // Use get_work_immediate() which resets the miner-side rate-limiter clock.
                    retry_template_request(true);
                    return;
                }

                if (first_send || since_last_s >= RECOVERY_RESEND_INTERVAL_SECONDS) {
                    m_logger->info("[Worker_manager] ⟳ Recovery resend GET_BLOCK (epoch {}, {}s elapsed, last transmitted: {})",
                        m_recovery_epoch, recovery_elapsed_s, first_send ? "never" : std::to_string(since_last_s) + "s ago");
                    retry_template_request(true);  // Force GET_BLOCK + MINER_READY
                } else {
                    m_logger->info("[Worker_manager] ⧖ Recovery pending (epoch {}, {}s elapsed) — health monitor skip-stop; "
                        "last GET_BLOCK transmitted {}s ago (resend in {}s)",
                        m_recovery_epoch, recovery_elapsed_s, since_last_s,
                        RECOVERY_RESEND_INTERVAL_SECONDS - since_last_s);
                }
                return;
            }

            // Recovery window exceeded — check inter-escalation guards before escalating.

            // Change B: Only escalate if sufficient time has passed since the last escalation.
            // Prevents re-escalation before the new epoch's GET_BLOCK has had time to be answered.
            if (m_last_escalation_at != std::chrono::steady_clock::time_point{}) {
                auto since_last_escalation = std::chrono::duration_cast<std::chrono::seconds>(
                    now_ts - m_last_escalation_at).count();
                if (since_last_escalation < MIN_ESCALATION_INTERVAL_SECONDS) {
                    m_logger->info("[Worker_manager] Escalation suppressed — only {}s since last escalation (min={}s), resending GET_BLOCK instead",
                        since_last_escalation, MIN_ESCALATION_INTERVAL_SECONDS);
                    retry_template_request(true);
                    return;
                }
            }

            // Change A: Do not re-escalate immediately after the previous escalation — give the
            // new GET_BLOCK at least RECOVERY_RESEND_INTERVAL_SECONDS * 3 seconds to be answered.
            if (m_recovery_epoch > 1) {
                auto since_epoch_start = std::chrono::duration_cast<std::chrono::seconds>(
                    now_ts - m_recovery_started_at).count();
                if (since_epoch_start < (RECOVERY_RESEND_INTERVAL_SECONDS * EPOCH_NO_ESCALATE_MULTIPLIER)) {
                    // Still within the no-re-escalate window — only resend GET_BLOCK, do not stop workers again.
                    return;
                }
            }

            // Escalate to hard recovery.
            m_logger->warn("[Worker_manager] ⚡ Recovery timeout: epoch {} exceeded {}s window ({}s elapsed)",
                m_recovery_epoch, RECOVERY_WINDOW_SECONDS, recovery_elapsed_s);
            m_logger->warn("[Worker_manager]    Escalating: stop workers + discard template + GET_BLOCK");
            m_recovery_pending = false;  // Reset so next staleness detection starts a fresh epoch
            template_interface->discard_template("Recovery timeout: " + std::to_string(recovery_elapsed_s) +
                                                 "s > " + std::to_string(RECOVERY_WINDOW_SECONDS) + "s window");
            stop_all_workers();
            // Bug 3 fix: Recreate workers immediately after stopping them so they are alive
            // and ready to receive the incoming template from retry_template_request().
            create_workers();
            // Change C: Brief yield to give worker threads time to enter their receive loop before
            // the node responds to our GET_BLOCK with a fresh template.
            // 50ms is sufficient for thread startup; prevents set_block() from racing thread init.
            std::this_thread::sleep_for(std::chrono::milliseconds(WORKER_INIT_DELAY_MS));
            m_last_escalation_at = std::chrono::steady_clock::now();  // Change B: record escalation time
            retry_template_request(true);
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

        // Gap 3: If a keepalive ACK was received recently (within 2× keepalive interval = 90s),
        // the TCP connection is demonstrably alive — defer the hard recovery to avoid
        // spurious stops during slow-block scenarios (e.g. long Prime blocks).
        bool recent_ack = (ht_snap.last_keepalive_ack_at != std::chrono::steady_clock::time_point{}) &&
            (std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ht_snap.last_keepalive_ack_at).count() < KEEPALIVE_ACK_RECENT_THRESHOLD_SECONDS);
        if (recent_ack && !chain_advanced) {
            auto since_ack_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ht_snap.last_keepalive_ack_at).count();
            m_logger->warn("[Worker_manager] EMERGENCY deferred: keepalive ACK is recent ({}s ago) — "
                           "connection alive, awaiting push for template refresh",
                           since_ack_s);
            retry_template_request(false);
            return;
        }

        if (chain_advanced) {
            // Apply the same temporal guard as the primary staleness check.
            // Even in the emergency path, if the template is newer than the last push,
            // the staleness is a false positive — suppress the hard recovery.
            // STARTUP GUARD: zero time_point compares as epoch; treat as "never received".
            bool template_never_received = (ht_snap.last_template_update == std::chrono::steady_clock::time_point{});
            bool template_is_newer_than_push = (!template_never_received &&
                                                ht_snap.last_template_update >= ht_snap.last_height_update);
            if (template_is_newer_than_push) {
                m_logger->debug("[Worker_manager] EMERGENCY {} is_template_stale() true but template (t={}) is newer than last push (t={}) — suppressing false-positive stop",
                    channel_name,
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_template_update.time_since_epoch()).count(),
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_height_update.time_since_epoch()).count());
                retry_template_request(false);
                return;
            }
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
        // Bug 3 fix: Recreate workers immediately after stopping them so they are alive
        // and ready to receive the incoming template from retry_template_request().
        create_workers();
        retry_template_request(true);
    }
}

}
