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
#include "protocol/protocol_constants.hpp"
#include "protocol/session_status_policy.hpp"
#include <variant>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace nexusminer
{

// Recovery window: if no template arrives within this many seconds after a
// GET_BLOCK recovery is initiated, the health monitor escalates to hard recovery.
// Channel-aware: Prime blocks genuinely take 2-5+ min, so a 60 s window causes
// spurious escalations during normal long Prime blocks. Hash blocks arrive every
// ~18 s so 60 s (≈ 3 blocks) is appropriate for Hash.
namespace {
    // Push-notification liveness threshold: if a push notification
    // (PRIME/HASH_BLOCK_AVAILABLE) was received within this window, the TCP session
    // is demonstrably alive and authenticated.  PUSH is the sole authoritative
    // signal for session liveness — keepalive ACK is diagnostic only.
    constexpr int64_t PUSH_ALIVE_THRESHOLD_SECONDS = protocol::ProtocolConstants::PUSH_LIVENESS_THRESHOLD_SECONDS;

    // Fix A: push-alive guard in retry_connect() uses a much shorter window (30s).
    constexpr int64_t RETRY_CONNECT_PUSH_LIVE_SECONDS = 30;

    // Unified height drift threshold
    constexpr uint32_t UNIFIED_DRIFT_THRESHOLD = 5;
}

Worker_manager::Worker_manager(std::shared_ptr<asio::io_context> io_context, Config& config,
    chrono::Timer_factory::Sptr timer_factory, network::Socket::Sptr socket)
: m_io_context{std::move(io_context)}
, m_config{config}
, m_socket{std::move(socket)}
, m_logger{spdlog::get("logger")}
, m_stats_collector{std::make_shared<stats::Collector>(m_config)}
, m_timer_manager{std::move(timer_factory)}
{
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

        // Create primary NodeSession (handles both stateless and legacy ports automatically via SIM Link)
        m_primary_node_session = std::make_shared<NodeSession>(
            m_io_context,
            m_config,
            m_socket,
            m_stats_collector,
            "PRIMARY",
            &m_sim_link);  // Pass DualConnectionManager for lane health tracking

        // Configure miner keys
        m_primary_node_session->set_miner_keys(pubkey, privkey);

        // Configure Tritium GenesisHash if provided
        if (m_config.has_tritium_genesis()) {
            std::vector<uint8_t> genesis;
            if (keys::from_hex(m_config.get_tritium_genesis(), genesis)) {
                m_primary_node_session->set_tritium_genesis(genesis);
                m_logger->info("[Worker_manager] Tritium GenesisHash configured for reward binding");
            } else {
                m_logger->warn("[Worker_manager] Failed to parse Tritium GenesisHash - invalid hex format");
            }
        }

        // Configure keepalive interval
        m_primary_node_session->set_keepalive_interval(get_effective_keepalive_interval());
        m_logger->info("[Worker_manager] Keepalive interval: {} hours", get_effective_keepalive_interval());

        m_logger->info("[Worker_manager] ChaCha20 encryption: ENABLED (ALWAYS ON - core security)");
        m_logger->info("[Worker_manager] Disposable Falcon signing: ENABLED (ALWAYS ON - core protocol, 0 blockchain overhead)");

        // Configure reward address for stateless mining (MINER_SET_REWARD protocol)
        if (m_config.has_reward_address()) {
            m_primary_node_session->set_reward_address(m_config.get_reward_address());
            m_logger->info("[Worker_manager] Reward address configured: {}", m_config.get_reward_address());
        } else {
            m_logger->debug("[Worker_manager] No reward address configured - using node default");
        }

        m_logger->info("[Worker_manager] Falcon keys loaded from config");
        m_logger->info("[Worker_manager] Auth address: {}", m_config.get_local_ip());

        /* ========== REGISTER TEMPLATE DISTRIBUTION HANDLER ========== */
        /* Connects protocol layer (validated templates) to worker layer (mining threads) */
        /* This lambda is called by the template feed handler (PR #62) when templates arrive */
        m_primary_node_session->set_template_handler(
            [this](const ::LLP::CBlock& block, uint32_t nBits) {
                std::size_t worker_count = 0;
                {
                    std::lock_guard<std::mutex> lock(m_worker_mutex);
                    worker_count = m_workers.size();
                }
                m_logger->info("[Worker_manager] ═══════════════════════════════════════");
                m_logger->info("[Worker_manager] DISTRIBUTING TEMPLATE TO {} WORKERS", worker_count);
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

                // Note: Template feed debounce is now handled in MiningTemplateInterface
                // (unified dedup gate). This handler is only called after the template
                // passes the debounce check, so no additional checking is needed here.

                // Update mined-block cache confirmations based on new chain height.
                m_mined_block_cache.update_confirmations(block.nHeight);

                // In STOPPED state, workers may have been destroyed.
                // Restart them so set_block() below actually starts mining threads.
                size_t workers_fed = 0;
                {
                    std::lock_guard<std::mutex> lock(m_worker_mutex);
                    if (m_mining_state == MiningState::STOPPED && m_workers.empty()) {
                        m_logger->info("[Worker_manager] STOPPED state: restarting workers before feeding recovery template");
                        create_workers_locked();
                    }

                    /* Safety check - workers should be created by now */
                    if (m_workers.empty()) {
                        m_logger->error("[Worker_manager] CRITICAL: No workers available for mining!");
                        m_logger->error("[Worker_manager]   Workers may not be initialized yet");
                        m_logger->error("[Worker_manager]   Template will be lost - mining cannot start");
                        return;
                    }

                    /* Create shared WorkPackage once for all workers */
                    auto work_package = std::make_shared<WorkPackage>(block, nBits);
                    m_logger->debug("[Worker_manager] Created shared WorkPackage (block height: {}, nBits: 0x{:08x})",
                                    block.nHeight, nBits);

#ifdef PRIME_ENABLED
                    /* Optimization: For prime channel, precompute base hash (Skein+Keccak) once
                     * instead of having each worker compute it independently */
                    if (block.nChannel == 1) {  // Prime channel
                        Block_data temp_block{block};
                        work_package->set_prime_base_hash(temp_block.GetPrimeBaseHash());

                        m_logger->debug("[Worker_manager] Precomputed prime base hash for all workers");
                    }
#endif

                    /* Distribute template to all worker threads */
                    for (size_t i = 0; i < m_workers.size(); ++i) {
                        auto& worker = m_workers[i];
                        if (worker) {
                            worker->set_block(work_package, [this](auto id, auto block_data)
                            {
                            m_logger->info("════════════════════════════════════════════════════════");
                            m_logger->info("💎 BLOCK FOUND CALLBACK INVOKED!");
                            m_logger->info("   Worker ID:  {}", id);
                            m_logger->info("   Height:     {}", block_data->nHeight);
                            m_logger->info("   Nonce:      0x{:016x}", block_data->nNonce);
                            m_logger->info("════════════════════════════════════════════════════════");

                            if (!m_primary_node_session || !m_primary_node_session->is_authenticated())
                            {
                                m_logger->error("[Worker_manager] No authenticated session. Can't submit block.");
                                return;
                            }

                            // Get the mining template interface to prepare full block submission
                            auto solo_protocol = m_primary_node_session->get_primary_protocol();
                            if (!solo_protocol)
                            {
                                m_logger->error("[Worker_manager] Failed to get protocol from NodeSession");
                                return;
                            }

                            auto* template_interface = solo_protocol->get_template_interface();
                            if (!template_interface)
                            {
                                m_logger->error("[Worker_manager] Template interface not available");
                                return;
                            }

                            // ✅ NEW: Final staleness check before submission (Template Staleness Prevention)
                            // Use HeightTracker snapshot as single source of truth for both channel and age checks
                            auto ht_snap = solo_protocol->get_height_tracker_snapshot();

                            // Check 1 — Channel Height (PRIMARY: has another miner found this block?)
                            bool channel_stale = ht_snap.is_template_stale();

                            // Check 2 — Age (SECONDARY: safety net for missed push notifications)
                            // 600s matches the push-driven era MAX_TEMPLATE_AGE
                            bool age_stale = ht_snap.is_template_age_stale();
                            uint64_t template_age = ht_snap.get_template_age_seconds();

                            if (channel_stale || age_stale)
                            {
                                if (channel_stale) {
                                    m_logger->error("[Worker_manager] ❌ Solution found but channel height ADVANCED!");
                                    m_logger->error("[Worker_manager]    channel_height {} >= channel_target {}",
                                                   ht_snap.channel_height, ht_snap.channel_target);
                                    m_logger->error("[Worker_manager]    Another miner found this block first - discarding");
                                } else {
                                    m_logger->error("[Worker_manager] ❌ Solution found but template too old: {}s (max: 600s)",
                                                   template_age);
                                    m_logger->error("[Worker_manager]    Push notifications likely missed - discarding");
                                }
                                template_interface->discard_template(channel_stale ? "Channel height advanced before submission"
                                                                                   : "Age exceeded 600s before submission");
                                transition_to(MiningState::STOPPED, channel_stale ? "submit_side_channel_stale"
                                                                                  : "submit_side_age_stale");
                                send_get_block(true);
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
                            if (!block_data->vOffsets.empty())
                                m_logger->info("[Worker_manager]   vOffsets: {} bytes (Prime channel)",
                                               block_data->vOffsets.size());

                            auto full_block_bytes = template_interface->prepare_block_submission(
                                block_data->merkle_root.GetBytes(),
                                block_data->nNonce,
                                block_data->vOffsets);

                            if (full_block_bytes.empty())
                            {
                                m_logger->error("[Worker_manager] Failed to prepare block submission - empty payload");
                                m_logger->error("[Worker_manager]   This indicates template or block data is invalid");
                                return;
                            }

                            m_logger->info("[Worker_manager] Full block serialized: {} bytes", full_block_bytes.size());
                            m_logger->info("[Worker_manager] Submitting block to protocol layer...");

                            // Submit the full block via NodeSession
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
                }
                
                if (workers_fed > 0) {
                    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
                    m_logger->info("[Worker_manager] ✓ Template distributed to {} workers - MINING STARTED", 
                                  workers_fed);
                    if (solo_protocol) {
                        solo_protocol->mark_authoritative_recovery_healthy("fresh_template_distributed_to_workers");
                    }
                    // Transition to MINING now that workers have a valid template.
                    if (m_mining_state != MiningState::MINING) {
                        transition_to(MiningState::MINING, "fresh_template_distributed");
                    }

                    // Re-subscribe to push notifications if they have been silent too long.
                    if (solo_protocol) {
                        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
                        bool push_ever_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});

                        if (!push_ever_received) {
                            m_logger->info("[Worker_manager] No push notification ever received — skipping resubscribe");
                        } else {
                            auto now_resub = std::chrono::steady_clock::now();
                            int64_t since_push_s = std::chrono::duration_cast<std::chrono::seconds>(
                                now_resub - ht_snap.last_push_notification_at).count();

                            constexpr int64_t POST_RECOVERY_HOLDOFF_SECONDS = 60;
                            int64_t since_state_entered_s = std::chrono::duration_cast<std::chrono::seconds>(
                                now_resub - m_state_entered_at).count();

                            constexpr int64_t PUSH_RESUBSCRIBE_THRESHOLD_SECONDS = 400;

                            if (since_state_entered_s < POST_RECOVERY_HOLDOFF_SECONDS) {
                                m_logger->info("[Worker_manager] State entered {}s ago — within hold-off, skipping resubscribe",
                                               since_state_entered_s);
                            } else if (since_push_s > PUSH_RESUBSCRIBE_THRESHOLD_SECONDS) {
                                m_logger->warn("[Worker_manager] Push notifications silent for {}s after recovery — re-subscribing",
                                               since_push_s);
                                solo_protocol->resubscribe_push_notifications();
                            }
                        }
                    }
                } else {
                    m_logger->error("[Worker_manager] FAILED: No workers received template!");
                    transition_to(MiningState::STOPPED, "no_workers_fed");
                    send_get_block(true);
                }
            }
        );
        
        m_logger->info("[Worker_manager] Template distribution handler registered");

        /* ========== REGISTER VALIDATION FAILURE HANDLER ========== */
        /* This handler is called when template validation fails */
        /* It stops workers and requests a fresh template */
        auto solo_protocol = m_primary_node_session->get_primary_protocol();
        if (solo_protocol) {
            auto* template_interface = solo_protocol->get_template_interface();
            if (template_interface) {
            template_interface->set_validation_failure_handler(
                [this](const protocol::MiningTemplateInterface::ValidationResult& result) {
                    m_logger->error("[Worker_manager] ════════════════════════════════════════");
                    m_logger->error("[Worker_manager] ⚠️  TEMPLATE VALIDATION FAILED");
                    m_logger->error("[Worker_manager]    Reason: {}", result.error_message);
                    m_logger->error("[Worker_manager] ════════════════════════════════════════");
                    
                    transition_to(MiningState::STOPPED, "validation_failure");
                    send_get_block(true);
                }
            );
            m_logger->info("[Worker_manager] Validation failure handler registered");
        } else {
            m_logger->warn("[Worker_manager] Template interface not available - validation failure handler not registered");
        }
    } else {
        m_logger->warn("[Worker_manager] Primary protocol not available - validation failure handler not registered");
    }

        /* ========== REGISTER RECOVERY INITIATED HANDLER ========== */
        /* Multi-block/channel-stale recovery: transition to STOPPED. */
        m_primary_node_session->set_recovery_initiated_handler(
            [this]() {
                m_logger->warn("[Worker_manager] ⚡ Recovery: push detected channel-stale — transitioning to STOPPED");
                transition_to(MiningState::STOPPED, "push_staleness");
                send_get_block(true);
            }
        );
        m_logger->info("[Worker_manager] Recovery handler registered");

        /* ========== REGISTER SESSION EXPIRED HANDLER ========== */
        /* Called by Solo when SESSION_EXPIRED opcode is received from the node.     */
        /* The TCP connection is still alive — we must re-authenticate in-band       */
        /* using login() on the existing connection, NOT reset() which tears down    */
        /* the TCP connection. Uses existing session auth backoff infrastructure.    */
        m_primary_node_session->set_session_expired_handler(
            [this]() {
                if (m_reconnect_in_progress) {
                    m_logger->warn("[Worker_manager] Session EXPIRED ignored: reconnect already in progress");
                    return;
                }

                m_logger->warn("[Worker_manager] Session EXPIRED — initiating in-band re-authentication");
                transition_to(MiningState::STOPPED, "session_expired");

                // Use the current session auth fail count to calculate backoff delay.
                // NOTE: We do NOT increment m_session_auth_fail_count here.
                // The session_authenticated_handler will increment it if the subsequent
                // authentication fails (session_id == 0), avoiding double-counting.

                // If we've already exceeded max retries, halt re-authentication
                if (m_session_auth_fail_count >= protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES)
                {
                    m_logger->error("[Session] Max authentication retries ({}) already reached after SESSION_EXPIRED",
                        protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES);
                    m_logger->error("[Session] Node appears to be persistently expiring or rejecting sessions");
                    m_logger->error("[Session] Check node logs and session keepalive configuration");
                    return;
                }

                // Calculate backoff delay based on current failure count
                // (will be 0 delay on first SESSION_EXPIRED if no prior auth failures)
                auto delay_ms = m_session_auth_fail_count > 0
                    ? m_session_auth_backoff.calculate_delay_ms(m_session_auth_fail_count)
                    : 0;
                auto delay_seconds = static_cast<uint16_t>(delay_ms / 1000);

                if (delay_seconds > 0) {
                    m_logger->warn("[Session] Scheduling in-band re-authentication in {}s (based on {} prior failures, exponential backoff)",
                        delay_seconds, m_session_auth_fail_count);
                } else {
                    m_logger->info("[Session] Scheduling immediate in-band re-authentication (no prior auth failures)");
                }

                // Schedule re-auth via io_context to avoid calling login()
                // from within a packet-receive callback (stack depth / reentrancy safety).
                if (m_io_context && m_primary_node_session) {
                    auto timer = std::make_shared<asio::steady_timer>(*m_io_context, std::chrono::seconds(delay_seconds));
                    timer->async_wait([self = shared_from_this(), timer](const asio::error_code& ec) {
                        if (ec) {
                            if (ec != asio::error::operation_aborted) {
                                self->m_logger->error("[Session] Re-auth timer error: {}", ec.message());
                            }
                            return;
                        }

                        if (!self->m_primary_node_session) {
                            self->m_logger->warn("[Session] Node session destroyed before re-auth could execute");
                            return;
                        }

                        self->m_logger->info("[Session] Executing in-band re-authentication (calling login() on existing connection)");

                        // Call login() on the existing connection via the primary protocol
                        auto primary_protocol = self->m_primary_node_session->get_primary_protocol();
                        if (!primary_protocol) {
                            self->m_logger->error("[Session] Primary protocol not available for re-authentication");
                            return;
                        }

                        // The login callback result is not critical here - the session_authenticated_handler
                        // will be invoked after MINER_AUTH_RESULT is received and will handle
                        // success/failure and further retry logic if needed
                        auto auth_payload = primary_protocol->login([self](bool login_result) {
                            if (!login_result) {
                                self->m_logger->error("[Session] In-band re-authentication login() call failed");
                                // The session_authenticated_handler will handle retry logic
                            } else {
                                self->m_logger->info("[Session] In-band re-authentication login() call succeeded, awaiting MINER_AUTH_RESULT");
                            }
                        });

                        if (auth_payload && !auth_payload->empty()) {
                            self->m_primary_node_session->transmit(auth_payload);
                        } else {
                            self->m_logger->error("[Session] Failed to generate re-authentication payload");
                        }
                    });
                }
            }
        );
        m_logger->info("[Worker_manager] Session expired handler registered");

        /* ========== REGISTER SESSION AUTHENTICATED HANDLER (BUG FIX #2) ========== */
        /* Called by Solo after MINER_AUTH_RESULT is fully processed and session_id is set. */
        /* This is the correct place to check session_id=0 (not in the login callback which */
        /* fires before MINER_AUTH_RESULT arrives). Triggers retry with exponential backoff. */
        m_primary_node_session->set_session_authenticated_handler(
            [this](uint32_t session_id) {
                // CRITICAL: If session_id = 0, the node rejected authentication or didn't provide a session.
                // Mining cannot proceed without a valid session_id (work submissions will be silently rejected).
                // Use exponential backoff with max retry limit to prevent infinite tight retry loops.
                if (session_id == 0)
                {
                    ++m_session_auth_fail_count;
                    m_logger->error("[Session] CRITICAL: Node returned session_id=0x00000000 after authentication (attempt #{}/{})",
                        m_session_auth_fail_count, protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES);
                    m_logger->error("[Session] This indicates the node rejected the session or is misconfigured");
                    m_logger->error("[Session] Work submissions cannot proceed without a valid session ID");

                    // Hard limit: if we've exceeded max retries, halt reconnection to prevent infinite loop
                    if (m_session_auth_fail_count > protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES)
                    {
                        m_logger->error("[Session] Max authentication retries ({}) exceeded — halting reconnection",
                            protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES);
                        m_logger->error("[Session] Node appears to be persistently rejecting authentication");
                        m_logger->error("[Session] Check node logs, miner_auth handler, and mining account configuration");
                        return;
                    }

                    // Exponential backoff: 1s, 2s, 4s, 8s, ..., capped at 60s
                    auto delay_ms = m_session_auth_backoff.calculate_delay_ms(m_session_auth_fail_count);
                    auto delay_seconds = static_cast<uint16_t>(delay_ms / 1000);

                    m_logger->warn("[Session] Scheduling reconnection retry in {}s (exponential backoff)",
                        delay_seconds);

                    // Get the endpoint from the current connection
                    network::Endpoint wallet_endpoint = m_primary_endpoint;

                    // Schedule delayed retry using the existing connection retry timer infrastructure
                    m_timer_manager.start_connection_retry_timer(delay_seconds, shared_from_this(), wallet_endpoint);
                    return;
                }

                // Successful authentication: reset session auth failure counter
                m_session_auth_fail_count = 0;
                // Clear reconnect guard now that connection is fully authenticated
                m_reconnect_in_progress = false;
                m_reconnect_started_at = {};

                if (m_using_failover)
                {
                    m_logger->info("[Failover] Fresh session established on failover node: session_id=0x{:08x}",
                        session_id);
                }
                else
                {
                    m_logger->info("[Primary] Fresh session established on primary node: session_id=0x{:08x}",
                        session_id);
                }

                // Bug 4 fix: If we are in degraded/recovery mode (e.g. after in-band
                // re-authentication following SESSION_EXPIRED), explicitly send GET_BLOCK
                // to acquire a fresh template and exit degraded mode.  Without this call
                // the miner has no way to escape degraded mode because workers can't be
                // fed without a template and a template won't arrive without GET_BLOCK.
                if (m_mining_state == MiningState::STOPPED) {
                    m_logger->info("[Worker_manager] Re-authentication SUCCESS — "
                                   "requesting fresh template to exit STOPPED state");
                    send_get_block(true);
                }
            }
        );
        m_logger->info("[Worker_manager] Session authenticated handler registered");

        /* ========== REGISTER SESSION START HANDLER ========== */
        /* Called by Solo when SESSION_START is received and keepalive interval has been  */
        /* auto-adjusted from the node-advertised timeout. Updates m_node_keepalive_interval_hours */
        /* so future secondary/failover connections use the correct node-derived interval. */
        m_primary_node_session->set_session_start_handler(
            [weak_self = weak_from_this()](uint16_t keepalive_hours) {
                auto self = weak_self.lock();
                if (!self) return;
                self->m_node_keepalive_interval_hours.store(keepalive_hours);
                self->m_logger->info("[Worker_manager] Node-advertised keepalive interval: {} hours (will seed future connections)",
                    keepalive_hours);
            }
        );
        m_logger->info("[Worker_manager] Session start handler registered");

        /* ========== REGISTER BLOCK ACCEPTED HANDLER ========== */
        /* Records accepted blocks into the three-tier mined-block cache. */
        m_primary_node_session->set_block_accepted_handler(
            [weak_self = weak_from_this()](uint32_t height, uint1024_t hash_prev_block, uint32_t channel, uint64_t nonce) {
                auto self = weak_self.lock();
                if (!self) return;
                self->m_mined_block_cache.record_accepted_block(height, hash_prev_block, channel, nonce);
                self->m_logger->info("[Worker_manager] ⛏ Block recorded in mined-block cache — height={} ch={} total={}",
                    height, channel == 1 ? "Prime" : "Hash", self->m_mined_block_cache.total_blocks());
                self->log_mined_block_cache();
            }
        );
        m_logger->info("[Worker_manager] Block accepted handler registered");

        // Node shutdown handler: stop workers and log the reason when the node
        // sends NODE_SHUTDOWN (0xD0FF).  The Solo protocol already applies its
        // own reconnect backoff (NODE_SHUTDOWN_BACKOFF_S); we just need to park
        // the workers so they don't churn on stale work.
        m_primary_node_session->set_node_shutdown_handler(
            [self = weak_from_this()](uint8_t reason) {
                auto mgr = self.lock();
                if (!mgr) return;

                mgr->m_logger->warn("[Worker_manager] NODE_SHUTDOWN received (reason=0x{:02X}) — stopping workers",
                    reason);
                mgr->stop_all_workers();
            }
        );
        m_logger->info("[Worker_manager] Node shutdown handler registered");

        m_logger->info("[Worker_manager] NodeSession configured and handlers registered");

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

void Worker_manager::create_workers_locked()
{
    // Guard: if workers are already alive, do not spawn duplicates.
    // While m_worker_mutex is held, !m_workers.empty() means the prior generation
    // still exists. stop_all_workers() resets the shared_ptrs under the same mutex,
    // and each worker destructor blocks until its mining threads have fully joined.
    if (!m_workers.empty()) {
        m_logger->warn("[Worker_manager] create_workers_locked() called with {} workers already alive — skipping duplicate spawn",
                       m_workers.size());
        return;
    }

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

void Worker_manager::create_workers()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);
    create_workers_locked();
}

void Worker_manager::stop()
{
    m_timer_manager.stop();

    if (m_colin_agent)
    {
        m_colin_agent->stop();
        m_colin_agent.reset();
    }

    // Stop NodeSessions
    if (m_primary_node_session) {
        m_primary_node_session->stop();
    }
    if (m_failover_node_session) {
        m_failover_node_session->stop();
    }

    // destroy workers
    std::lock_guard<std::mutex> lock(m_worker_mutex);
    for(auto& worker : m_workers)
    {
        worker.reset();
    }
    m_workers.clear();
}

uint16_t Worker_manager::get_effective_keepalive_interval() const
{
    uint16_t node_interval = m_node_keepalive_interval_hours.load();
    return (node_interval > 0)
        ? node_interval
        : m_config.get_keepalive_interval();
}

void Worker_manager::retry_connect(network::Endpoint const& wallet_endpoint)
{
    // Safety guard: if push notifications have been received recently, the TCP
    // connection is demonstrably alive from the node's perspective. Tearing it
    // down here would destroy a valid node session. Use in-band re-auth instead.
    if (m_primary_node_session) {
        auto push_protocol = m_primary_node_session->get_primary_protocol();
        if (push_protocol) {
            auto ht_snap = push_protocol->get_height_tracker_snapshot();
            bool push_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});
            if (push_received) {
                auto now = std::chrono::steady_clock::now();
                auto since_push_s = std::chrono::duration_cast<std::chrono::seconds>(
                    now - ht_snap.last_push_notification_at).count();
                if (since_push_s < RETRY_CONNECT_PUSH_LIVE_SECONDS) {
                    // Conditional auth guard: suppress duplicate login() only if auth is recent.
                    // If auth has been in-flight longer than 10s it is likely stuck from a dead
                    // TCP mid-handshake — reset and retry rather than silently blocking.
                    double in_flight_s = push_protocol->auth_in_flight_seconds();
                    constexpr double AUTH_STALE_THRESHOLD_S = 10.0;

                    if (in_flight_s > 0.0 && in_flight_s <= AUTH_STALE_THRESHOLD_S) {
                        m_logger->info("[Worker_manager] Auth in-flight and recent ({:.1f}s < {}s) — "
                                       "skipping duplicate login()", in_flight_s, AUTH_STALE_THRESHOLD_S);
                        return;
                    }
                    if (in_flight_s > AUTH_STALE_THRESHOLD_S) {
                        m_logger->warn("[Worker_manager] Auth in-flight but stale ({:.1f}s > {}s) — "
                                       "resetting auth state before retry", in_flight_s, AUTH_STALE_THRESHOLD_S);
                    }
                    // Reset auth state so login() starts from a clean NOT_AUTHENTICATED state.
                    // This clears any stale WAITING_FOR_CHALLENGE / WAITING_FOR_RESULT left
                    // over from a previous attempt on a now-dead TCP connection.
                    push_protocol->reset_auth_state();
                    m_logger->warn("[Worker_manager] retry_connect() suppressed — push received {}s ago "
                                  "(TCP alive). Triggering in-band re-auth instead.", since_push_s);
                    // Attempt in-band re-authentication on the existing TCP connection
                    auto auth_payload = push_protocol->login([weak_self = weak_from_this()](bool login_result) {
                        auto self = weak_self.lock();
                        if (!self) return;
                        if (!login_result) {
                            self->m_logger->error("[Worker_manager] In-band re-auth (retry_connect guard) login() failed");
                        } else {
                            self->m_logger->info("[Worker_manager] In-band re-auth (retry_connect guard) login() sent, "
                                                 "awaiting MINER_AUTH_RESULT");
                        }
                    });
                    if (auth_payload && !auth_payload->empty()) {
                        m_primary_node_session->transmit(auth_payload);
                    } else {
                        m_logger->error("[Worker_manager] retry_connect guard: failed to generate re-auth payload");
                    }
                    return;
                } else {
                    m_logger->warn("[Worker_manager] retry_connect() push guard expired "
                                   "(push {}s ago > {}s threshold) — proceeding with TCP reconnect",
                                   since_push_s, RETRY_CONNECT_PUSH_LIVE_SECONDS);
                }
            }
        }
    }

    // Set reconnect guard to prevent stale RX callbacks from processing during reconnect
    m_reconnect_in_progress = true;
    m_reconnect_started_at = std::chrono::steady_clock::now();

    // Reset NodeSession for reconnection
    if (m_primary_node_session) {
        m_primary_node_session->reset();
    }

    stats::Global global_stats{};
    global_stats.m_connection_retries = 1;
    m_stats_collector->update_global_stats(global_stats);

    ++m_connection_retry_count;

    // Exponential backoff: start at the configured interval, double each failure, cap at 60s
    auto const base_delay = static_cast<uint32_t>(m_config.get_connection_retry_interval());
    if (m_connection_backoff.base == 0) {
        m_connection_backoff.base = base_delay;  // Set base delay from config on first use
    }
    auto current_delay = m_connection_backoff.next_delay();

    // ── Failover switchover logic ─────────────────────────────────────────────
    network::Endpoint effective_endpoint = wallet_endpoint;
    bool failover_switched = false;  // Track if we're switching nodes

    if (m_config.has_failover())
    {
        if (!m_using_failover)
        {
            ++m_primary_fail_count;
            if (m_primary_fail_count >= m_config.get_failover_max_retries())
            {
                m_using_failover = true;
                m_primary_fail_count = 0;
                m_connection_backoff.reset();  // reset backoff for failover attempt
                m_failover_activated_at = std::chrono::steady_clock::now();
                m_logger->warn("[Failover] Primary {} failed {} times — switching to failover {}",
                    m_primary_endpoint.to_string(),
                    m_config.get_failover_max_retries(),
                    m_failover_endpoint.to_string());
                effective_endpoint = m_failover_endpoint;
                failover_switched = true;
            }
        }
        else
        {
            ++m_primary_fail_count;
            if (m_primary_fail_count >= m_config.get_failover_max_retries())
            {
                m_using_failover = false;
                m_primary_fail_count = 0;
                m_connection_backoff.reset();
                m_logger->info("[Failover] Retrying primary {} after failover failures",
                    m_primary_endpoint.to_string());
                effective_endpoint = m_primary_endpoint;
                failover_switched = true;
            }
            else
            {
                effective_endpoint = m_failover_endpoint;
            }
        }

        // Clear cached keepalive interval for failover switch
        if (failover_switched)
        {
            m_logger->info("[Failover] Resetting NodeSession for fresh authentication on {}",
                effective_endpoint.to_string());
            m_node_keepalive_interval_hours.store(0);
            m_logger->info("[Failover] Cleared node-advertised keepalive interval (will re-learn from failover SESSION_START)");
        }
    }

    if (m_connection_retry_count > protocol::ProtocolConstants::CONNECTION_RETRY_ERROR_THRESHOLD)
        m_logger->error("Connection retry #{} - {} consecutive failures",
                        m_connection_retry_count, m_connection_retry_count);
    else
        m_logger->info("Connection retry {} seconds (attempt #{})",
                       current_delay, m_connection_retry_count);

    m_timer_manager.start_connection_retry_timer(current_delay, shared_from_this(), effective_endpoint);
}

Worker_manager::FailoverStatus Worker_manager::get_failover_status() const
{
    FailoverStatus fs;
    fs.has_failover_configured = m_config.has_failover();
    fs.using_failover          = m_using_failover;
    fs.primary_fail_count      = m_primary_fail_count;
    fs.failover_max_retries    = m_config.get_failover_max_retries();
    fs.primary_endpoint_str    = m_primary_endpoint.is_valid()  ? m_primary_endpoint.to_string()  : "";
    fs.failover_endpoint_str   = m_failover_endpoint.is_valid() ? m_failover_endpoint.to_string() : "";
    fs.failover_activated_at   = m_failover_activated_at;
    return fs;
}

const char* Worker_manager::state_name(MiningState s)
{
    switch (s) {
        case MiningState::MINING:     return "MINING";
        case MiningState::REFRESHING: return "REFRESHING";
        case MiningState::STOPPED:    return "STOPPED";
    }
    return "UNKNOWN";
}

int64_t Worker_manager::seconds_in_state() const
{
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_state_entered_at).count();
}

int64_t Worker_manager::seconds_since_last_get_block() const
{
    if (m_last_get_block_at == std::chrono::steady_clock::time_point{})
        return INT64_MAX;
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_last_get_block_at).count();
}

void Worker_manager::send_get_block(bool force)
{
    retry_template_request(force);
}

void Worker_manager::create_and_feed_workers()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);
    if (m_workers.empty()) {
        m_logger->info("[Worker_manager] Creating workers for template feed");
        create_workers_locked();
    }
    if (m_workers.empty()) {
        m_logger->error("[Worker_manager] create_and_feed_workers: no workers created!");
        return;
    }

    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (!solo_protocol) return;
    auto* tmpl_iface = solo_protocol->get_template_interface();
    if (tmpl_iface) {
        tmpl_iface->feed_current_template();
    }
}

void Worker_manager::transition_to(MiningState new_state, const char* reason)
{
    if (new_state == m_mining_state) return;

    m_logger->info("[Worker_manager] ⚡ State: {} → {} ({})",
                   state_name(m_mining_state), state_name(new_state), reason);

    auto now = std::chrono::steady_clock::now();

    // Track time spent in STOPPED for statistics
    if (m_mining_state == MiningState::STOPPED && new_state != MiningState::STOPPED) {
        if (m_state_entered_at != std::chrono::steady_clock::time_point{}) {
            auto elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now - m_state_entered_at).count());
            m_time_in_degraded_ms += elapsed_ms;
        }
        ++m_degraded_exit_total;

        // Update stats to reflect end of degraded mode
        auto global_stats = m_stats_collector->get_global_stats();
        global_stats.m_degraded_mode = false;
        m_stats_collector->update_global_stats(global_stats);
        m_stats_collector->reset_start_time();
    }

    if (new_state == MiningState::STOPPED && m_mining_state != MiningState::STOPPED) {
        stop_all_workers();  // only stop workers on transition TO stopped
        ++m_epoch;
        ++m_degraded_enter_total;
    }

    m_mining_state = new_state;
    m_state_entered_at = now;
}

bool Worker_manager::connect(network::Endpoint const& wallet_endpoint)
{
    // Save the primary endpoint on the very first connect() call from Miner::run()
    if (!m_primary_endpoint.is_valid())
    {
        m_primary_endpoint = wallet_endpoint;
        if (m_config.has_failover())
        {
            auto const fo_ip   = m_config.get_failover_wallet_ip();
            auto const fo_port = m_config.get_failover_port() != 0
                                     ? m_config.get_failover_port()
                                     : m_config.get_port();
            m_failover_endpoint = network::Endpoint{network::Transport_protocol::tcp, fo_ip, fo_port};
            m_logger->info("[Failover] Configured: {}:{} (switch after {} primary failures)",
                           fo_ip, fo_port, m_config.get_failover_max_retries());
        }
    }

    std::string wallet_addr;
    wallet_endpoint.address(wallet_addr);
    uint16_t configured_port = wallet_endpoint.port();

    m_logger->info("[Solo] Connecting to wallet {}:{}", wallet_addr, configured_port);
    m_logger->info("[Solo] Port Configuration: Using port {} from miner.conf", configured_port);
    m_logger->debug("[Solo] Connection initiated to endpoint: {}", wallet_endpoint.to_string());

    // Use NodeSession to connect (handles both stateless and legacy ports via SIM Link)
    std::weak_ptr<Worker_manager> weak_self = shared_from_this();
    return m_primary_node_session->connect(wallet_endpoint, [weak_self, wallet_endpoint](bool success) {
        auto self = weak_self.lock();
        if (!self) return;

        if (!success) {
            self->m_logger->error("[Solo] Connection to wallet {} not successful", wallet_endpoint.to_string());
            self->retry_connect(wallet_endpoint);
            return;
        }

        // Connection and authentication succeeded
        self->m_logger->info("[Solo] Successfully connected and authenticated to {}", wallet_endpoint.to_string());

        // Reset retry counters on successful connection
        self->m_connection_retry_count = 0;
        self->m_connection_backoff.reset();
        self->m_primary_fail_count = 0;

        // Clear reconnect guard now that connection is fully authenticated
        self->m_reconnect_in_progress = false;
        self->m_reconnect_started_at = {};

        // Start timers once only (guarded by flags)
        auto const print_statistics_interval = self->m_config.get_print_statistics_interval();
        if (!self->m_stats_timers_started)
        {
            self->m_stats_timers_started = true;
            self->m_timer_manager.start_stats_collector_timer(print_statistics_interval, self->m_workers, self->m_stats_collector);
            self->m_timer_manager.start_stats_printer_timer(print_statistics_interval, self->m_stats_printers);
        }

        // Start template health monitor
        constexpr uint16_t TEMPLATE_HEALTH_INTERVAL = 30;
        if (!self->m_template_health_timer_started)
        {
            self->m_template_health_timer_started = true;
            self->m_timer_manager.start_template_health_timer(TEMPLATE_HEALTH_INTERVAL, self);
            self->m_logger->info("[Worker_manager] Template health monitor started (30s interval)");
        }

        // Start GET_ROUND timer (access primary protocol through NodeSession)
        constexpr uint16_t GET_ROUND_TIMER_INTERVAL = 1;
        if (!self->m_get_round_timer_started)
        {
            self->m_get_round_timer_started = true;
            auto solo_protocol_ptr = self->m_primary_node_session->get_primary_protocol();
            auto connection_shared = self->m_primary_node_session->get_primary_connection();
            if (solo_protocol_ptr && connection_shared) {
                self->m_timer_manager.start_get_round_timer(
                    GET_ROUND_TIMER_INTERVAL,
                    connection_shared,
                    solo_protocol_ptr);
                self->m_logger->info("[Solo Poll] GET_ROUND polling timer started ({}s tick, {}--{}s adaptive interval, both lanes)",
                    GET_ROUND_TIMER_INTERVAL,
                    protocol::Solo::POLL_INTERVAL_MIN_MS / 1000,
                    protocol::Solo::POLL_INTERVAL_MAX_MS / 1000);
            }
        }

        // Start lane health check timer
        constexpr uint16_t LANE_HEALTH_INTERVAL = 30;
        if (!self->m_lane_health_timer_started)
        {
            self->m_lane_health_timer_started = true;
            self->m_timer_manager.start_lane_health_check_timer(LANE_HEALTH_INTERVAL, self);
        }

        // Start Colin agent on first successful connect
        if (!self->m_colin_agent && self->m_config.get_colin_enabled())
        {
            self->m_colin_agent = std::make_shared<ColinAgent>(
                self->m_io_context,
                &self->m_sim_link,
                self->m_stats_collector,
                self->m_logger,
                self->m_config.get_colin_report_interval_seconds());

            // Wire up diagnostic sources
            auto solo_protocol_ptr = self->m_primary_node_session->get_primary_protocol();
            if (solo_protocol_ptr)
            {
                std::weak_ptr<protocol::Solo> weak_proto = solo_protocol_ptr;

                // Wire up PING_DIAG source
                self->m_colin_agent->set_ping_source(
                    [weak_proto]() -> ::LLP::ReceivedPingFrame {
                        auto proto = weak_proto.lock();
                        return proto ? proto->last_received_ping() : ::LLP::ReceivedPingFrame{};
                    });

                // Wire up SESSION_STATUS_ACK source
                self->m_colin_agent->set_status_source(
                    [weak_proto]() -> std::pair<::LLP::SessionStatusAckFrame,
                                                 std::chrono::steady_clock::time_point> {
                        auto proto = weak_proto.lock();
                        if (!proto) return {};
                        return { proto->last_session_status_ack(),
                                 proto->last_session_status_ack_time() };
                    });

                // Wire up HeightTracker
                self->m_colin_agent->set_height_tracker(&solo_protocol_ptr->get_height_tracker());

                // Wire up MiningTemplateInterface
                if (auto* tmpl_iface = solo_protocol_ptr->get_template_interface())
                {
                    self->m_colin_agent->set_template_source(
                        [weak_proto]() -> ColinAgent::TemplateSnapshot {
                            ColinAgent::TemplateSnapshot snap;
                            auto proto = weak_proto.lock();
                            if (!proto) return snap;
                            auto* iface = proto->get_template_interface();
                            if (!iface) return snap;

                            auto stats = iface->get_stats();
                            snap.templates_received       = stats.templates_received;
                            snap.templates_validated      = stats.templates_validated;
                            snap.templates_rejected       = stats.templates_rejected;
                            snap.templates_stale          = stats.templates_stale;
                            snap.templates_fed            = stats.templates_fed;
                            snap.templates_expired_age    = stats.templates_expired_age;
                            snap.templates_expired_height = stats.templates_expired_height;

                            if (iface->has_valid_template())
                            {
                                if (const auto* tmpl = iface->get_current_template())
                                {
                                    snap.has_valid_template = true;
                                    snap.unified_height = tmpl->block.nHeight;
                                    snap.nBits          = tmpl->nBits;
                                    snap.channel_height = tmpl->nChannelHeight;
                                    snap.channel        = tmpl->block.nChannel;
                                    snap.state_name     = protocol::MiningTemplateInterface::state_to_string(tmpl->state);
                                    // Use HeightTracker for canonical age calculation
                                    auto ht_snap = proto->get_height_tracker_snapshot();
                                    snap.age_seconds = ht_snap.get_template_age_seconds();
                                }
                            }
                            return snap;
                        });
                }

                // Wire up ColinPingHandler
                self->m_colin_agent->set_pong_telemetry_source(
                    [weak_proto]() -> ColinAgent::PongTelemetrySnapshot {
                        ColinAgent::PongTelemetrySnapshot pt;
                        auto proto = weak_proto.lock();
                        if (!proto) return pt;
                        const auto& handler = proto->get_ping_handler();
                        pt.ping_count  = handler.ping_count();
                        pt.last_rtt_us = handler.last_rtt_us();
                        return pt;
                    });

                self->m_logger->info("[Worker_manager] Colin diagnostic sources wired");
            }

            // Wire MinedBlockCache source
            std::weak_ptr<Worker_manager> weak_wm = self->shared_from_this();
            self->m_colin_agent->set_mined_block_cache_source(
                [weak_wm]() -> std::vector<ColinAgent::MinedBlockSnapshot> {
                    std::vector<ColinAgent::MinedBlockSnapshot> result;
                    auto wm = weak_wm.lock();
                    if (!wm) return result;
                    const auto& tier1 = wm->m_mined_block_cache.tier1();
                    result.reserve(tier1.size());
                    for (const auto& rec : tier1) {
                        ColinAgent::MinedBlockSnapshot snap;
                        snap.height = rec.height;
                        snap.channel = rec.channel;
                        snap.confirmations = rec.confirmations;
                        snap.status_emoji = rec.status_emoji();
                        snap.channel_name = rec.channel_name();
                        snap.hash_prev_block_hex = rec.hash_prev_block.GetHex();
                        result.push_back(std::move(snap));
                    }
                    return result;
                });

            // Wire failover state source
            self->m_colin_agent->set_failover_source(
                [weak_wm]() -> ColinAgent::FailoverSnapshot {
                    ColinAgent::FailoverSnapshot snap;
                    auto wm = weak_wm.lock();
                    if (!wm) return snap;
                    auto fs = wm->get_failover_status();
                    snap.has_failover_configured = fs.has_failover_configured;
                    snap.using_failover          = fs.using_failover;
                    snap.primary_fail_count      = fs.primary_fail_count;
                    snap.failover_max_retries    = fs.failover_max_retries;
                    snap.active_endpoint_str  = fs.using_failover ? fs.failover_endpoint_str : fs.primary_endpoint_str;
                    snap.standby_endpoint_str = fs.using_failover ? fs.primary_endpoint_str  : fs.failover_endpoint_str;
                    if (fs.using_failover && fs.failover_activated_at != std::chrono::steady_clock::time_point{}) {
                        snap.failover_active_seconds = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now() - fs.failover_activated_at).count());
                    }
                    snap.secondary_ip = wm->m_sim_link.get_active_node_ip();
                    return snap;
                });

            self->m_colin_agent->start();
            self->m_logger->info("[Worker_manager] Colin agent started");
        }
    });
}


void Worker_manager::submit_solution(const std::vector<uint8_t>& full_block_bytes, uint64_t nNonce)
{
    // No submission withholding: if the template is valid enough to mine, it's valid enough to submit.
    // In STOPPED state, workers are halted so this shouldn't be called, but guard defensively.
    if (m_mining_state == MiningState::STOPPED) {
        m_logger->info("[Worker_manager] Submission suppressed — mining is STOPPED");
        return;
    }

    // Use NodeSession to submit block (handles SIM Link dual-lane submission internally)
    if (m_primary_node_session && m_primary_node_session->is_authenticated())
    {
        auto packet = m_primary_node_session->submit_block(full_block_bytes, nNonce);
        if (packet && !packet->empty())
        {
            m_primary_node_session->transmit(packet);
            return;
        }
    }

    m_logger->error("[Worker_manager] Block submission failed — NodeSession not authenticated!");
}

void Worker_manager::log_lane_health()
{
    bool primary_alive = m_primary_node_session && m_primary_node_session->is_authenticated();

    m_logger->info("[NodeSession] Session health — Authenticated: {}", primary_alive ? "YES" : "NO");

    send_session_status_if_due();
}

void Worker_manager::send_session_status_if_due()
{
    auto now = std::chrono::steady_clock::now();
    constexpr int64_t SESSION_STATUS_INTERVAL_SECONDS = 300;
    if (std::chrono::duration_cast<std::chrono::seconds>(
            now - m_last_session_status_sent).count() < SESSION_STATUS_INTERVAL_SECONDS)
        return;
    m_last_session_status_sent = now;

    bool degraded    = (m_mining_state == MiningState::STOPPED);
    bool workers_run = (m_mining_state != MiningState::STOPPED) && !m_workers.empty();

    // Send session status via NodeSession (handles both lanes internally)
    if (m_primary_node_session && m_primary_node_session->is_authenticated())
    {
        auto solo_protocol = m_primary_node_session->get_primary_protocol();
        if (solo_protocol)
        {
            // NodeSession handles SIM Link internally, so we don't need to track secondary separately
            auto pkt = solo_protocol->build_session_status_packet(degraded, workers_run, false);
            if (pkt && !pkt->empty())
                m_primary_node_session->transmit(pkt);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Worker Control Methods (3-State Mining State Machine)
// ═══════════════════════════════════════════════════════════════════════

void Worker_manager::stop_all_workers()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);

    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    m_logger->warn("[Worker_manager] ⚠️  STOPPING ALL WORKERS (STOPPED STATE)");
    m_logger->warn("[Worker_manager] ════════════════════════════════════════");

    if (auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr) {
        solo_protocol->mark_authoritative_recovery_required("workers_stopped_waiting_for_valid_template");
    }

    // Update stats to reflect degraded mode
    auto global_stats = m_stats_collector->get_global_stats();
    global_stats.m_degraded_mode = true;
    m_stats_collector->update_global_stats(global_stats);

    // Reset all worker instances
    for (auto& worker : m_workers) {
        worker.reset();
    }
    m_workers.clear();

    m_logger->warn("[Worker_manager] Mining stopped - waiting for valid template (epoch {})", m_epoch);
}

void Worker_manager::retry_template_request(bool bForce)
{
    m_logger->info("[Worker_manager] Requesting fresh template... (force={}, state={})",
                   bForce ? "true" : "false", state_name(m_mining_state));

    if (!m_primary_node_session || !m_primary_node_session->is_authenticated()) {
        m_logger->error("[Worker_manager] No authenticated session available to request template");
        auto const ip_address = m_config.get_wallet_ip();
        auto const port = m_config.get_port();
        network::Endpoint wallet_endpoint{network::Transport_protocol::tcp, ip_address, port};
        m_logger->info("[Worker_manager] Attempting to reconnect to {}:{}", ip_address, port);
        retry_connect(wallet_endpoint);
        return;
    }

    auto solo_protocol = m_primary_node_session->get_primary_protocol();
    if (!solo_protocol) {
        m_logger->error("[Worker_manager] Failed to get protocol from NodeSession");
        return;
    }

    if (!solo_protocol->is_authenticated()) {
        m_logger->info("[Worker_manager] GET_BLOCK deferred — not yet authenticated");
        return;
    }

    if (!m_primary_node_session->is_primary_connected()) {
        m_logger->warn("[Worker_manager] GET_BLOCK deferred — primary TCP connection is not established");
        retry_connect(m_primary_endpoint);
        return;
    }

    bool forced_lane = bForce && (m_mining_state == MiningState::STOPPED);
    auto work_payload = m_primary_node_session->request_work(forced_lane);
    if (work_payload && !work_payload->empty()) {
        m_primary_node_session->transmit(work_payload);
        m_last_get_block_at = std::chrono::steady_clock::now();
        m_logger->info("[Worker_manager] → GET_BLOCK sent (state={}, epoch={})",
                       state_name(m_mining_state), m_epoch);
    } else {
        m_logger->warn("[Worker_manager] GET_BLOCK not sent — request_work() returned empty");
    }
}

void Worker_manager::check_template_health()
{
    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (!solo_protocol) {
        return;
    }

    // Guard against a stalled reconnect
    if (m_reconnect_in_progress) {
        if (m_reconnect_started_at == std::chrono::steady_clock::time_point{}) {
            m_reconnect_started_at = std::chrono::steady_clock::now();
        }
        auto reconnect_age_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_reconnect_started_at).count();
        constexpr int64_t MAX_RECONNECT_WAIT_SECONDS = 60;
        if (reconnect_age_s > MAX_RECONNECT_WAIT_SECONDS) {
            m_logger->warn("[Worker_manager] Reconnect in-progress for {}s > {}s — clearing stale flag",
                           reconnect_age_s, MAX_RECONNECT_WAIT_SECONDS);
            m_reconnect_in_progress = false;
            m_reconnect_started_at = {};
        }
    }

    auto* template_interface = solo_protocol->get_template_interface();
    if (!template_interface) {
        return;
    }

    auto ht_snap = solo_protocol->get_height_tracker_snapshot();
    bool has_template = template_interface->has_valid_template();

    switch (m_mining_state) {
    case MiningState::MINING: {
        if (!has_template) {
            // Template disappeared — go to STOPPED
            transition_to(MiningState::STOPPED, "template_lost");
            send_get_block(true);
            break;
        }

        // Channel stale? → STOPPED
        if (ht_snap.is_template_stale()) {
            uint32_t blocks_behind = ht_snap.blocks_behind();

            // Temporal guard: if template is newer than last push, it's a false positive
            bool template_never_received = (ht_snap.last_template_update == std::chrono::steady_clock::time_point{});
            bool template_is_newer_than_push = (!template_never_received &&
                                                ht_snap.last_template_update >= ht_snap.last_height_update);
            if (template_is_newer_than_push) {
                // False positive — template already accounts for latest push
                send_get_block(false);
                break;
            }

            if (blocks_behind <= 1) {
                // Normal single-block advance: just request refresh, workers keep mining
                send_get_block(false);
                break;
            }

            // Multi-block lag: genuine staleness → STOPPED
            m_logger->warn("[Worker_manager] ⚠️  Channel stale: channel_height {} >= channel_target {} ({} blocks behind)",
                ht_snap.channel_height, ht_snap.channel_target, blocks_behind);
            template_interface->discard_template("channel_stale");
            transition_to(MiningState::STOPPED, "channel_stale");
            send_get_block(true);
            break;
        }

        // 600s emergency? → STOPPED
        {
            uint64_t template_age = ht_snap.get_template_age_seconds();
            if (template_age > protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {
                // Check if push is still alive — defer if so
                bool recent_push = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{}) &&
                    (std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - ht_snap.last_push_notification_at).count() < PUSH_ALIVE_THRESHOLD_SECONDS);
                if (recent_push && !ht_snap.is_template_stale()) {
                    m_logger->warn("[Worker_manager] EMERGENCY deferred: push notification is recent — connection alive");
                    send_get_block(false);
                    break;
                }

                m_logger->error("[Worker_manager] ❌ EMERGENCY: template {}s old — forcing hard recovery", template_age);
                template_interface->discard_template("600s_emergency");
                transition_to(MiningState::STOPPED, "600s_emergency");
                send_get_block(true);
                break;
            }

            // Age warning
            if (template_age > protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS) {
                m_logger->warn("[Worker_manager] ⚠️  Template age {}s (warning threshold {}s)",
                    template_age, protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS);
            }
        }

        // Unified height drift? → STOPPED
        {
            uint32_t tmpl_height = template_interface->get_template_height();
            if (ht_snap.unified_height > 0 && tmpl_height > 0 &&
                ht_snap.unified_height > tmpl_height + UNIFIED_DRIFT_THRESHOLD)
            {
                int32_t drift = static_cast<int32_t>(ht_snap.unified_height) -
                                static_cast<int32_t>(tmpl_height);
                m_logger->warn("[Worker_manager] ⚠️  HEIGHT_DRIFT: unified={} vs template.nHeight={} (drift={})",
                    ht_snap.unified_height, tmpl_height, drift);
                template_interface->discard_template("Unified height drift: " +
                    std::to_string(drift) + " blocks behind");
                transition_to(MiningState::STOPPED, "height_drift");
                send_get_block(true);
                break;
            }
        }

        // Tip moved? → REFRESHING (workers keep mining)
        if (ht_snap.is_tip_moved()) {
            m_logger->debug("[Worker_manager] Unified tip moved (template_unified_height {} → unified_height {}) — requesting fresh template",
                           ht_snap.template_unified_height, ht_snap.unified_height);
            transition_to(MiningState::REFRESHING, "tip_moved");
            send_get_block(false);
            break;
        }

        // Fork canary (diagnostic only)
        {
            auto diag = solo_protocol->get_diagnostic_snapshot();
            if (diag.keepalive_peak_fork_score > 0) {
                m_logger->warn("[Worker_manager] [Colin] FORK CANARY: peak_fork_score={} (diagnostic only)",
                    diag.keepalive_peak_fork_score);
            }
        }
        break;
    }

    case MiningState::REFRESHING: {
        // Template arrived (fresh and not stale)? → MINING
        if (has_template && !ht_snap.is_tip_moved() && !ht_snap.is_template_stale()) {
            transition_to(MiningState::MINING, "fresh_template");
            break;
        }
        // Channel went stale while refreshing? → STOPPED
        if (has_template && ht_snap.is_template_stale()) {
            uint32_t blocks_behind = ht_snap.blocks_behind();
            if (blocks_behind > 1) {
                template_interface->discard_template("stale_during_refresh");
                transition_to(MiningState::STOPPED, "stale_during_refresh");
                send_get_block(true);
                break;
            }
        }
        // Template lost while refreshing? → STOPPED
        if (!has_template) {
            transition_to(MiningState::STOPPED, "template_lost_during_refresh");
            send_get_block(true);
            break;
        }
        // 300s without fresh template? → STOPPED
        if (seconds_in_state() > 300) {
            if (has_template) template_interface->discard_template("refresh_timeout");
            transition_to(MiningState::STOPPED, "refresh_timeout");
            send_get_block(true);
            break;
        }
        // Resend GET_BLOCK every 60s
        if (seconds_since_last_get_block() > 60) {
            send_get_block(false);
        }
        break;
    }

    case MiningState::STOPPED: {
        // Template arrived? → MINING (recreate workers)
        if (has_template) {
            create_and_feed_workers();
            transition_to(MiningState::MINING, "template_arrived");
            break;
        }

        // Escape ladder: if STOPPED for too long with dead push, reconnect
        {
            auto now = std::chrono::steady_clock::now();
            int64_t stopped_duration = seconds_in_state();
            bool push_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});
            int64_t since_push_s = push_received
                ? std::chrono::duration_cast<std::chrono::seconds>(now - ht_snap.last_push_notification_at).count()
                : INT64_MAX;
            bool push_recent = push_received && (since_push_s <= PUSH_ALIVE_THRESHOLD_SECONDS);

            // Hard limit reconnect
            const auto hard_limit_decision = protocol::SessionStatusPolicy::evaluate_degraded_session({
                stopped_duration,
                protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
                push_recent
            });
            if (hard_limit_decision.force_reconnect) {
                m_logger->error("[Worker_manager] ⛔ STOPPED HARD LIMIT ({}s) — forcing TCP reconnect", stopped_duration);
                retry_connect(m_primary_endpoint);
                break;
            }

            // Stage 3: >180s AND push stale → reconnect
            if (stopped_duration > protocol::ProtocolConstants::DEGRADED_MODE_STAGE3_SECONDS &&
                !push_recent && m_primary_node_session) {
                m_logger->error("[Worker_manager] ⚡ Stage 3 ESCALATION ({}s stopped, push dead) — forcing reconnect", stopped_duration);
                retry_connect(m_primary_endpoint);
                break;
            }

            // Fast reconnect: push dead for >90s and stopped >30s
            if (!push_recent &&
                since_push_s > protocol::ProtocolConstants::FAST_RECONNECT_SIGNAL_DEAD_SECONDS &&
                stopped_duration > protocol::ProtocolConstants::FAST_RECONNECT_DEGRADED_SECONDS &&
                !m_reconnect_in_progress) {
                m_logger->error("[Worker_manager] ⚡ Stage 0 FAST RECONNECT: push signal dead (push {}s ago, {}s stopped)",
                                since_push_s == INT64_MAX ? -1LL : since_push_s, stopped_duration);
                retry_connect(m_primary_endpoint);
                break;
            }

            // Stage 2: >60s AND push stale → in-band re-auth
            if (stopped_duration > protocol::ProtocolConstants::DEGRADED_MODE_STAGE2_SECONDS &&
                !push_recent && m_primary_node_session) {
                auto primary_protocol = m_primary_node_session->get_primary_protocol();
                if (primary_protocol) {
                    m_logger->warn("[Worker_manager] ⚡ Stage 2 ({}s stopped, push stale) — attempting re-auth", stopped_duration);
                    auto auth_payload = primary_protocol->login([weak_self = weak_from_this()](bool login_result) {
                        auto self = weak_self.lock();
                        if (!self) return;
                        if (!login_result) {
                            self->m_logger->error("[Worker_manager] Stage 2 re-auth login() failed");
                        }
                    });
                    if (auth_payload && !auth_payload->empty()) {
                        m_primary_node_session->transmit(auth_payload);
                    }
                }
            }
        }

        // Retry GET_BLOCK every 30s
        if (seconds_since_last_get_block() > 30) {
            m_logger->info("[Worker_manager] ⚠️  STOPPED ({}s): retrying GET_BLOCK (epoch {})", seconds_in_state(), m_epoch);
            send_get_block(true);
        }
        break;
    }
    } // switch
}

void Worker_manager::log_mined_block_cache() const
{
    auto summary = m_mined_block_cache.format_cache_summary();
    // Log each line individually for proper formatting
    std::istringstream iss(summary);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty())
            m_logger->info("[MinedBlockCache] {}", line);
    }
}

}
