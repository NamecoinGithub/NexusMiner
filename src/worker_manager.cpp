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
#include <asio/steady_timer.hpp>
#include <variant>
#include <algorithm>
#include <random>
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
    constexpr int64_t RECOVERY_WINDOW_SECONDS_HASH  =  60;   // Hash blocks every ~18s; 60s ≈ 3 blocks
    constexpr int64_t RECOVERY_WINDOW_SECONDS_PRIME = 300;   // Prime blocks take 2-5+ min; 300s gives margin

    // Minimum interval between successive GET_BLOCK sends by the health monitor
    // during an active recovery.  Prevents rapid-fire GETs while still allowing
    // periodic retries if the first attempt is not answered.
    // 15s gives 4 attempts in a 60s hash-block window (t=0, t=15, t=30, t=45),
    // well above the node's 2s rate-limit floor (GET_BLOCK_COOLDOWN_SECONDS).
    constexpr int64_t RECOVERY_RESEND_INTERVAL_SECONDS = 15;

    // Minimum interval between successive hard escalations (stop workers + hard recovery).
    // Prevents re-escalation before the new epoch's GET_BLOCK has had time to be answered.
    // Must be at least RECOVERY_RESEND_INTERVAL_SECONDS * 3 so that a GET_BLOCK sent during
    // escalation has time to be answered before we escalate again (minimum = 15 × 3 = 45s).
    // 90s provides 2× the minimum — comfortable margin for slow nodes.
    constexpr int64_t MIN_ESCALATION_INTERVAL_SECONDS = 90;

    // Multiplier on RECOVERY_RESEND_INTERVAL_SECONDS for the per-epoch no-re-escalate window.
    // 3 × 15s = 45s gives the new epoch's GET_BLOCK at least 3 resend intervals to be answered
    // before another escalation is permitted.
    constexpr int64_t EPOCH_NO_ESCALATE_MULTIPLIER = 3;

    // Push-notification liveness threshold: if a push notification
    // (PRIME/HASH_BLOCK_AVAILABLE) was received within this window, the TCP session
    // is demonstrably alive and authenticated.  PUSH is the sole authoritative
    // signal for session liveness — keepalive ACK is diagnostic only.
    constexpr int64_t PUSH_ALIVE_THRESHOLD_SECONDS = protocol::ProtocolConstants::PUSH_LIVENESS_THRESHOLD_SECONDS;

    // Fix A: push-alive guard in retry_connect() uses a much shorter window (30s).
    // A push received in the last 30s proves the TCP connection is alive RIGHT NOW.
    // A push received 5 minutes ago proves nothing about current TCP state and must
    // not suppress a TCP reconnect — that causes the doom loop.
    constexpr int64_t RETRY_CONNECT_PUSH_LIVE_SECONDS = 30;

    // Aggressive secondary reconnect delay during degraded mode.
    // Unified height drift threshold: if HeightTracker.unified_height exceeds
    // template.block.nHeight by more than this many blocks, the template is
    // presumed stale (hashPrevBlock is wrong) and must be discarded.
    // On a 3-channel Nexus blockchain, the unified height advances whenever any
    // channel (Prime, Hash, Stake) finds a block. A drift of 1-3 blocks between
    // push notification and new BLOCK_DATA template is normal during the propagation
    // window. Set threshold to 5 to avoid false-positive template discards.
    constexpr uint32_t UNIFIED_DRIFT_THRESHOLD = 5;
    constexpr int64_t FORCED_RETRY_JITTER_MIN_MS = 100;
    constexpr int64_t FORCED_RETRY_JITTER_MAX_MS = 250;

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

        // Create EpochCoordinator and wire it to the session manager before any auth begins.
        m_epoch_coordinator = std::make_shared<protocol::EpochCoordinator>();
        m_primary_node_session->set_epoch_coordinator(m_epoch_coordinator);

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

                // ═══════════════════════════════════════════════════════════════
                // Soft-pause (SOFT_REFRESH) state is cleared by the phase transition
                // in clear_recovery_state() below (workers_fed > 0 branch).
                // Do not clear here — we must confirm workers actually received the
                // template first before exiting recovery state.
                // ═══════════════════════════════════════════════════════════════

                // Bug 1 fix: In degraded mode, workers may have been stopped and reset
                // by stop_all_workers().  Restart them now so set_block() below actually
                // starts mining threads; without this the template is silently dropped and
                // workers_fed falsely reads 0 keeping the miner in a doom loop.
                size_t workers_fed = 0;
                {
                    std::lock_guard<std::mutex> lock(m_worker_mutex);
                    if (is_degraded() && !m_recovery_workers_spawned && m_workers.empty()) {
                        m_logger->info("[Worker_manager] Degraded mode: restarting workers before feeding recovery template");
                        create_workers_locked();
                        m_recovery_workers_spawned = !m_workers.empty();  // set AFTER success for exception safety
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
                                const char* soft_refresh_reason = channel_stale
                                    ? "submit_side_channel_stale"
                                    : "submit_side_age_stale";
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
                                mark_soft_refresh_requested(soft_refresh_reason);
                                template_interface->discard_template(channel_stale ? "Channel height advanced before submission"
                                                                                   : "Age exceeded 600s before submission");

                                // Request fresh template via NodeSession
                                m_logger->info("[Worker_manager] Requesting fresh template via NodeSession");
                                auto work_payload = m_primary_node_session->request_work();
                                if (work_payload && !work_payload->empty()) {
                                    m_primary_node_session->transmit(work_payload);
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
                    // ✅ Clear degraded mode and all recovery state now that a valid template
                    // has been successfully delivered to workers.  This is intentionally done
                    // AFTER distribution so we only exit recovery state when workers actually
                    // received the template (not merely on template arrival).
                    if (is_recovery_active()) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - m_recovery.entered_at).count();
                        m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
                        m_logger->warn("[Worker_manager] ✅ RECOVERY COMPLETE — epoch {} ({}s elapsed)", m_epoch_coordinator->recovery_epoch(), elapsed);
                        m_logger->warn("[Worker_manager]    Fresh template distributed to workers successfully");
                        m_logger->warn("[Worker_manager]    Workers resumed mining on valid template");
                        m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
                    }
                    clear_recovery_state();

                    // Re-subscribe to push notifications if they have been silent too long.
                    // After prolonged push silence the node's push subscription may have been
                    // lost during TCP disruption or session cycling.  Sending MINER_READY
                    // re-establishes the subscription and prevents the 600s timeout cycle.
                    if (solo_protocol) {
                        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
                        bool push_ever_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});

                        // Fix 1: If no push was ever received, skip entirely — MINER_READY was
                        // already sent during the authentication handshake.  Resubscribing now
                        // is redundant and triggers an immediate STATELESS_GET_BLOCK that causes
                        // a duplicate-template loop.
                        if (!push_ever_received) {
                            m_logger->info("[Worker_manager] No push notification ever received — skipping resubscribe");
                        } else {
                            auto now_resub = std::chrono::steady_clock::now();
                            int64_t since_push_s = std::chrono::duration_cast<std::chrono::seconds>(
                                now_resub - ht_snap.last_push_notification_at).count();

                            // Fix 2: Post-recovery hold-off — don't fire resubscribe within 60 s
                            // of recovery completing.  The template just delivered needs time to
                            // flow before we declare push silence.
                            constexpr int64_t POST_RECOVERY_HOLDOFF_SECONDS = 60;
                            int64_t since_recovery_s =
                                (m_recovery.last_completed_at != std::chrono::steady_clock::time_point{})
                                ? std::chrono::duration_cast<std::chrono::seconds>(
                                      now_resub - m_recovery.last_completed_at).count()
                                : INT64_MAX;  // No recovery ever completed — hold-off does not apply

                            // Fix 3: Raised from 120 → 400 to exceed the longest observed Prime
                            // block time (~330 s); prevents mid-mining resubscription on long blocks.
                            // NOTE: For faster resubscription during active recovery (reorg scenario),
                            // see the Reorg Resubscription Guard in check_template_health().
                            // This path handles post-recovery push silence only after recovery completes.
                            constexpr int64_t PUSH_RESUBSCRIBE_THRESHOLD_SECONDS = 400;

                            if (since_recovery_s < POST_RECOVERY_HOLDOFF_SECONDS) {
                                m_logger->info("[Worker_manager] Recovery completed {}s ago — within hold-off, skipping resubscribe",
                                               since_recovery_s);
                            } else if (since_push_s > PUSH_RESUBSCRIBE_THRESHOLD_SECONDS) {
                                m_logger->warn("[Worker_manager] Push notifications silent for {}s after recovery — re-subscribing",
                                               since_push_s);
                                solo_protocol->resubscribe_push_notifications();
                            }
                        }
                    }
                } else {
                    m_logger->error("[Worker_manager] FAILED: No workers received template!");
                    // Immediately request a new template — don't wait 30s for health monitor.
                    // transition_to(HARD_RECOVERY) is triggered by mark_recovery_initiated()
                    // inside retry_template_request(true), after stop_all_workers() here.
                    stop_all_workers();
                    retry_template_request(true);
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
                    
                    // Stop all workers
                    stop_all_workers();
                    
                    // NOTE: create_workers() intentionally omitted here.
                    // Worker recreation is handled by recovery_initiated_handler (for push staleness)
                    // or by the block distribution handler's degraded-mode guard when the recovery
                    // template arrives. Calling create_workers() here causes duplicate workers when
                    // both handlers fire for the same staleness event.
                    
                    // Request fresh template
                    retry_template_request(true);
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
        /* Multi-block/channel-stale recovery remains a hard stop path. Same-height  */
        /* canonical replacement now takes the dedicated soft-refresh handler below, */
        /* which withholds submissions while the replacement template is fetched.    */
        m_primary_node_session->set_recovery_initiated_handler(
            [this]() {
                mark_recovery_initiated("push_staleness");
                // Workers keep running with current template while we request a fresh one.
                retry_template_request(true);
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
                if (is_reconnecting() || (is_recovery_active() && m_epoch_coordinator->recovery_epoch() > 0)) {
                    m_logger->warn("[Worker_manager] Session EXPIRED ignored: reconnect/recovery already in progress "
                                   "(phase={}, recovery_active={}, recovery_epoch={})",
                                   phase_name(m_recovery.phase),
                                   is_recovery_active(),
                                   m_epoch_coordinator->recovery_epoch());
                    return;
                }

                m_logger->warn("[Worker_manager] Session EXPIRED — initiating in-band re-authentication");
                mark_recovery_initiated("session_expired");

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
                // Clear reconnect guard if we're in RECONNECTING phase (in-band re-auth path).
                // For the TCP reconnect path, the connection callback already cleared it.
                if (is_reconnecting()) {
                    // Transition back to WAITING_TEMPLATE — still need a fresh template.
                    transition_to(RecoveryPhase::WAITING_TEMPLATE, "in_band_reauth_complete");
                    m_logger->info("[Worker_manager] In-band re-auth complete — back in WAITING_TEMPLATE");
                }

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
                if (is_degraded() || is_recovery_active()) {
                    m_logger->info("[Worker_manager] Re-authentication SUCCESS — "
                                   "requesting fresh template to exit degraded mode");
                    // Reset m_recovery.degraded_since so the escape ladder timer restarts cleanly
                    // for this new authenticated session (avoids Stage 3 immediately firing).
                    m_recovery.degraded_since = {};
                    restart_recovery_window("session_reauthenticated");
                    retry_template_request(true);
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

    // Transition to RECONNECTING phase — guards against stale callbacks and
    // prevents session_expired from re-entering during TCP reconnect window.
    transition_to(RecoveryPhase::RECONNECTING, "tcp_reconnect");

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



int64_t Worker_manager::next_forced_retry_jitter_ms()
{
    thread_local std::mt19937 rng([]() {
        std::random_device rd;
        auto now = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        std::seed_seq seed{
            rd(), rd(),
            static_cast<uint32_t>(now & 0xffffffffu),
            static_cast<uint32_t>((now >> 32) & 0xffffffffu)
        };
        return std::mt19937(seed);
    }());
    std::uniform_int_distribution<int64_t> dist(FORCED_RETRY_JITTER_MIN_MS, FORCED_RETRY_JITTER_MAX_MS);
    return dist(rng);
}

bool Worker_manager::has_valid_template_available(const std::shared_ptr<protocol::Solo>& solo_protocol) const
{
    auto* template_interface = solo_protocol ? solo_protocol->get_template_interface() : nullptr;
    return (template_interface && template_interface->has_valid_template());
}


void Worker_manager::schedule_forced_recovery_retry(const char* trigger_reason)
{
    if (!m_io_context || !is_recovery_active()) {
        return;
    }
    if (m_forced_retry_timer_pending) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto delay_ms = next_forced_retry_jitter_ms();
    auto due = now + std::chrono::milliseconds(delay_ms);

    auto wait_ms = std::max<int64_t>(
        1,
        std::chrono::duration_cast<std::chrono::milliseconds>(due - now).count());
    m_forced_retry_timer_pending = true;
    ++m_forced_retry_timer_token;
    const auto token = m_forced_retry_timer_token;
    m_forced_retry_timer = std::make_shared<asio::steady_timer>(*m_io_context, std::chrono::milliseconds(wait_ms));
    m_logger->info("[Worker_manager] Queue forced degraded retry token={} in {}ms (reason={})",
                   token, wait_ms, trigger_reason ? trigger_reason : "unknown");
    m_forced_retry_timer->async_wait([self = shared_from_this(), token](const asio::error_code& ec) {
        if (ec) {
            return;
        }
        if (!self->is_recovery_active() || token != self->m_forced_retry_timer_token) {
            self->m_forced_retry_timer_pending = false;
            return;
        }
        self->m_forced_retry_timer_pending = false;
        self->retry_template_request(true);
    });
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

        // Clear reconnect guard now that connection is fully authenticated.
        // Transition back from RECONNECTING to HARD_RECOVERY to request a fresh template.
        if (self->is_reconnecting()) {
            self->transition_to(RecoveryPhase::WAITING_TEMPLATE, "reconnect_complete");
            self->m_logger->info("[Worker_manager] Reconnect complete — entering WAITING_TEMPLATE to obtain fresh template");
        }

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

    bool degraded    = is_degraded();
    bool workers_run = !is_degraded() && !m_workers.empty();

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
// Worker Control Methods (Degraded Mode Support)
// ═══════════════════════════════════════════════════════════════════════

// ── State machine helpers ────────────────────────────────────────────────

const char* Worker_manager::phase_name(RecoveryPhase phase) {
    switch (phase) {
        case RecoveryPhase::HEALTHY:          return "HEALTHY";
        case RecoveryPhase::WAITING_TEMPLATE: return "WAITING_TEMPLATE";
        case RecoveryPhase::RECONNECTING:     return "RECONNECTING";
    }
    return "UNKNOWN";
}

bool Worker_manager::is_valid_transition(RecoveryPhase from, RecoveryPhase to) {
    if (from == to) return true;
    switch (from) {
        case RecoveryPhase::HEALTHY:
            return to == RecoveryPhase::WAITING_TEMPLATE ||
                   to == RecoveryPhase::RECONNECTING;
        case RecoveryPhase::WAITING_TEMPLATE:
            return to == RecoveryPhase::HEALTHY ||
                   to == RecoveryPhase::RECONNECTING;
        case RecoveryPhase::RECONNECTING:
            return to == RecoveryPhase::HEALTHY ||
                   to == RecoveryPhase::WAITING_TEMPLATE;
    }
    return false;
}

void Worker_manager::on_phase_exit(RecoveryPhase old_phase) {
    switch (old_phase) {
        case RecoveryPhase::RECONNECTING:
            m_recovery.reconnect_started_at = {};
            break;
        default:
            break;
    }
}

void Worker_manager::on_phase_enter(RecoveryPhase new_phase) {
    switch (new_phase) {
        case RecoveryPhase::HEALTHY: {
            auto now = std::chrono::steady_clock::now();
            m_recovery.degraded_since = {};
            m_recovery.last_completed_at = now;
            m_recovery.entered_at = {};
            // Template successfully adopted — reset GET_BLOCK mismatch backoff.
            m_get_block_backoff_ms    = 0;
            m_get_block_backoff_until = {};
            auto global_stats = m_stats_collector->get_global_stats();
            global_stats.m_degraded_mode = false;
            m_stats_collector->update_global_stats(global_stats);
            m_stats_collector->reset_start_time();
            break;
        }
        case RecoveryPhase::WAITING_TEMPLATE: {
            auto now = std::chrono::steady_clock::now();
            bool is_new_outage = (m_recovery.degraded_since == std::chrono::steady_clock::time_point{});
            if (is_new_outage) {
                m_recovery.degraded_since = now;
                ++m_degraded_enter_total;
            }
            auto global_stats = m_stats_collector->get_global_stats();
            global_stats.m_degraded_mode = true;
            m_stats_collector->update_global_stats(global_stats);
            break;
        }
        case RecoveryPhase::RECONNECTING: {
            m_recovery.reconnect_started_at = std::chrono::steady_clock::now();
            break;
        }
    }
}

void Worker_manager::transition_to(RecoveryPhase new_phase, const char* reason) {
    RecoveryPhase old_phase = m_recovery.phase;
    if (old_phase == new_phase) {
        return;  // Already in this phase — no-op
    }

    if (!is_valid_transition(old_phase, new_phase)) {
        m_logger->error("[Worker_manager] ⚡ ILLEGAL TRANSITION: {} → {} (reason: {})",
                        phase_name(old_phase), phase_name(new_phase),
                        reason ? reason : "unknown");
        // In debug builds, assert to catch illegal transitions early during development.
        // In release builds, log and proceed to avoid hard crashes in production.
#ifndef NDEBUG
        assert(false && "Illegal RecoveryPhase transition — see error log above");
#endif
    }

    // Pre-transition accounting: if exiting WAITING_TEMPLATE to HEALTHY,
    // accumulate total time spent in degraded mode.
    if (new_phase == RecoveryPhase::HEALTHY && old_phase == RecoveryPhase::WAITING_TEMPLATE) {
        auto now = std::chrono::steady_clock::now();
        if (m_recovery.degraded_since != std::chrono::steady_clock::time_point{}) {
            auto elapsed_ms = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - m_recovery.degraded_since).count());
            m_time_in_degraded_ms += elapsed_ms;
        }
        ++m_degraded_exit_total;
    }

    on_phase_exit(old_phase);

    m_recovery.phase = new_phase;
    m_recovery.reason = reason;

    // Reset per-epoch state for all non-HEALTHY phases
    if (new_phase != RecoveryPhase::HEALTHY) {
        m_epoch_coordinator->advance_recovery_epoch(reason ? reason : "unknown");
        m_recovery.entered_at = std::chrono::steady_clock::now();
        m_recovery.get_block_confirmed = false;
        m_recovery.last_get_block_at = {};
        m_forced_retry_timer_pending = false;
        ++m_forced_retry_timer_token;
        if (m_forced_retry_timer) {
            m_forced_retry_timer->cancel();
        }
    }

    on_phase_enter(new_phase);

    m_logger->info("[Worker_manager] ⚡ TRANSITION: {} → {} (epoch={}, reason={})",
                   phase_name(old_phase), phase_name(new_phase),
                   m_epoch_coordinator->recovery_epoch(), reason ? reason : "unknown");
}


void Worker_manager::mark_recovery_initiated(const char* reason)
{
    // Idempotent: if already in WAITING_TEMPLATE or RECONNECTING,
    // a new epoch is already running — do NOT reset it.
    if (is_recovery_active()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery.entered_at).count();
        m_logger->info("[Worker_manager] Recovery already pending (epoch {}, {}s elapsed, reason: {})",
                       m_epoch_coordinator->recovery_epoch(), elapsed, reason ? reason : "unknown");
        return;
    }
    // From HEALTHY → WAITING_TEMPLATE (new epoch; workers keep running)
    transition_to(RecoveryPhase::WAITING_TEMPLATE, reason);
    m_logger->warn("[Worker_manager] ⚑ RECOVERY INITIATED — epoch {} (reason: {})",
                   m_epoch_coordinator->recovery_epoch(), reason ? reason : "unknown");
    m_logger->warn("[Worker_manager]   Workers keep running with current template while requesting fresh one");
}

void Worker_manager::mark_soft_refresh_requested(const char* reason)
{
    // Both soft refresh and hard recovery now map to WAITING_TEMPLATE.
    // Workers keep running; no submissions withheld in the new model.
    mark_recovery_initiated(reason);
}

void Worker_manager::restart_recovery_window(const char* reason)
{
    // Reset the current-epoch timing state while staying in the current recovery phase.
    // Used after successful re-authentication to give the new session a clean recovery
    // window clock without exiting degraded mode (workers are still stopped, no template yet).
    const bool had_pending_recovery = is_recovery_active();
    const bool had_forced_retry_timer = m_forced_retry_timer_pending;
    int64_t elapsed_s = 0;
    if (had_pending_recovery && m_recovery.entered_at != std::chrono::steady_clock::time_point{}) {
        elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery.entered_at).count();
    }

    // Reset per-epoch state in-place (no phase change)
    m_recovery.entered_at = std::chrono::steady_clock::now();  // fresh epoch clock
    m_recovery.last_get_block_at = {};
    m_recovery.get_block_confirmed = false;
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_forced_retry_timer) {
        m_forced_retry_timer->cancel();
    }

    if (had_pending_recovery || had_forced_retry_timer) {
        m_logger->info("[Worker_manager] Restarting recovery window after {} "
                       "(prior_epoch={} prior_elapsed={}s phase={})",
                       reason ? reason : "unknown",
                       m_epoch_coordinator->recovery_epoch(),
                       elapsed_s,
                       phase_name(m_recovery.phase));
    }
}

void Worker_manager::clear_recovery_state()
{
    if (!is_degraded() && !is_recovery_active())
        return;  // Already HEALTHY — nothing to clear

    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (is_degraded() && !has_valid_template_available(solo_protocol)) {
        m_logger->warn("[Worker_manager] clear_recovery_state() deferred: no valid template accepted yet");
        return;
    }

    if (solo_protocol) {
        auto* session_manager = solo_protocol->get_session_manager();
        if (session_manager) {
            const auto session_snapshot = session_manager->get_runtime_snapshot();
            if (session_snapshot.recovery_state != protocol::SessionManager::RecoveryState::HEALTHY ||
                !session_snapshot.recovery_reason.empty()) {
                solo_protocol->mark_authoritative_recovery_healthy("worker_manager_clear_recovery_state");
            }
        }
    }

    m_logger->info("[Worker_manager] Clearing recovery state — exiting {} phase",
                   phase_name(m_recovery.phase));

    // Note: m_recovery_workers_spawned is intentionally NOT reset here.
    // It is only reset in stop_all_workers() which actually destroys workers,
    // preventing a mid-recovery clear_recovery_state() call (e.g. from a
    // different epoch's template feed) from allowing duplicate worker creation.

    // transition_to(HEALTHY) handles: degraded time accounting, global stats,
    // stats reset, last_completed_at, clearing of all recovery fields.
    transition_to(RecoveryPhase::HEALTHY, "template_distributed");

    m_logger->info("[Worker_manager] Recovery state cleared — degraded_exit_count={} cumulative_degraded_time_ms={}",
                   m_degraded_exit_total, m_time_in_degraded_ms);
}

void Worker_manager::stop_all_workers()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);

    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    m_logger->warn("[Worker_manager] ⚠️  STOPPING ALL WORKERS (DEGRADED MODE)");
    m_logger->warn("[Worker_manager] ════════════════════════════════════════");

    // Notify protocol layer that recovery is required.
    // Phase transition is handled by the caller (mark_recovery_initiated / transition_to)
    // before or after stop_all_workers() — this function is a pure physical stop.
    if (auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr) {
        solo_protocol->mark_authoritative_recovery_required("workers_stopped_waiting_for_valid_template");
    }

    // Reset all worker instances so that the next create_workers() call starts fresh
    // without duplicating existing workers.  The shared_ptr reset() destroys the Worker
    // object (and joins its mining thread in the destructor), effectively stopping it.
    for (auto& worker : m_workers) {
        worker.reset();
    }
    m_workers.clear();

    // Clear the recovery gate so the next epoch can re-create workers
    m_recovery_workers_spawned = false;

    m_logger->warn("[Worker_manager] Mining stopped - waiting for valid template");
    m_logger->warn("[Worker_manager] Workers stopped and cleared — will be restarted on recovery");
    m_logger->warn("[Worker_manager] ⬆  DEGRADED MODE ENTERED — recovery will be attempted via GET_BLOCK (0xD081)");
    m_logger->warn("[Worker_manager] degraded_enter_total={}", m_degraded_enter_total);
}


void Worker_manager::retry_template_request(bool bForce)
{
    auto now = std::chrono::steady_clock::now();
    m_logger->info("[Worker_manager] Requesting fresh template... (force={})", bForce ? "true" : "false");

    if (!m_primary_node_session || !m_primary_node_session->is_authenticated()) {
        m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context=missing_authenticated_session");
        m_logger->error("[Worker_manager] No authenticated session available to request template");
        // Reconstruct wallet endpoint from config and retry connection
        auto const ip_address = m_config.get_wallet_ip();
        auto const port = m_config.get_port();
        network::Endpoint wallet_endpoint{network::Transport_protocol::tcp, ip_address, port};
        m_logger->info("[Worker_manager] Attempting to reconnect to {}:{}", ip_address, port);
        retry_connect(wallet_endpoint);
        return;
    }

    auto solo_protocol = m_primary_node_session->get_primary_protocol();
    if (!solo_protocol) {
        m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context=no_protocol");
        m_logger->error("[Worker_manager] Failed to get protocol from NodeSession");
        return;
    }

    // ── GET_BLOCK exponential backoff (hashPrevBlock mismatch storm guard) ───
    // If validate_current_template() has discarded the last several templates due to
    // hashPrevBlock mismatch (consecutive > 0), a rapid-fire GET_BLOCK ↔ discard loop
    // is forming.  Apply an exponential delay before the next request so we don't
    // hammer a node that is already under load.  Forced recovery calls (bForce=true)
    // coming from the health-monitor still respect the backoff; the health-monitor's
    // own tick period (~5 s) already provides a natural floor delay.
    {
        uint32_t consecutive = solo_protocol->get_hashprev_mismatch_consecutive();
        if (consecutive > 0) {
            // Compute the target backoff for this mismatch depth (doubles each step, 30 s cap).
            // consecutive==1 → 2 s, consecutive==2 → 4 s, … consecutive>=4 → 30 s
            // Cap the iteration count to avoid a pathologically large loop; the backoff
            // plateaus at GET_BLOCK_BACKOFF_MAX_MS well before the cap is reached.
            constexpr uint32_t MAX_BACKOFF_ITERATIONS = 16;
            uint32_t iterations = std::min(consecutive - 1, MAX_BACKOFF_ITERATIONS);
            int64_t target_backoff_ms = GET_BLOCK_BACKOFF_INITIAL_MS;
            for (uint32_t i = 0; i < iterations; ++i) {
                target_backoff_ms = std::min(target_backoff_ms * 2, GET_BLOCK_BACKOFF_MAX_MS);
                if (target_backoff_ms >= GET_BLOCK_BACKOFF_MAX_MS) break;
            }

            // Extend the deadline if the new target is longer than the current one.
            auto desired_until = now + std::chrono::milliseconds(target_backoff_ms);
            if (desired_until > m_get_block_backoff_until) {
                m_get_block_backoff_ms    = target_backoff_ms;
                m_get_block_backoff_until = desired_until;
                m_logger->warn("[Worker_manager] ⏳ GET_BLOCK backoff set to {}ms "
                               "({} consecutive hashPrevBlock mismatches) — deferring request",
                               target_backoff_ms, consecutive);
            }
        } else {
            // No consecutive mismatches — clear any residual backoff (template was
            // recently adopted and the mismatch chain is broken).  The HEALTHY phase
            // transition handler also resets the backoff as a second safety net for
            // the case where the consecutive count is queried after adoption.
            m_get_block_backoff_ms    = 0;
            m_get_block_backoff_until = {};
        }

        // Suppress this GET_BLOCK if we are still within the backoff window.
        if (m_get_block_backoff_until != std::chrono::steady_clock::time_point{} &&
            now < m_get_block_backoff_until)
        {
            auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                m_get_block_backoff_until - now).count();
            m_logger->info("[Worker_manager] GET_BLOCK suppressed: context=hashprev_mismatch_backoff "
                           "({}ms remaining)", remaining_ms);
            return;
        }
    }

    bool no_valid_template = !has_valid_template_available(solo_protocol);

    // When this is a forced recovery (bForce=true) and not already tracked as such,
    // mark a new recovery epoch so check_template_health() knows recovery is pending.
    if (bForce) {
        mark_recovery_initiated("health_monitor_or_validation");
    }

    // Early-exit if not yet authenticated — the channel-advanced staleness detector
    // can fire during the brief window after a push increments channel_height but
    // before MINER_AUTH_RESULT has set m_authenticated.  This is a normal transient
    // startup/reconnect condition; the health monitor will retry at the next tick.
    if (!solo_protocol->is_authenticated()) {
        m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context=solo_not_authenticated");
        m_logger->info("[Worker_manager] GET_BLOCK deferred — not yet authenticated (auth in progress); "
                       "health monitor will retry when session is established");
        return;
    }

    // Early-exit if primary TCP connection is down — request_work() would silently
    // return nullptr in this case (NodeSession checks m_primary_connected before
    // calling get_work).  Detect it here so we can log the real reason and trigger
    // reconnect immediately instead of burning a recovery tick.
    if (!m_primary_node_session->is_primary_connected()) {
        m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context=primary_disconnected");
        m_logger->warn("[Worker_manager] GET_BLOCK deferred — primary TCP connection is not established; "
                       "initiating reconnect");
        retry_connect(m_primary_endpoint);
        return;
    }

    bool forced_lane = bForce && is_recovery_active() && solo_protocol->is_authenticated() && no_valid_template;

    // Gate: SessionManager::can_request_get_block() must be true before transmitting GET_BLOCK.
    // This guard is bypassed when this is a forced recovery request (bForce && is_recovery_active())
    // so the recovery ladder can always make progress even when push notifications are absent
    // (no PUSH subscription, post-reorg push silence, or initial connection before first push).
    if (!solo_protocol->can_request_get_block()) {
        if (bForce && is_recovery_active()) {
            m_logger->info("[Worker_manager] GET_BLOCK can_request_get_block=false bypassed by forced recovery");
        } else {
            m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context=session_not_ready_for_get_block");
            m_logger->info("[Worker_manager] GET_BLOCK deferred — session not ready for GET_BLOCK; "
                           "health monitor will retry at next tick");
            return;
        }
    }

    // Request template via NodeSession
    m_logger->info("[Worker_manager] Requesting fresh template via NodeSession (forced_lane={})",
                   forced_lane ? "true" : "false");
    auto work_payload = m_primary_node_session->request_work(forced_lane);
    if (work_payload && !work_payload->empty()) {
        m_primary_node_session->transmit(work_payload);
        m_recovery.last_get_block_at = std::chrono::steady_clock::now();
        m_recovery.get_block_confirmed = true;
        ++m_get_block_sent_total;
        if (forced_lane) {
            ++m_get_block_forced_retry_total;
        }
        m_logger->info("[Worker_manager] → GET_BLOCK sent (recovery epoch {})", m_epoch_coordinator->recovery_epoch());
    } else {
        auto last_status = solo_protocol->get_last_get_block_request_status();
        const char* status_str = "request_work_empty";
        switch (last_status) {
            case protocol::Solo::GetBlockRequestStatus::DUPLICATE_WINDOW:
                status_str = "duplicate_window";
                break;
            case protocol::Solo::GetBlockRequestStatus::UNAUTHENTICATED:
            case protocol::Solo::GetBlockRequestStatus::SESSION_INVALID:
                status_str = "unauthenticated";
                break;
            default:
                break;
        }
        m_logger->debug("[Worker_manager] GET_BLOCK suppressed: context={}", status_str);
        // request_work() returned empty despite passing all guards above.
        // Most likely cause: 100ms GET_BLOCK dedup guard in Solo::get_work() or
        // transient reward-binding gap.  The recovery timer will retry at the next tick.
        m_logger->warn("[Worker_manager]   GET_BLOCK not sent — request_work() returned empty "
                       "(authenticated={}, primary_connected={}, see Solo logs for specific suppression reason)",
                       solo_protocol->is_authenticated(),
                       m_primary_node_session->is_primary_connected());
        if (is_recovery_active() && solo_protocol->is_authenticated() && no_valid_template) {
            schedule_forced_recovery_retry("request_work_empty");
        }
    }
}

void Worker_manager::check_template_health()
{
    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (!solo_protocol) {
        return;
    }

    // Guard against a stalled reconnect. If RECONNECTING phase has been active for
    // more than 60 seconds, the TCP connect attempt itself has likely failed silently.
    // Transition back to WAITING_TEMPLATE so the escape ladder is not indefinitely suppressed.
    if (is_reconnecting()) {
        if (m_recovery.reconnect_started_at == std::chrono::steady_clock::time_point{}) {
            m_logger->warn("[Worker_manager] RECONNECTING but reconnect_started_at unset — "
                           "logic error detected; stamping now to allow timeout guard");
            m_recovery.reconnect_started_at = std::chrono::steady_clock::now();
        }
        auto reconnect_age_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery.reconnect_started_at).count();
        constexpr int64_t MAX_RECONNECT_WAIT_SECONDS = 60;
        if (reconnect_age_s > MAX_RECONNECT_WAIT_SECONDS) {
            m_logger->warn("[Worker_manager] Reconnect stalled for {}s > {}s — clearing RECONNECTING phase",
                           reconnect_age_s, MAX_RECONNECT_WAIT_SECONDS);
            transition_to(RecoveryPhase::WAITING_TEMPLATE, "reconnect_timeout");
        }
    }

    // WAITING_TEMPLATE: check timing and connection health, retry GET_BLOCK
    if (is_recovery_active() && !is_reconnecting()) {
        auto now = std::chrono::steady_clock::now();
        if (m_recovery.degraded_since == std::chrono::steady_clock::time_point{}) {
            m_recovery.degraded_since = now;
        }
        auto degraded_secs = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_recovery.degraded_since).count();

        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
        bool push_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});
        int64_t since_push_s = push_received
            ? std::chrono::duration_cast<std::chrono::seconds>(now - ht_snap.last_push_notification_at).count()
            : INT64_MAX;
        bool push_recent = push_received && (since_push_s <= PUSH_ALIVE_THRESHOLD_SECONDS);

        m_logger->info("[Worker_manager] WAITING_TEMPLATE: {}s elapsed, push {}s ago (recent={})",
                       degraded_secs,
                       push_received ? since_push_s : static_cast<int64_t>(-1),
                       push_recent ? "YES" : "NO");

        // After 60s without template, check connection health
        if (degraded_secs > 60 && !push_recent) {
            m_logger->error("[Worker_manager] ⛔ 60s timeout: no template and push is dead — reconnecting");
            retry_connect(m_primary_endpoint);
            return;
        }

        // Retry GET_BLOCK on every health check tick
        retry_template_request(true);

        /* ── Reorg Resubscription Guard ──────────────────────────────────────────
         * After 60s in WAITING_TEMPLATE with a live authenticated session but no
         * incoming push, proactively re-send MINER_READY.  This covers the reorg
         * case: the node recovered the session but the push subscription state was
         * lost during the TCP disconnect, so the node's heartbeat cycle (480s) is
         * the only thing that would otherwise restore it.
         * Cooldown: once per 60s to prevent rapid-fire. */
        constexpr int64_t REORG_RESUBSCRIBE_THRESHOLD_SECONDS = 60;
        constexpr int64_t REORG_RESUBSCRIBE_COOLDOWN_SECONDS  = 60;

        bool push_silent_in_recovery = !push_recent &&
            (degraded_secs > protocol::ProtocolConstants::DEGRADED_MODE_STAGE2_SECONDS);

        if (push_silent_in_recovery && solo_protocol->is_authenticated())
        {
            auto since_last_resub_s =
                (m_last_resubscribe_at == std::chrono::steady_clock::time_point{})
                ? INT64_MAX
                : std::chrono::duration_cast<std::chrono::seconds>(
                      now - m_last_resubscribe_at).count();

            if (since_last_resub_s >= REORG_RESUBSCRIBE_COOLDOWN_SECONDS &&
                since_push_s >= REORG_RESUBSCRIBE_THRESHOLD_SECONDS)
            {
                int64_t display_push_silence_s = (since_push_s == INT64_MAX) ? -1 : since_push_s;
                m_logger->warn("[Worker_manager] ⚡ REORG RESUBSCRIBE GUARD: {}s in recovery, "
                               "push silent {}s, sending MINER_READY to restore subscription",
                               degraded_secs, display_push_silence_s);
                solo_protocol->resubscribe_push_notifications();
                m_last_resubscribe_at = now;
            }
        }

        return;
    }

    auto* template_interface = solo_protocol->get_template_interface();
    if (!template_interface) {
        return;
    }

    uint8_t channel = template_interface->get_channel();
    std::string channel_name = (channel == mining::CHANNEL_PRIME) ? "Prime" : "Hash";
    const bool has_valid_template = template_interface->has_valid_template();

    if (!has_valid_template) {
        // No template in HEALTHY state — request one
        retry_template_request(false);
        return;
    }

    // Get HeightTracker snapshot for staleness and age checks (single source of truth)
    auto ht_snap = solo_protocol->get_height_tracker_snapshot();
    uint64_t template_age = ht_snap.get_template_age_seconds();

    // Channel height-based staleness detection (primary check — HeightTracker is the single
    // source of truth).  Template is stale when channel_height >= channel_target (both non-zero).
    {
        if (ht_snap.is_template_stale()) {
            uint32_t blocks_behind = ht_snap.blocks_behind();

            bool template_never_received = (ht_snap.last_template_update == std::chrono::steady_clock::time_point{});
            bool template_is_newer_than_push = (!template_never_received &&
                                                ht_snap.last_template_update >= ht_snap.last_height_update);
            if (template_is_newer_than_push) {
                m_logger->debug("[Worker_manager] {} is_template_stale() true but template (t={}) is newer than last push (t={}) — suppressing false-positive stop",
                    channel_name,
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_template_update.time_since_epoch()).count(),
                    std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_height_update.time_since_epoch()).count());
                retry_template_request(false);
                return;
            }

            if (blocks_behind == 1) {
                m_logger->info("[Worker_manager] {} template anchor advanced normally: channel_height {} -> next target {} (template target {}, 1 block behind) — requesting refresh without recovery",
                    channel_name,
                    ht_snap.channel_height,
                    ht_snap.expected_template_target(),
                    ht_snap.channel_target);
                retry_template_request(false);
                return;
            }

            if (blocks_behind == 0) {
                m_logger->debug("[Worker_manager] {} stale snapshot reported with zero block lag (channel_height {}, channel_target {}) — requesting refresh without recovery",
                    channel_name,
                    ht_snap.channel_height,
                    ht_snap.channel_target);
                retry_template_request(false);
                return;
            }

            m_logger->warn("[Worker_manager] ⚠️  {} channel advanced: channel_height {} >= channel_target {} — age {}s",
                channel_name, ht_snap.channel_height, ht_snap.channel_target, template_age);
            m_logger->info("[Worker_manager]    Template (t={}) predates last push (t={}) — true staleness ({} blocks behind)",
                std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_template_update.time_since_epoch()).count(),
                std::chrono::duration_cast<std::chrono::milliseconds>(ht_snap.last_height_update.time_since_epoch()).count(),
                blocks_behind);

            // Enter WAITING_TEMPLATE: workers keep running with stale template while we request a fresh one
            mark_recovery_initiated("health_monitor_channel_stale");
            retry_template_request(true);
            return;
        }
    }

    // Unified tip moved on another channel — request fresh template opportunistically
    if (ht_snap.is_tip_moved()) {
        m_logger->debug("[Worker_manager] Unified tip moved (template_unified_height {} → unified_height {}) — requesting fresh template; workers continue on valid channel template",
                       ht_snap.template_unified_height, ht_snap.unified_height);
        retry_template_request(false);
        return;
    }

    // Unified height drift detection
    {
        auto ht_snap2 = solo_protocol->get_height_tracker_snapshot();
        uint32_t tmpl_height = template_interface->get_template_height();

        if (ht_snap2.unified_height > 0 && tmpl_height > 0 &&
            ht_snap2.unified_height > tmpl_height + UNIFIED_DRIFT_THRESHOLD)
        {
            int32_t drift = static_cast<int32_t>(ht_snap2.unified_height) -
                            static_cast<int32_t>(tmpl_height);
            m_logger->warn("[Worker_manager] ⚠️  HEIGHT_DRIFT: unified={} vs template.nHeight={} (drift={}) — template on stale tip",
                ht_snap2.unified_height, tmpl_height, drift);
            template_interface->discard_template("Unified height drift: " +
                std::to_string(drift) + " blocks behind");
            mark_recovery_initiated("height_drift");
            retry_template_request(true);
            return;
        }
    }

    // ── Fork / tip mismatch detection (DIAGNOSTIC ONLY) ────────────────────────
    // Fork score and hash_tip_lo32 come from keepalive ACKs (DiagnosticObserverState).
    // They are INFORMATIONAL and must NOT be used to trigger hard stops, as keepalive
    // data can lag chain advancement by 45s and cause false-positive fork detections
    // during normal block-finding events.
    //
    // Real fork detection uses canonical_hash_prev_block vs push hashPrevBlock
    // (handled by the TEMPLATE_ANCHOR in solo.cpp, not here).
    {
        auto diag = solo_protocol->get_diagnostic_snapshot();
        if (diag.keepalive_peak_fork_score > 0) {
            m_logger->warn("[Worker_manager] [Colin] FORK CANARY: peak_fork_score={} fork_score={} hash_tip_lo32=0x{:08x} (diagnostic only — not stopping workers)",
                diag.keepalive_peak_fork_score, diag.keepalive_fork_score, diag.keepalive_hash_tip_lo32);
        }
        // Do NOT stop workers based on keepalive fork_score alone.
    }

    // Age-based warning: 480s gives operators a 120s (2-minute) window before the 600s emergency fires.
    // Both channels use the same threshold — in the push-driven protocol the node pushes
    // on every unified tip advance (~18s apart via hash blocks), so 480s without a push
    // is unusual for either channel.
    // Proactively request a fresh template at the warning threshold so the age clock resets
    // before the 600s emergency fires.  Workers continue mining on the same height in the
    // meantime; only the timestamp is refreshed.  retry_template_request(false) is non-forced
    // so it respects the can_request_get_block() session gate and hashPrevBlock mismatch backoff.
    if (template_age > protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS &&
        template_age <= protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {
        m_logger->warn("[Worker_manager] ⚠️  {} template age {}s (warning threshold {}s, emergency {}s)",
            channel_name, template_age,
            protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS,
            protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS);
        m_logger->warn("[Worker_manager]    No push received for {}s — requesting proactive template refresh", template_age);
        retry_template_request(false);
    }

    // Age-based emergency (600s) — dead-connection detector for both channels.
    //
    // In the push-driven era the node pushes a fresh template within ~2s of every unified
    // tip advance.  Even during long Prime blocks, hash blocks keep advancing the unified
    // chain every ~18s, so a push should arrive well within 600s.
    //
    // If template_age > 600s the connection is almost certainly dead (missed push).
    // We then check HeightTracker to distinguish the two sub-cases for logging:
    //   • chain advanced  → push missed while chain moved  (clear emergency)
    //   • chain unchanged → push missed, chain stuck or truly no advance yet
    //     Either way the connection needs recovery — do NOT silently loop forever.
    if (template_age > protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {

        // Bug D fix: During an active recovery epoch, the miner is already waiting for a
        // fresh GET_BLOCK response.  Discarding the template now makes recovery self-defeating:
        // we'd have no template AND no recovery in progress simultaneously (doom-loop).
        // Suppress the hard emergency discard while recovery is pending; the recovery window
        // escalation logic (above) handles escalation if the window expires without a template.
        if (is_recovery_active()) {
            m_logger->debug("[Worker_manager] Emergency aging ({}s) suppressed during active recovery (epoch {})",
                            template_age, m_epoch_coordinator->recovery_epoch());
            // Resend GET_BLOCK (non-force: respects RECOVERY_RESEND_INTERVAL_SECONDS rate-limit)
            // so recovery keeps making progress without escalating to hard stop/restart.
            retry_template_request(false);
            return;
        }

        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
        bool chain_advanced = ht_snap.is_template_stale();

        // If a push notification was received recently, the TCP session is
        // demonstrably alive — defer the hard recovery to avoid spurious stops
        // during slow-block scenarios (e.g. long Prime blocks).
        // PUSH is the sole authoritative signal; keepalive ACK is not used here.
        bool recent_push = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{}) &&
            (std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ht_snap.last_push_notification_at).count() < PUSH_ALIVE_THRESHOLD_SECONDS);
        if (recent_push && !chain_advanced) {
            auto since_push_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - ht_snap.last_push_notification_at).count();
            m_logger->warn("[Worker_manager] EMERGENCY deferred: push notification is recent ({}s ago) — "
                           "connection alive, awaiting fresh template",
                           since_push_s);
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
            // but 600s without any hash-block push is still a dead-connection signal.
            m_logger->error("[Worker_manager] ❌ EMERGENCY ({} channel): template {}s old — no push received",
                            channel_name, template_age);
            m_logger->error("[Worker_manager]    channel_height {} / channel_target {} (chain not yet advanced in tracker)",
                            ht_snap.channel_height, ht_snap.channel_target);
            if (channel == mining::CHANNEL_PRIME) {
                m_logger->error("[Worker_manager]    Prime blocks are long, but 600s without ANY push (hash or prime) indicates a dead connection");
            }
            m_logger->error("[Worker_manager]    Forcing hard recovery (discard + stop + retry)");
        }

        template_interface->discard_template("Emergency: age " + std::to_string(template_age) +
                                             "s exceeded " + std::to_string(protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) + "s limit");
        stop_all_workers();
        // Keep degraded mode authoritative here: workers are recreated just-in-time by the
        // template feed path once a valid replacement template actually arrives.
        retry_template_request(true);
    }
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
