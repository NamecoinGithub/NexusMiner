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
#include <deque>

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

    // Keepalive ACK guard: if an ACK was received within this many seconds of the
    // emergency timeout, the TCP connection is demonstrably alive and we defer the
    // hard recovery to avoid spurious stops during slow-block scenarios.
    // Aligned with KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS so a recent ACK also
    // covers the full stale window; prevents spurious reconnects on slow nodes.
    constexpr int64_t KEEPALIVE_ACK_RECENT_THRESHOLD_SECONDS = 300;

    // Colin agent: maximum acceptable seconds between keepalive ACK responses.
    // If no ACK is received for this long, the node may have dropped the session.
    constexpr int64_t KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS = 300;

    // Two-signal liveness model: secondary push-notification recency threshold.
    // Aligned with KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS: if a push notification
    // (PRIME/HASH_BLOCK_AVAILABLE) was received within this window, the TCP session
    // is demonstrably alive and authenticated regardless of keepalive ACK silence.
    // Only force a hard TCP reconnect when BOTH signals are stale.
    constexpr int64_t PUSH_ALIVE_THRESHOLD_SECONDS = protocol::ProtocolConstants::PUSH_LIVENESS_THRESHOLD_SECONDS;

    // Fix A: push-alive guard in retry_connect() uses a much shorter window (30s).
    // A push received in the last 30s proves the TCP connection is alive RIGHT NOW.
    // A push received 5 minutes ago proves nothing about current TCP state and must
    // not suppress a TCP reconnect — that causes the doom loop.
    constexpr int64_t RETRY_CONNECT_PUSH_LIVE_SECONDS = 30;

    // Aggressive secondary reconnect delay during degraded mode.
    constexpr int64_t PROACTIVE_GET_HEIGHT_MIN_INTERVAL_SECONDS = 30;
    constexpr int64_t FORCED_RETRY_INTERVAL_MS = 1000;
    constexpr int64_t FORCED_RETRY_JITTER_MIN_MS = 100;
    constexpr int64_t FORCED_RETRY_JITTER_MAX_MS = 250;
    constexpr int64_t FORCED_RETRY_WINDOW_SECONDS = 60;
    constexpr size_t MAX_FORCED_BURST_PER_60S = 25;

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

                // Clear soft-pause: a fresh template has arrived, so
                // submissions are safe again.  Cleared unconditionally
                // (cheap no-op when already false).
                m_template_withheld = false;
                
                // ═══════════════════════════════════════════════════════════════
                // Recovery state is cleared AFTER successful template distribution
                // (see workers_fed > 0 branch below). Do not clear here — we must
                // confirm workers actually received the template first.
                // ═══════════════════════════════════════════════════════════════

                // Bug 1 fix: In degraded mode, workers may have been stopped and reset
                // by stop_all_workers().  Restart them now so set_block() below actually
                // starts mining threads; without this the template is silently dropped and
                // workers_fed falsely reads 0 keeping the miner in a doom loop.
                size_t workers_fed = 0;
                {
                    std::lock_guard<std::mutex> lock(m_worker_mutex);
                    if (m_degraded_mode && !m_recovery_workers_spawned && m_workers.empty()) {
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
                                solo_protocol->mark_authoritative_soft_refresh(soft_refresh_reason);
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
                    // AFTER distribution so we only exit degraded mode when workers actually
                    // received the template (not merely on template arrival).
                    if (m_recovery_pending) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - m_recovery_started_at).count();
                        m_logger->info("[Worker_manager] Recovery complete — epoch {} ({}s elapsed): "
                                       "fresh template distributed, workers resumed mining",
                                       m_recovery_epoch, elapsed);
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
                bool was_pending = m_recovery_pending;
                mark_recovery_initiated("push_staleness");

                if (!was_pending) {
                    // CORRECT: Stop workers immediately — don't mine stale data.
                    // Workers will restart when fresh template arrives.
                    m_logger->warn("[Worker_manager] Recovery: STOPPING workers immediately (template stale, awaiting fresh template)");
                    stop_all_workers();
                }

                // Request a fresh template
                retry_template_request(true);
            }
        );
        m_logger->info("[Worker_manager] Recovery handler registered");

        m_primary_node_session->set_soft_refresh_requested_handler(
            [this]() {
                bool had_pending = m_recovery_pending;
                mark_soft_refresh_requested("same_height_push_tip_replacement");

                if (!had_pending) {
                    m_logger->info("[Worker_manager] Same-height tip replacement — withholding submissions while fresh template is fetched");
                } else {
                    m_logger->info("[Worker_manager] Soft refresh already pending — keeping template withheld until replacement arrives");
                }
            }
        );
        m_logger->info("[Worker_manager] Soft-refresh handler registered");

        /* ========== REGISTER SESSION EXPIRED HANDLER ========== */
        /* Called by Solo when SESSION_EXPIRED opcode is received from the node.     */
        /* The TCP connection is still alive — we must re-authenticate in-band       */
        /* using login() on the existing connection, NOT reset() which tears down    */
        /* the TCP connection. Uses existing session auth backoff infrastructure.    */
        m_primary_node_session->set_session_expired_handler(
            [this]() {
                if (m_reconnect_in_progress || (m_recovery_pending && m_recovery_epoch > 0)) {
                    m_logger->warn("[Worker_manager] Session EXPIRED ignored: reconnect/recovery already in progress "
                                   "(reconnect_in_progress={}, recovery_pending={}, recovery_epoch={})",
                                   m_reconnect_in_progress,
                                   m_recovery_pending,
                                   m_recovery_epoch);
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
                if (m_degraded_mode || m_recovery_pending) {
                    m_logger->info("[Worker_manager] Re-authentication SUCCESS — "
                                   "requesting fresh template to exit degraded mode");
                    // Reset m_degraded_since so the escape ladder timer restarts cleanly
                    // for this new authenticated session (avoids Stage 3 immediately firing).
                    m_degraded_since = {};
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

const char* Worker_manager::suppression_reason_name(GetBlockSuppressionReason reason)
{
    switch (reason) {
        case GetBlockSuppressionReason::NONE: return "NONE";
        case GetBlockSuppressionReason::DUPLICATE_WINDOW: return "DUPLICATE_WINDOW";
        case GetBlockSuppressionReason::REQUEST_WORK_EMPTY: return "REQUEST_WORK_EMPTY";
        case GetBlockSuppressionReason::UNAUTHENTICATED: return "UNAUTHENTICATED";
        case GetBlockSuppressionReason::BACKPRESSURE: return "BACKPRESSURE";
        case GetBlockSuppressionReason::RATE_LIMIT_LOCAL: return "RATE_LIMIT_LOCAL";
        case GetBlockSuppressionReason::COUNT: return "COUNT";
    }
    return "UNKNOWN";
}

bool Worker_manager::request_get_height_probe(const std::shared_ptr<protocol::Solo>& solo_protocol,
                                              const char* reason)
{
    const char* probe_reason = reason ? reason : "unknown";

    if (!m_primary_node_session || !m_primary_node_session->is_authenticated() || !solo_protocol) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    if (m_last_proactive_get_height_at != std::chrono::steady_clock::time_point{}) {
        const auto since_last_probe_s = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_last_proactive_get_height_at).count();
        if (since_last_probe_s < PROACTIVE_GET_HEIGHT_MIN_INTERVAL_SECONDS) {
            m_logger->info("[Worker_manager] GET_HEIGHT probe suppressed for {} — {}s since last probe (min={}s)",
                           probe_reason,
                           since_last_probe_s,
                           PROACTIVE_GET_HEIGHT_MIN_INTERVAL_SECONDS);
            return false;
        }
    }

    auto pkt = solo_protocol->send_get_height();
    if (!pkt || pkt->empty()) {
        m_logger->info("[Worker_manager] GET_HEIGHT probe unavailable for {} — auth/dedup guard still active",
                       probe_reason);
        return false;
    }

    m_primary_node_session->transmit(pkt);
    m_last_proactive_get_height_at = now;
    m_logger->info("[Worker_manager] GET_HEIGHT probe sent for {} — awaiting BLOCK_HEIGHT cross-check",
                   probe_reason);
    return true;
}

void Worker_manager::prune_forced_retry_window(std::chrono::steady_clock::time_point now)
{
    while (!m_forced_retry_send_timestamps.empty()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - m_forced_retry_send_timestamps.front()).count();
        if (age <= FORCED_RETRY_WINDOW_SECONDS) {
            break;
        }
        m_forced_retry_send_timestamps.pop_front();
    }
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
    return (template_interface && template_interface->has_ready_template());
}

bool Worker_manager::can_send_forced_retry(std::chrono::steady_clock::time_point now)
{
    prune_forced_retry_window(now);
    if (m_forced_retry_send_timestamps.size() >= MAX_FORCED_BURST_PER_60S) {
        return false;
    }
    if (m_next_forced_retry_due != std::chrono::steady_clock::time_point{} && now < m_next_forced_retry_due) {
        return false;
    }
    return true;
}

void Worker_manager::log_get_block_decision(bool sent,
                                            bool forced_retry,
                                            GetBlockSuppressionReason reason,
                                            const char* context)
{
    m_last_get_block_suppression_reason = reason;
    if (sent) {
        ++m_get_block_sent_total;
        if (forced_retry) {
            ++m_get_block_forced_retry_total;
        }
        m_logger->info("[Worker_manager] GET_BLOCK decision: action=sent context={} forced_retry={} "
                       "get_block_sent_total={} get_block_forced_retry_total={}",
                       context ? context : "unknown",
                       forced_retry ? "true" : "false",
                       m_get_block_sent_total,
                       m_get_block_forced_retry_total);
        return;
    }

    const auto idx = static_cast<size_t>(reason);
    if (idx < m_get_block_suppressed_total.size()) {
        ++m_get_block_suppressed_total[idx];
    }
    m_logger->warn("[Worker_manager] GET_BLOCK decision: action=suppressed context={} forced_retry={} "
                   "reason={} get_block_suppressed_total{{reason={}}}={}",
                   context ? context : "unknown",
                   forced_retry ? "true" : "false",
                   suppression_reason_name(reason),
                   suppression_reason_name(reason),
                   (idx < m_get_block_suppressed_total.size()) ? m_get_block_suppressed_total[idx] : 0ULL);
}

void Worker_manager::schedule_forced_recovery_retry(const char* trigger_reason)
{
    if (!m_io_context || !m_degraded_mode || !m_recovery_pending) {
        return;
    }
    if (m_forced_retry_timer_pending) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto delay_ms = FORCED_RETRY_INTERVAL_MS + next_forced_retry_jitter_ms();
    auto due = now + std::chrono::milliseconds(delay_ms);
    if (m_next_forced_retry_due != std::chrono::steady_clock::time_point{} && due < m_next_forced_retry_due) {
        due = m_next_forced_retry_due;
    }

    auto wait_ms = std::max<int64_t>(
        1,
        std::chrono::duration_cast<std::chrono::milliseconds>(due - now).count());
    m_next_forced_retry_due = due;
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
        if (!self->m_degraded_mode || !self->m_recovery_pending || token != self->m_forced_retry_timer_token) {
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
            if (solo_protocol_ptr) {
                // Note: timer_manager needs to be updated to work with NodeSession
                // For now, we'll skip this timer - it's disabled by default anyway
                self->m_logger->info("[Solo Poll] GET_ROUND timer disabled (push notifications are primary)");
            }
        }

        // Start GET_HEIGHT timer: sends GET_HEIGHT every 30s as primary height shadow source
        constexpr uint16_t GET_HEIGHT_TIMER_INTERVAL = 30;
        if (!self->m_get_height_timer_started)
        {
            self->m_get_height_timer_started = true;
            self->m_timer_manager.start_get_height_timer(GET_HEIGHT_TIMER_INTERVAL, self);
            self->m_logger->info("[Worker_manager] GET_HEIGHT timer started ({}s interval, primary height shadow)",
                GET_HEIGHT_TIMER_INTERVAL);
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

                // Wire up ChannelHeightShadowTracker (GET_HEIGHT primary + keepalive secondary freshness)
                self->m_colin_agent->set_shadow_source(
                    [weak_proto]() -> nexusminer::protocol::ChannelHeightShadowTracker::Snapshot {
                        auto proto = weak_proto.lock();
                        if (!proto) return {};
                        return proto->get_channel_shadow_snapshot();
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
    // Soft-pause guard: suppress submissions while the template is withheld
    // (push_staleness recovery in progress — workers keep running but solutions
    // found on the stale template must not be sent to the node).
    if (m_template_withheld) {
        m_logger->info("[Worker_manager] Submission suppressed — template withheld (soft-pause)");
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

    bool degraded    = m_degraded_mode;
    bool workers_run = !m_degraded_mode && !m_workers.empty();

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

void Worker_manager::send_get_height_if_due()
{
    // Called by the 30-second GET_HEIGHT timer.  Sends GET_HEIGHT on the live
    // authenticated lane.  The node responds with BLOCK_HEIGHT which is ingested
    // by Solo as the primary unified-height shadow source for cross-check.
    if (!m_primary_node_session || !m_primary_node_session->is_authenticated())
        return;

    auto solo_protocol = m_primary_node_session->get_primary_protocol();
    if (!solo_protocol)
        return;

    auto pkt = solo_protocol->send_get_height();
    if (pkt && !pkt->empty())
    {
        m_primary_node_session->transmit(pkt);
        m_logger->debug("[Worker_manager] GET_HEIGHT sent (primary shadow poll)");
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
    m_next_forced_retry_due = {};
    m_forced_retry_send_timestamps.clear();
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_forced_retry_timer) {
        m_forced_retry_timer->cancel();
    }
    m_last_get_block_suppression_reason = GetBlockSuppressionReason::NONE;
    m_logger->warn("[Worker_manager] ⚑ RECOVERY INITIATED — epoch {} (reason: {})",
                   m_recovery_epoch, reason ? reason : "unknown");
    m_logger->warn("[Worker_manager]   Health monitor will NOT stop workers during channel recovery window");
}

void Worker_manager::mark_soft_refresh_requested(const char* reason)
{
    auto now = std::chrono::steady_clock::now();
    m_template_withheld = true;
    if (m_recovery_pending) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_recovery_started_at).count();
        m_logger->info("[Worker_manager] Soft refresh already pending (epoch {}, {}s elapsed, reason: {})",
                       m_recovery_epoch, elapsed, reason ? reason : "soft refresh requested");
        return;
    }

    ++m_recovery_epoch;
    m_recovery_pending = true;
    m_recovery_started_at = now;
    m_recovery_last_get_block_sent_at = {};
    m_recovery_last_get_block_transmitted_at = {};
    m_recovery_get_block_transmitted = false;
    m_next_forced_retry_due = {};
    m_forced_retry_send_timestamps.clear();
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_forced_retry_timer) {
        m_forced_retry_timer->cancel();
    }
    m_last_get_block_suppression_reason = GetBlockSuppressionReason::NONE;
    m_logger->info("[Worker_manager] Template refresh requested — epoch {} (reason: {})",
                   m_recovery_epoch, reason ? reason : "soft refresh requested");
    m_logger->info("[Worker_manager]   Workers keep running; only submissions are withheld during the replacement-template window");
}

void Worker_manager::restart_recovery_window(const char* reason)
{
    const bool had_pending_recovery = m_recovery_pending;
    const bool had_forced_retry_timer = m_forced_retry_timer_pending;
    int64_t elapsed_s = 0;
    if (had_pending_recovery && m_recovery_started_at != std::chrono::steady_clock::time_point{}) {
        elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_recovery_started_at).count();
    }

    m_recovery_pending = false;
    m_recovery_started_at = {};
    m_recovery_last_get_block_sent_at = {};
    m_recovery_last_get_block_transmitted_at = {};
    m_recovery_get_block_transmitted = false;
    m_next_forced_retry_due = {};
    m_forced_retry_send_timestamps.clear();
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_forced_retry_timer) {
        m_forced_retry_timer->cancel();
    }
    m_last_get_block_suppression_reason = GetBlockSuppressionReason::NONE;
    m_last_escalation_at = {};

    if (had_pending_recovery || had_forced_retry_timer) {
        m_logger->info("[Worker_manager] Restarting recovery window after {} "
                       "(prior_epoch={} prior_elapsed={}s degraded_mode={})",
                       reason ? reason : "unknown",
                       m_recovery_epoch,
                       elapsed_s,
                       m_degraded_mode ? "true" : "false");
    }
}

void Worker_manager::clear_recovery_state()
{
    if (!m_degraded_mode && !m_recovery_pending)
        return;  // Nothing to clear

    auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (m_degraded_mode && !has_valid_template_available(solo_protocol)) {
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

    m_logger->info("[Worker_manager] Clearing recovery state — exiting degraded mode");
    auto now = std::chrono::steady_clock::now();
    if (m_degraded_since != std::chrono::steady_clock::time_point{}) {
        auto elapsed_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(now - m_degraded_since).count());
        m_time_in_degraded_ms += elapsed_ms;
    }
    if (m_degraded_mode) {
        ++m_degraded_exit_total;
    }
    m_degraded_mode = false;
    m_recovery_pending = false;
    m_template_withheld = false;  // Clear any residual soft-pause flag (defensive)
    m_recovery_epoch = 0;
    m_recovery_started_at = {};
    m_recovery_last_get_block_sent_at = {};
    m_recovery_last_get_block_transmitted_at = {};
    m_recovery_get_block_transmitted = false;
    m_next_forced_retry_due = {};
    m_forced_retry_send_timestamps.clear();
    m_forced_retry_timer_pending = false;
    ++m_forced_retry_timer_token;
    if (m_forced_retry_timer) {
        m_forced_retry_timer->cancel();
    }
    m_last_get_block_suppression_reason = GetBlockSuppressionReason::NONE;
    m_degraded_since = {};  // Clear escape-ladder timer; next outage will re-anchor it
    // Note: m_recovery_workers_spawned is intentionally NOT reset here.
    // It is only reset in stop_all_workers() which actually destroys workers,
    // preventing a mid-recovery clear_recovery_state() call (e.g. from a
    // different epoch's template feed) from allowing duplicate worker creation.

    auto global_stats = m_stats_collector->get_global_stats();
    global_stats.m_degraded_mode = false;
    m_stats_collector->update_global_stats(global_stats);
    m_last_escalation_at = {};

    m_logger->info("[Worker_manager] Recovery state cleared — degraded_exit_count={} cumulative_degraded_time_ms={}",
                   m_degraded_exit_total, m_time_in_degraded_ms);

    // Reset start time so GISPS/hashrate calculation excludes the degraded-mode idle period
    m_stats_collector->reset_start_time();
}

void Worker_manager::stop_all_workers()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);

    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    m_logger->warn("[Worker_manager] ⚠️  STOPPING ALL WORKERS (DEGRADED MODE)");
    m_logger->warn("[Worker_manager] ════════════════════════════════════════");
    
    // Set degraded mode flag
    bool first_entry = !m_degraded_mode;
    m_degraded_mode = true;
    m_template_withheld = false;  // Full stop supersedes soft-pause
    if (auto solo_protocol = m_primary_node_session ? m_primary_node_session->get_primary_protocol() : nullptr) {
        solo_protocol->mark_authoritative_recovery_required("workers_stopped_waiting_for_valid_template");
    }

    // Record when degraded mode was first entered (only on first entry — not overwritten
    // by subsequent stop_all_workers() calls within the same outage, so the escape ladder
    // measures wall-clock time from the true start of the outage).
    if (m_degraded_since == std::chrono::steady_clock::time_point{}) {
        m_degraded_since = std::chrono::steady_clock::now();
    }
    if (first_entry) {
        ++m_degraded_enter_total;
    }
    
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
        log_get_block_decision(false, bForce, GetBlockSuppressionReason::BACKPRESSURE, "missing_authenticated_session");
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
        log_get_block_decision(false, bForce, GetBlockSuppressionReason::BACKPRESSURE, "no_protocol");
        m_logger->error("[Worker_manager] Failed to get protocol from NodeSession");
        return;
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
        log_get_block_decision(false, bForce, GetBlockSuppressionReason::UNAUTHENTICATED, "solo_not_authenticated");
        m_logger->info("[Worker_manager] GET_BLOCK deferred — not yet authenticated (auth in progress); "
                       "health monitor will retry when session is established");
        return;
    }

    // Early-exit if primary TCP connection is down — request_work() would silently
    // return nullptr in this case (NodeSession checks m_primary_connected before
    // calling get_work).  Detect it here so we can log the real reason and trigger
    // reconnect immediately instead of burning a recovery tick.
    if (!m_primary_node_session->is_primary_connected()) {
        log_get_block_decision(false, bForce, GetBlockSuppressionReason::BACKPRESSURE, "primary_disconnected");
        m_logger->warn("[Worker_manager] GET_BLOCK deferred — primary TCP connection is not established; "
                       "initiating reconnect");
        retry_connect(m_primary_endpoint);
        return;
    }

    bool forced_lane = bForce && m_degraded_mode && solo_protocol->is_authenticated() && no_valid_template;
    if (forced_lane && !can_send_forced_retry(now)) {
        log_get_block_decision(false, true, GetBlockSuppressionReason::RATE_LIMIT_LOCAL, "forced_lane_rate_limit");
        schedule_forced_recovery_retry("forced_lane_rate_limit");
        return;
    }

    // Request template via NodeSession
    m_logger->info("[Worker_manager] Requesting fresh template via NodeSession (forced_lane={})",
                   forced_lane ? "true" : "false");
    auto work_payload = m_primary_node_session->request_work(forced_lane);
    if (work_payload && !work_payload->empty()) {
        m_primary_node_session->transmit(work_payload);
        m_recovery_last_get_block_sent_at = std::chrono::steady_clock::now();
        m_recovery_last_get_block_transmitted_at = m_recovery_last_get_block_sent_at;
        m_recovery_get_block_transmitted = true;
        if (forced_lane) {
            m_forced_retry_send_timestamps.push_back(m_recovery_last_get_block_sent_at);
            m_next_forced_retry_due = m_recovery_last_get_block_sent_at +
                std::chrono::milliseconds(FORCED_RETRY_INTERVAL_MS + next_forced_retry_jitter_ms());
            prune_forced_retry_window(m_recovery_last_get_block_sent_at);
        }
        log_get_block_decision(true, forced_lane, GetBlockSuppressionReason::NONE, "request_work_sent");
        m_logger->info("[Worker_manager] → GET_BLOCK sent (recovery epoch {})", m_recovery_epoch);
    } else {
        GetBlockSuppressionReason reason = GetBlockSuppressionReason::REQUEST_WORK_EMPTY;
        auto last_status = solo_protocol->get_last_get_block_request_status();
        switch (last_status) {
            case protocol::Solo::GetBlockRequestStatus::DUPLICATE_WINDOW:
                reason = GetBlockSuppressionReason::DUPLICATE_WINDOW;
                break;
            case protocol::Solo::GetBlockRequestStatus::UNAUTHENTICATED:
            case protocol::Solo::GetBlockRequestStatus::SESSION_INVALID:
                reason = GetBlockSuppressionReason::UNAUTHENTICATED;
                break;
            case protocol::Solo::GetBlockRequestStatus::REWARD_NOT_BOUND:
            case protocol::Solo::GetBlockRequestStatus::BUILD_EMPTY:
            case protocol::Solo::GetBlockRequestStatus::NONE:
            case protocol::Solo::GetBlockRequestStatus::SENT:
                reason = GetBlockSuppressionReason::REQUEST_WORK_EMPTY;
                break;
        }
        log_get_block_decision(false, forced_lane, reason, "request_work_empty");
        // request_work() returned empty despite passing all guards above.
        // Most likely cause: 100ms GET_BLOCK dedup guard in Solo::get_work() or
        // transient reward-binding gap.  The recovery timer will retry at the next tick.
        m_logger->warn("[Worker_manager]   GET_BLOCK not sent — request_work() returned empty "
                       "(authenticated={}, primary_connected={}, see Solo logs for specific suppression reason)",
                       solo_protocol->is_authenticated(),
                       m_primary_node_session->is_primary_connected());
        if (m_degraded_mode && solo_protocol->is_authenticated() && no_valid_template) {
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

    // Fix B: Guard against a stalled reconnect. If m_reconnect_in_progress has been true
    // for more than 60 seconds, the TCP connect attempt itself has likely failed silently.
    // Clear the flag so the escape ladder is not indefinitely suppressed.
    if (m_reconnect_in_progress) {
        if (m_reconnect_started_at == std::chrono::steady_clock::time_point{}) {
            // m_reconnect_started_at should always be set alongside m_reconnect_in_progress.
            // If it is unset here, that indicates a logic error — log and recover defensively.
            m_logger->warn("[Worker_manager] m_reconnect_in_progress=true but m_reconnect_started_at unset — "
                           "logic error detected; stamping now to allow timeout guard to function");
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

    if (auto* session_manager = solo_protocol->get_session_manager()) {
        const auto session_snapshot = session_manager->get_runtime_snapshot();
        if (session_snapshot.recovery_state == protocol::SessionManager::RecoveryState::SOFT_REFRESH_REQUESTED) {
            if (!m_recovery_pending) {
                m_logger->info("[Worker_manager] Syncing local recovery state from authoritative soft-refresh state");
                m_recovery_pending = true;
            }
            if (m_recovery_started_at == std::chrono::steady_clock::time_point{}) {
                m_recovery_started_at = std::chrono::steady_clock::now();
            }
            m_template_withheld = true;
        }
    }

    uint8_t channel = template_interface->get_channel();
    std::string channel_name = (channel == mining::CHANNEL_PRIME) ? "Prime" : "Hash";
    const int64_t effective_recovery_window =
        (channel == mining::CHANNEL_PRIME) ? RECOVERY_WINDOW_SECONDS_PRIME
                                           : RECOVERY_WINDOW_SECONDS_HASH;
    const bool has_valid_template = template_interface->has_ready_template();

    if (m_template_withheld && m_recovery_pending && !m_degraded_mode) {
        // Belt-and-suspenders: if a valid template was installed during the pending
        // window (e.g. via a BLOCK_DATA path that raced with the health monitor tick),
        // close out the recovery state immediately so we stop sending spurious GET_BLOCKs.
        // Normally clear_recovery_state() is called by the template feed handler after
        // workers are fed, but this guard catches the case where that path was skipped
        // (e.g. duplicate-feed suppression) while the template itself is still valid.
        if (has_valid_template) {
            m_logger->info("[Worker_manager] ✓ Valid template present during soft-refresh pending window "
                           "(epoch {}) — closing out recovery state",
                           m_recovery_epoch);
            clear_recovery_state();
            return;
        }

        auto now = std::chrono::steady_clock::now();
        if (m_recovery_started_at == std::chrono::steady_clock::time_point{}) {
            m_recovery_started_at = now;
        }
        auto recovery_elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_recovery_started_at).count();

        if (recovery_elapsed_s < effective_recovery_window) {
            bool first_send = (m_recovery_last_get_block_transmitted_at == std::chrono::steady_clock::time_point{});
            auto since_last_s = first_send ? recovery_elapsed_s
                : std::chrono::duration_cast<std::chrono::seconds>(
                      now - m_recovery_last_get_block_transmitted_at).count();

            if (first_send || since_last_s >= RECOVERY_RESEND_INTERVAL_SECONDS) {
                m_logger->info("[Worker_manager] ⟳ Template swap pending on {} channel (epoch {}, {}s elapsed, valid_template={}) — requesting replacement template",
                               channel_name,
                               m_recovery_epoch,
                               recovery_elapsed_s,
                               has_valid_template ? "yes" : "no");
                retry_template_request(true);
            } else {
                m_logger->info("[Worker_manager] ⧖ Template swap pending on {} channel (epoch {}, {}s elapsed, valid_template={}) — submissions withheld, next retry in {}s",
                               channel_name,
                               m_recovery_epoch,
                               recovery_elapsed_s,
                               has_valid_template ? "yes" : "no",
                               RECOVERY_RESEND_INTERVAL_SECONDS - since_last_s);
            }
            return;
        }

        m_logger->warn("[Worker_manager] ⚡ Template swap timeout on {} channel (epoch {}, {}s elapsed, valid_template={}) — escalating soft refresh into degraded mode",
                       channel_name,
                       m_recovery_epoch,
                       recovery_elapsed_s,
                       has_valid_template ? "yes" : "no");
        m_recovery_pending = false;
        // Compatibility note: retain the legacy reason label because existing
        // monitoring/log parsing may key off it, even though this timeout path
        // now covers broader soft-refresh stalls (including tip_moved refreshes).
        mark_recovery_initiated("same_height_soft_refresh_timeout");
        m_template_withheld = false;
        if (has_valid_template) {
            template_interface->discard_template("Soft refresh timeout: " + std::to_string(recovery_elapsed_s) +
                                                 "s > " + std::to_string(effective_recovery_window) + "s window");
        }
        stop_all_workers();
        retry_template_request(true);
        return;
    }

    if (!has_valid_template) {

        // In degraded mode with no valid template — apply escape ladder to prevent permanent lockout.
        if (m_degraded_mode) {
            auto now = std::chrono::steady_clock::now();
            auto ht_snap = solo_protocol->get_height_tracker_snapshot();

            // Belt-and-suspenders: ensure m_degraded_since is stamped even if stop_all_workers()
            // was somehow bypassed (e.g. direct m_degraded_mode = true assignment in tests).
            if (m_degraded_since == std::chrono::steady_clock::time_point{}) {
                m_degraded_since = now;
            }
            auto degraded_duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - m_degraded_since).count();

            // Compute liveness signals from HeightTracker snapshot.
            bool keepalive_ack_received = (ht_snap.last_keepalive_ack_at != std::chrono::steady_clock::time_point{});
            int64_t since_ack_s = keepalive_ack_received
                ? std::chrono::duration_cast<std::chrono::seconds>(now - ht_snap.last_keepalive_ack_at).count()
                : INT64_MAX;
            bool ack_recent = keepalive_ack_received && (since_ack_s <= KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS);

            // Use last_push_notification_at — set ONLY by OnPushNotification() (actual BLOCK_AVAILABLE opcodes).
            // last_height_update was formerly also updated by keepalive ACKs and GET_ROUND, making it
            // unsuitable for session liveness decisions. last_push_notification_at is the canonical
            // "is the node pushing to us?" signal for the escape ladder and retry_connect guard.
            bool push_received = (ht_snap.last_push_notification_at != std::chrono::steady_clock::time_point{});
            int64_t since_push_s = push_received
                ? std::chrono::duration_cast<std::chrono::seconds>(now - ht_snap.last_push_notification_at).count()
                : INT64_MAX;
            bool push_recent = push_received && (since_push_s <= PUSH_ALIVE_THRESHOLD_SECONDS);
            const bool auth_in_progress = solo_protocol->is_auth_in_progress();
            const bool auth_ready = solo_protocol->is_authenticated();
            const double auth_in_flight_s = auth_in_progress
                ? solo_protocol->auth_in_flight_seconds()
                : 0.0;
            const char* auth_state = auth_in_progress
                ? "IN_FLIGHT"
                : (auth_ready ? "AUTHENTICATED" : "NOT_AUTHENTICATED");

            // Diagnostic: log keepalive epoch alongside timestamps so future incidents can
            // identify split between session epoch and last-ack epoch without log scraping.
            m_logger->info("[Worker_manager] Degraded-mode liveness: epoch={} keepalive_ack={}s ago (recent={}) "
                           "push={}s ago (recent={}) auth_state={} auth_in_flight_s={:.1f}",
                           ht_snap.session_epoch,
                           keepalive_ack_received ? since_ack_s : static_cast<int64_t>(-1),
                           ack_recent ? "YES" : "NO",
                           push_received ? since_push_s : static_cast<int64_t>(-1),
                           push_recent ? "YES" : "NO",
                           auth_state,
                           auth_in_flight_s);

            // ── Hard limit: reconnect after DEGRADED_MODE_HARD_LIMIT_SECONDS ─────────────────
            // But only if push notifications are also stale — a recent push proves the TCP
            // connection is alive and the node is actively communicating. In that case,
            // escalate to a full in-band re-authentication instead of tearing down the live
            // session. A miner that is still degraded after 300s despite recent push traffic is
            // considered stalled; GET_BLOCK retries are no longer sufficient.
            const auto hard_limit_decision = protocol::SessionStatusPolicy::evaluate_degraded_session({
                degraded_duration,
                protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
                push_recent
            });
            if (hard_limit_decision.force_reauth) {
                m_logger->error("[Worker_manager] ⛔ DEGRADED MODE HARD LIMIT ({}s > {}s) — "
                               "{}; push received {}s ago, forcing full in-band re-auth instead of reconnect",
                               degraded_duration,
                               protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
                               hard_limit_decision.reason,
                               since_push_s);
                // Attempt full re-authentication on the existing TCP connection.
                // Even if local auth still says "authenticated", being degraded for >300s
                // while push traffic is alive means the session is stalled and must be
                // restarted cleanly rather than retried with GET_BLOCK alone.
                if (m_primary_node_session) {
                    auto primary_protocol = m_primary_node_session->get_primary_protocol();
                    if (primary_protocol) {
                        double in_flight_s = primary_protocol->auth_in_flight_seconds();
                        constexpr double AUTH_STALE_THRESHOLD_S = 10.0;
                        if (in_flight_s > 0.0 && in_flight_s <= AUTH_STALE_THRESHOLD_S) {
                            m_logger->info("[Worker_manager] Hard-limit full re-auth already in flight ({:.1f}s < {}s) — "
                                           "skipping duplicate login()",
                                           in_flight_s, AUTH_STALE_THRESHOLD_S);
                            return;
                        }
                        if (in_flight_s > AUTH_STALE_THRESHOLD_S) {
                            m_logger->warn("[Worker_manager] Hard-limit full re-auth in flight but stale ({:.1f}s > {}s) — "
                                           "resetting auth state before retry",
                                           in_flight_s, AUTH_STALE_THRESHOLD_S);
                        }
                        primary_protocol->reset_auth_state();
                        auto auth_payload = primary_protocol->login([weak_self = weak_from_this()](bool login_result) {
                            auto self = weak_self.lock();
                            if (!self) return;
                            if (!login_result) {
                                self->m_logger->error("[Worker_manager] Hard-limit re-auth login() failed");
                            } else {
                                self->m_logger->info("[Worker_manager] Hard-limit re-auth login() sent, "
                                                     "awaiting MINER_AUTH_RESULT");
                            }
                        });
                        if (auth_payload && !auth_payload->empty()) {
                            m_primary_node_session->transmit(auth_payload);
                        } else {
                            m_logger->error("[Worker_manager] Hard-limit re-auth: failed to generate payload");
                        }
                    }
                }
                return;
            }
            if (hard_limit_decision.force_reconnect) {
                m_logger->error("[Worker_manager] ⛔ DEGRADED MODE HARD LIMIT ({}s > {}s) — "
                               "{}; forcing full TCP reconnect "
                               "(last ACK {}s ago, last push {}s ago)",
                               degraded_duration, protocol::ProtocolConstants::DEGRADED_MODE_HARD_LIMIT_SECONDS,
                               hard_limit_decision.reason,
                               keepalive_ack_received ? since_ack_s : static_cast<int64_t>(-1),
                               push_received ? since_push_s : static_cast<int64_t>(-1));
                retry_connect(m_primary_endpoint);
                return;
            }

            // ── Stage 3 (>180s AND both signals stale): true dead connection ────────────────
            if (degraded_duration > protocol::ProtocolConstants::DEGRADED_MODE_STAGE3_SECONDS &&
                !ack_recent && !push_recent && m_primary_node_session)
            {
                m_logger->error("[Worker_manager] Stage 3 ESCALATION ({}s in degraded, both signals dead) — "
                               "forcing reconnect (last ACK {}s ago, last push {}s ago)",
                               degraded_duration,
                               keepalive_ack_received ? since_ack_s : static_cast<int64_t>(-1),
                               push_received ? since_push_s : static_cast<int64_t>(-1));
                retry_connect(m_primary_endpoint);
                return;
            }

            // ── Bug 1 fix: stale keepalive ACK but push is still arriving ────────────────────
            // The TCP session is demonstrably alive (push notifications proving authenticated
            // connection).  Do NOT tear down — just retry GET_BLOCK on the live session.
            if (keepalive_ack_received && since_ack_s > KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS && push_recent) {
                m_logger->warn("[Worker_manager] ⚠️  KEEPALIVE ACK STALE ({}s) but push received {}s ago — "
                               "TCP session alive, retrying template request (node-side responder silent)",
                               since_ack_s, since_push_s);
                retry_template_request(true);
                return;
            }

            // ── Stage 0 (fast path): both signals dead for > 90s and degraded > 30s ──────────
            // If neither ACK nor push has been received for 90+ seconds, the TCP connection
            // is almost certainly dead. Skip the Stage 1/2 ladder and reconnect immediately.
            // This cuts recovery time from up to 180s down to ~30s for clean disconnects.
            if (!ack_recent && !push_recent &&
                since_ack_s > protocol::ProtocolConstants::FAST_RECONNECT_SIGNAL_DEAD_SECONDS &&
                since_push_s > protocol::ProtocolConstants::FAST_RECONNECT_SIGNAL_DEAD_SECONDS &&
                degraded_duration > protocol::ProtocolConstants::FAST_RECONNECT_DEGRADED_SECONDS &&
                !m_reconnect_in_progress)
            {
                m_logger->error("[Worker_manager] Stage 0 FAST RECONNECT: both signals dead "
                                "(ACK {}s ago, push {}s ago, {}s degraded) — skipping ladder",
                                since_ack_s == INT64_MAX ? -1LL : since_ack_s,
                                since_push_s == INT64_MAX ? -1LL : since_push_s,
                                degraded_duration);
                retry_connect(m_primary_endpoint);
                return;
            }

            // ── Stage 2 (60s–180s, both signals stale): attempt in-band re-auth ─────────────
            if (degraded_duration > protocol::ProtocolConstants::DEGRADED_MODE_STAGE2_SECONDS &&
                !ack_recent && !push_recent && m_primary_node_session)
            {
                auto primary_protocol = m_primary_node_session->get_primary_protocol();
                if (primary_protocol) {
                    m_logger->warn("[Worker_manager] Stage 2 ({}s in degraded, both signals stale) — "
                                   "attempting in-band re-authentication via login()", degraded_duration);
                    auto auth_payload = primary_protocol->login([weak_self = weak_from_this()](bool login_result) {
                        auto self = weak_self.lock();
                        if (!self) return;
                        if (!login_result) {
                            self->m_logger->error("[Worker_manager] Stage 2 re-auth login() failed");
                        } else {
                            self->m_logger->info("[Worker_manager] Stage 2 re-auth login() sent, "
                                                 "awaiting MINER_AUTH_RESULT");
                        }
                    });
                    if (auth_payload && !auth_payload->empty()) {
                        m_primary_node_session->transmit(auth_payload);
                    } else {
                        m_logger->error("[Worker_manager] Stage 2 re-auth: failed to generate payload");
                    }
                }
            }

            // ── Stage 1 (< 60s) or Stage 2 fallback: retry GET_BLOCK and wait ───────────────
            m_logger->warn("[Worker_manager] ⚠️  DEGRADED MODE ({}s): no valid template — "
                           "retrying recovery request (stage {})",
                           degraded_duration,
                           degraded_duration > protocol::ProtocolConstants::DEGRADED_MODE_STAGE2_SECONDS ? 2 : 1);
            retry_template_request(true);
        }
        return;
    }

    // Get HeightTracker snapshot for staleness and age checks (single source of truth)
    auto ht_snap = solo_protocol->get_height_tracker_snapshot();
    uint64_t template_age = ht_snap.get_template_age_seconds();

    // ── Belt-and-suspenders guard ────────────────────────────────────────────
    // If a valid template exists but m_degraded_mode is still set (e.g. because
    // clear_recovery_state() was somehow bypassed), clear it now so the stats
    // printer stops showing "MINING STOPPED" and the health monitor doesn't
    // keep triggering spurious recoveries on every 30 s tick.
    //
    // IMPORTANT: only call clear_recovery_state() AFTER verifying workers actually
    // received the template. Clearing before confirmation resets m_degraded_since
    // and the escape ladder timer, preventing Stage 2/3/Hard-Limit from ever firing.
    if (m_degraded_mode) {
        m_logger->warn("[Worker_manager] ⚠️  Valid template exists but m_degraded_mode=true — clearing outdated degraded flag");
        bool has_alive_workers = false;
        bool should_refeed_template = false;
        {
            std::lock_guard<std::mutex> lock(m_worker_mutex);
            has_alive_workers = !m_workers.empty();
            if (!has_alive_workers) {
                // Workers are dead — restart them and re-feed the template.
                // Only clear recovery state if the template was successfully delivered.
                // If feed fails, keep degraded mode so the escape ladder can proceed.
                m_logger->info("[Worker_manager] Belt-and-suspenders: workers dead, restarting and re-feeding template");
                create_workers_locked();
                m_recovery_workers_spawned = !m_workers.empty();
                should_refeed_template = !m_workers.empty();
            }
        }
        if (has_alive_workers) {
            // Workers are alive and mining — just clear the stale degraded flag.
            // No need to restart workers or re-feed template — they are already mining.
            m_logger->info("[Worker_manager] Belt-and-suspenders: workers already alive, clearing stale degraded flag only");
            clear_recovery_state();
        } else if (should_refeed_template) {
            // Re-feed the template so the newly created workers receive it.
            bool fed = template_interface->feed_current_template(true);
            if (fed) {
                m_logger->info("[Worker_manager] ✅ Belt-and-suspenders recovery: template fed to workers — clearing degraded mode");
                clear_recovery_state();
            } else {
                m_logger->error("[Worker_manager] Belt-and-suspenders recovery FAILED: "
                                "workers created but template feed returned false — keeping degraded mode for escape ladder. "
                                "Check that workers are properly configured and the template interface has a registered feed handler.");
                // Do NOT call clear_recovery_state() — let the escape ladder proceed
            }
        } else {
            m_logger->error("[Worker_manager] Belt-and-suspenders recovery FAILED: worker recreation produced no workers");
        }
    }

    // Channel height-based staleness detection (primary check — HeightTracker is the single
    // source of truth).  Template is stale when channel_height >= channel_target (both non-zero).
    {
        if (ht_snap.is_template_stale()) {
            uint32_t blocks_behind = ht_snap.blocks_behind();

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

            // A single-block lag is the normal case on every fresh block: the miner is
            // still holding the template for the previous channel tip until the next
            // GET_BLOCK arrives. Request a refresh, but keep workers running.
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

            // ── Recovery state gate (doom-loop prevention) ───────────────────────────
            // mark_recovery_initiated is idempotent: if the push handler already set
            // m_recovery_pending (via m_recovery_handler callback), this is a no-op.
            // Otherwise it starts a new recovery epoch now.
            mark_recovery_initiated("health_monitor_channel_stale");

            auto now_ts = std::chrono::steady_clock::now();
            auto recovery_elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                now_ts - m_recovery_started_at).count();

            if (recovery_elapsed_s < effective_recovery_window) {
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
                        "(not authenticated?). Retrying...", recovery_elapsed_s);
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
            m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
            m_logger->warn("[Worker_manager] ⚡ RECOVERY TIMEOUT: {} epoch {} exceeded {}s window",
                channel_name, m_recovery_epoch, effective_recovery_window);
            m_logger->warn("[Worker_manager]    Elapsed: {}s (exceeded {}s recovery window)",
                recovery_elapsed_s, effective_recovery_window);
            m_logger->warn("[Worker_manager]    Escalating: discard stale template + stop workers + request fresh GET_BLOCK");
            m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
            m_recovery_pending = false;  // Reset so next staleness detection starts a fresh epoch
            m_template_withheld = false;  // Clear soft-pause — full escalation takes over
            template_interface->discard_template("Recovery timeout: " + std::to_string(recovery_elapsed_s) +
                                                 "s > " + std::to_string(effective_recovery_window) + "s window");
            stop_all_workers();
            // Workers are recreated just-in-time by the set_block_handler degraded-mode guard
            // when the recovery template arrives. Avoid eager restart and I/O-thread blocking.
            m_last_escalation_at = std::chrono::steady_clock::now();  // Change B: record escalation time
            // Recovery Tuning 3: Start a fresh epoch immediately so the next health-monitor tick
            // sees a clean recovery window clock — preventing immediate re-escalation.
            mark_recovery_initiated("escalation_hard_recovery");
            retry_template_request(true);
            return;
        }
    }

    // Unified tip movement without channel staleness is the normal cross-channel
    // refresh path: withhold submissions and fetch a replacement template first.
    // Do not let the HEIGHT_DRIFT hard-stop path bypass this softer recovery mode.
    const uint32_t verified_unified_height = ht_snap.verified_unified_height();
    if (ht_snap.is_tip_moved()) {
        bool had_pending = m_recovery_pending;
        mark_soft_refresh_requested("health_monitor_tip_moved");
        if (!had_pending) {
            m_logger->info("[Worker_manager] ⚡ Unified tip moved (template_unified_height {} -> unified_height {}) — requesting refresh without degraded-mode escalation",
                           ht_snap.template_unified_height, verified_unified_height);
        } else {
            m_logger->debug("[Worker_manager] Unified tip still ahead during soft refresh (template_unified_height {} -> unified_height {}, epoch {})",
                            ht_snap.template_unified_height, verified_unified_height, m_recovery_epoch);
        }
        retry_template_request(false);
        return;
    }

    // ── Unified height drift detection ──────────────────────────────────────
    // If HeightTracker's unified_height has advanced past the template's
    // block.nHeight by more than UNIFIED_DRIFT_THRESHOLD blocks, the template
    // is on a stale tip even if the channel height hasn't triggered
    // is_template_stale() (e.g. only other channels found blocks, or stale
    // BLOCK_DATA metadata regressed the tracker before OnTemplateMetadata fix).
    {
        auto ht_snap = solo_protocol->get_height_tracker_snapshot();
        uint32_t tmpl_height = template_interface->get_template_height();

        const uint32_t observed_unified_height = ht_snap.verified_unified_height();
        if (observed_unified_height > 0 && tmpl_height > 0 &&
            observed_unified_height > tmpl_height + protocol::ProtocolConstants::UNIFIED_DRIFT_THRESHOLD)
        {
            int32_t drift = static_cast<int32_t>(observed_unified_height) -
                            static_cast<int32_t>(tmpl_height);
            const auto shadow_snap = solo_protocol->get_channel_shadow_snapshot();
            const auto& cross_check = shadow_snap.cross_check;
            const auto active_shadow_source = cross_check.active_unified_source();
            const auto active_shadow_delta = cross_check.active_unified_delta();
            const uint32_t active_shadow_divergence = cross_check.active_unified_divergence();
            const bool shadow_tracker_confirms_divergence =
                cross_check.is_disagreement(protocol::ProtocolConstants::GET_HEIGHT_DIVERGENCE_TRIGGER_BLOCKS);

            if (shadow_tracker_confirms_divergence) {
                bool had_pending = m_recovery_pending;
                mark_soft_refresh_requested("height_drift_shadow_tracker_cross_check");
                m_logger->warn("[Worker_manager] ⚠️  HEIGHT_DRIFT cross-check confirmed: unified={} template.nHeight={} "
                               "canonical={} source={} shadow_unified={} (drift={} shadow_delta={} abs_divergence={}) — requesting non-blocking GET_BLOCK",
                               observed_unified_height,
                               tmpl_height,
                               shadow_snap.canonical.unified_height,
                               protocol::ChannelHeightShadowTracker::source_name(active_shadow_source),
                               shadow_snap.active_unified_height(),
                               drift,
                               active_shadow_delta,
                               active_shadow_divergence);
                if (!had_pending) {
                    retry_template_request(false);
                }
            } else {
                m_logger->warn("[Worker_manager] ⚠️  HEIGHT_DRIFT preflight: unified={} vs template.nHeight={} (drift={}) — "
                               "probing GET_HEIGHT before any degraded-mode escalation",
                               observed_unified_height,
                               tmpl_height,
                               drift);
                request_get_height_probe(solo_protocol, "height_drift_preflight");
            }
            return;
        }
    }

    // ── Fork / tip mismatch detection (DIAGNOSTIC ONLY) ──────────────────
    // If the keepalive ACK reports a non-zero fork_score AND the node's
    // hash_tip_lo32 differs from the template's hashPrevBlock lo32, log a
    // diagnostic warning.  Keepalive-derived fork_score is NOT authoritative
    // for mining decisions — only canonical hashPrevBlock changes (from
    // OnBlockDataReceived) trigger real fork recovery.
    //
    // Guard: only log when the keepalive ACK is fresh (received within
    // KEEPALIVE_ACK_STALE_THRESHOLD_SECONDS).  A stale keepalive means
    // hash_tip_lo32 is stale data — don't even warn on it.
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
    if (template_age > protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS &&
        template_age <= protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS) {
        m_logger->warn("[Worker_manager] ⚠️  {} template age {}s (warning threshold {}s, emergency {}s)",
            channel_name, template_age,
            protocol::ProtocolConstants::TEMPLATE_AGE_WARNING_SECONDS,
            protocol::ProtocolConstants::TEMPLATE_AGE_EMERGENCY_TIMEOUT_SECONDS);
        m_logger->warn("[Worker_manager]    No push received for {}s — connection may be degrading", template_age);
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
        if (m_recovery_pending) {
            m_logger->debug("[Worker_manager] Emergency aging ({}s) suppressed during active recovery (epoch {})",
                            template_age, m_recovery_epoch);
            // Resend GET_BLOCK (non-force: respects RECOVERY_RESEND_INTERVAL_SECONDS rate-limit)
            // so recovery keeps making progress without escalating to hard stop/restart.
            retry_template_request(false);
            return;
        }

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
