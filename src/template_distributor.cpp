#include "template_distributor.hpp"
#include "worker_manager.hpp"
#include "Util/include/weak_ptr_utils.hpp"
#include "LLP/block.hpp"
#include "worker/worker.hpp"
#include "protocol/solo.hpp"
#include "protocol/channel_utils.hpp"
#include <spdlog/spdlog.h>

namespace nexusminer
{

void TemplateDistributor::on_template_received(
    const ::LLP::CBlock& block,
    uint32_t nBits,
    std::shared_ptr<Worker_manager> self)
{
    std::size_t worker_count = 0;
    {
        std::lock_guard<std::mutex> lock(self->m_worker_mutex);
        worker_count = self->m_workers.size();
    }
    self->m_logger->info("[Worker_manager] ═══════════════════════════════════════");
    self->m_logger->info("[Worker_manager] DISTRIBUTING TEMPLATE TO {} WORKERS", worker_count);
    self->m_logger->info("[Worker_manager]   Height:     {}", block.nHeight);
    self->m_logger->info("[Worker_manager]   Channel:    {} ({})", 
                  block.nChannel,
                  (block.nChannel == 1) ? "prime" : "hash");
    self->m_logger->info("[Worker_manager]   Difficulty: 0x{:08x}", nBits);
    self->m_logger->info("[Worker_manager]   Merkle:     {}...",
                  block.hashMerkleRoot.ToString().substr(0, 16));
    self->m_logger->info("[Worker_manager]   PrevHash:   {}...",
                  block.hashPrevBlock.ToString().substr(0, 20));
    self->m_logger->info("[Worker_manager] ═══════════════════════════════════════");

    // Note: Template feed debounce is now handled in MiningTemplateInterface
    // (unified dedup gate). This handler is only called after the template
    // passes the debounce check, so no additional checking is needed here.

    // Update mined-block cache confirmations based on new chain height.
    self->m_mined_block_cache.update_confirmations(block.nHeight);

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
        std::lock_guard<std::mutex> lock(self->m_worker_mutex);
        if (self->is_degraded() && !self->m_recovery_workers_spawned && self->m_workers.empty()) {
            self->m_logger->info("[Worker_manager] Degraded mode: restarting workers before feeding recovery template");
            self->create_workers_locked();
            self->m_recovery_workers_spawned = !self->m_workers.empty();  // set AFTER success for exception safety
        }

        /* Safety check - workers should be created by now */
        if (self->m_workers.empty()) {
            self->m_logger->error("[Worker_manager] CRITICAL: No workers available for mining!");
            self->m_logger->error("[Worker_manager]   Workers may not be initialized yet");
            self->m_logger->error("[Worker_manager]   Template will be lost - mining cannot start");
            return;
        }

        /* Create shared WorkPackage once for all workers */
        auto work_package = std::make_shared<WorkPackage>(block, nBits);
        self->m_logger->debug("[Worker_manager] Created shared WorkPackage (block height: {}, nBits: 0x{:08x})",
                        block.nHeight, nBits);

#ifdef PRIME_ENABLED
        /* Optimization: For prime channel, precompute base hash (Skein+Keccak) once
         * instead of having each worker compute it independently */
        if (block.nChannel == 1) {  // Prime channel
            Block_data temp_block{block};
            work_package->set_prime_base_hash(temp_block.GetPrimeBaseHash());

            self->m_logger->debug("[Worker_manager] Precomputed prime base hash for all workers");
        }
#endif

        /* Distribute template to all worker threads */
        std::weak_ptr<Worker_manager> weak_mgr = self;
        for (size_t i = 0; i < self->m_workers.size(); ++i) {
            auto& worker = self->m_workers[i];
            if (worker) {
                worker->set_block(work_package, [weak_mgr](auto id, auto block_data)
                {
                    on_block_found(weak_mgr, id, std::move(block_data));
                });
                if (worker->is_running()) {
                    workers_fed++;
                    self->m_logger->debug("[Worker_manager] Template sent to worker {}/{}", 
                                    workers_fed, self->m_workers.size());
                } else {
                    self->m_logger->warn("[Worker_manager] Worker {} did not start after set_block() — not counted", i);
                }
            } else {
                self->m_logger->warn("[Worker_manager] Skipping null worker at index {}", i);
            }
        }
    }
    
    if (workers_fed > 0) {
        auto solo_protocol = self->m_primary_node_session ? self->m_primary_node_session->get_primary_protocol() : nullptr;
        self->m_logger->info("[Worker_manager] ✓ Template distributed to {} workers - MINING STARTED", 
                      workers_fed);
        // ✅ Clear degraded mode and all recovery state now that a valid template
        // has been successfully delivered to workers.  This is intentionally done
        // AFTER distribution so we only exit recovery state when workers actually
        // received the template (not merely on template arrival).
        if (self->is_recovery_active()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - self->m_recovery_sm.context().entered_at).count();
            self->m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
            self->m_logger->warn("[Worker_manager] ✅ RECOVERY COMPLETE — epoch {} ({}s elapsed)", self->m_coordinator->recovery_epoch(), elapsed);
            self->m_logger->warn("[Worker_manager]    Fresh template distributed to workers successfully");
            self->m_logger->warn("[Worker_manager]    Workers resumed mining on valid template");
            self->m_logger->warn("[Worker_manager] ═══════════════════════════════════════════════════════════");
        }
        self->clear_recovery_state();

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
                self->m_logger->info("[Worker_manager] No push notification ever received — skipping resubscribe");
            } else {
                auto now_resub = std::chrono::steady_clock::now();
                int64_t since_push_s = std::chrono::duration_cast<std::chrono::seconds>(
                    now_resub - ht_snap.last_push_notification_at).count();

                // Fix 2: Post-recovery hold-off — don't fire resubscribe within 60 s
                // of recovery completing.  The template just delivered needs time to
                // flow before we declare push silence.
                constexpr int64_t POST_RECOVERY_HOLDOFF_SECONDS = 60;
                int64_t since_recovery_s =
                    (self->m_recovery_sm.context().last_completed_at != std::chrono::steady_clock::time_point{})
                    ? std::chrono::duration_cast<std::chrono::seconds>(
                          now_resub - self->m_recovery_sm.context().last_completed_at).count()
                    : INT64_MAX;  // No recovery ever completed — hold-off does not apply

                // Fix 3: Raised from 120 → 400 to exceed the longest observed Prime
                // block time (~330 s); prevents mid-mining resubscription on long blocks.
                // NOTE: For faster resubscription during active recovery (reorg scenario),
                // see the Reorg Resubscription Guard in check_template_health().
                // This path handles post-recovery push silence only after recovery completes.
                constexpr int64_t PUSH_RESUBSCRIBE_THRESHOLD_SECONDS = 400;

                if (since_recovery_s < POST_RECOVERY_HOLDOFF_SECONDS) {
                    self->m_logger->info("[Worker_manager] Recovery completed {}s ago — within hold-off, skipping resubscribe",
                                   since_recovery_s);
                } else if (since_push_s > PUSH_RESUBSCRIBE_THRESHOLD_SECONDS) {
                    self->m_logger->warn("[Worker_manager] Push notifications silent for {}s after recovery — re-subscribing",
                                   since_push_s);
                    solo_protocol->resubscribe_push_notifications();
                }
            }
        }
    } else {
        self->m_logger->error("[Worker_manager] FAILED: No workers received template!");
        // Immediately request a new template — don't wait 30s for health monitor.
        // transition_to(HARD_RECOVERY) is triggered by mark_recovery_initiated()
        // inside retry_template_request(true), after stop_all_workers() here.
        self->stop_all_workers();
        self->retry_template_request(true);
    }
}

void TemplateDistributor::on_block_found(
    std::weak_ptr<Worker_manager> weak_mgr,
    std::uint32_t id,
    std::unique_ptr<Block_data>&& block_data)
{
    LOCK_WEAK_OR_RETURN(weak_mgr, self);
    self->m_logger->info("════════════════════════════════════════════════════════");
    self->m_logger->info("💎 BLOCK FOUND CALLBACK INVOKED!");
    self->m_logger->info("   Worker ID:  {}", id);
    self->m_logger->info("   Height:     {}", block_data->nHeight);
    self->m_logger->info("   Nonce:      0x{:016x}", block_data->nNonce);
    self->m_logger->info("════════════════════════════════════════════════════════");

    if (!self->m_primary_node_session || !self->m_primary_node_session->is_authenticated())
    {
        self->m_logger->error("[Worker_manager] No authenticated session. Can't submit block.");
        return;
    }

    // Get the mining template interface to prepare full block submission
    auto solo_protocol = self->m_primary_node_session->get_primary_protocol();
    if (!solo_protocol)
    {
        self->m_logger->error("[Worker_manager] Failed to get protocol from NodeSession");
        return;
    }

    auto* template_interface = solo_protocol->get_template_interface();
    if (!template_interface)
    {
        self->m_logger->error("[Worker_manager] Template interface not available");
        return;
    }

    // ✅ Final staleness check before submission (Template Staleness Prevention)
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
            self->m_logger->error("[Worker_manager] ❌ Solution found but channel height ADVANCED!");
            self->m_logger->error("[Worker_manager]    channel_height {} >= channel_target {}",
                           ht_snap.channel_height, ht_snap.channel_target);
            self->m_logger->error("[Worker_manager]    Another miner found this block first - discarding");
        } else {
            self->m_logger->error("[Worker_manager] ❌ Solution found but template too old: {}s (max: 600s)",
                           template_age);
            self->m_logger->error("[Worker_manager]    Push notifications likely missed - discarding");
        }
        self->mark_soft_refresh_requested(soft_refresh_reason);
        template_interface->discard_template(channel_stale ? "Channel height advanced before submission"
                                                           : "Age exceeded 600s before submission");

        // Request fresh template via NodeSession
        self->m_logger->info("[Worker_manager] Requesting fresh template via NodeSession");
        auto work_payload = self->m_primary_node_session->request_work();
        if (work_payload && !work_payload->empty()) {
            self->m_primary_node_session->transmit(work_payload);
        }
        return;
    }

    self->m_logger->info("[Worker_manager] 💎 Solution found! Age: {}s, Channel height valid ✅ - SUBMITTING", template_age);

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
            self->m_logger->info("[SUBMIT AUDIT]   block.hashPrevBlock = {}... (tip anchor — node Guard 2 will verify this == hashBestChain)", prev_hex);
        }
    }

    // Prepare full block submission (216 or 220 bytes depending on format)
    // This reconstructs the full block from the current template with the
    // mined merkle root and nonce
    self->m_logger->info("[Worker_manager] Preparing full block submission");
    self->m_logger->info("[Worker_manager]   Height: {}", block_data->nHeight);
    self->m_logger->info("[Worker_manager]   Nonce:  0x{:016x}", block_data->nNonce);
    if (!block_data->vOffsets.empty())
        self->m_logger->info("[Worker_manager]   vOffsets: {} bytes (Prime channel)",
                       block_data->vOffsets.size());

    auto full_block_bytes = template_interface->prepare_block_submission(
        block_data->merkle_root.GetBytes(),
        block_data->nNonce,
        block_data->vOffsets);

    if (full_block_bytes.empty())
    {
        self->m_logger->error("[Worker_manager] Failed to prepare block submission - empty payload");
        self->m_logger->error("[Worker_manager]   This indicates template or block data is invalid");
        return;
    }

    self->m_logger->info("[Worker_manager] Full block serialized: {} bytes", full_block_bytes.size());
    self->m_logger->info("[Worker_manager] Submitting block to protocol layer...");

    // Submit the full block via NodeSession
    self->submit_solution(full_block_bytes, block_data->nNonce);
}

} // namespace nexusminer
