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

namespace {
    // Push-notification liveness threshold: if a push notification
    // (PRIME/HASH_BLOCK_AVAILABLE) was received within this window, the TCP session
    // is demonstrably alive and authenticated.  PUSH is the sole authoritative
    // signal for session liveness — keepalive ACK is diagnostic only.
    constexpr int64_t PUSH_ALIVE_THRESHOLD_SECONDS = protocol::ProtocolConstants::PUSH_LIVENESS_THRESHOLD_SECONDS;

    // Unified height drift threshold: if HeightTracker.unified_height exceeds
    // template.block.nHeight by more than this many blocks, the template is
    // presumed stale (hashPrevBlock is wrong) and must be discarded.
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

                // ═══════════════════════════════════════════════════════════════
                size_t workers_fed = 0;
                {
                    std::lock_guard<std::mutex> lock(m_worker_mutex);

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

                            // Final staleness check before submission (Template Staleness Prevention)
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

                                // Request fresh template via NodeSession
                                m_logger->info("[Worker_manager] Requesting fresh template via NodeSession");
                                auto work_payload = m_primary_node_session->request_work();
                                if (work_payload && !work_payload->empty()) {
                                    m_primary_node_session->transmit(work_payload);
                                }
                                return;
                            }

                            m_logger->info("[Worker_manager] 💎 Solution found! Age: {}s, Channel height valid ✅ - SUBMITTING", template_age);

                            // Log hashPrevBlock before submission (SUBMIT AUDIT).
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
                    m_logger->info("[Worker_manager] ✓ Template distributed to {} workers - MINING", 
                                  workers_fed);
                    if (solo_protocol) {
                        solo_protocol->mark_authoritative_recovery_healthy("fresh_template_distributed_to_workers");
                    }
                } else {
                    m_logger->error("[Worker_manager] FAILED: No workers received template!");
                }
            }
        );
        
        m_logger->info("[Worker_manager] Template distribution handler registered");

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

                mgr->m_logger->warn("[Worker_manager] NODE_SHUTDOWN received (reason=0x{:02X}) — workers continue, connection preserved",
                    reason);
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
    // still exists. Workers run forever — they are never stopped by Worker_manager.
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

bool Worker_manager::connect(network::Endpoint const& wallet_endpoint)
{
    // Save the primary endpoint on the very first connect() call from Miner::run()
    if (!m_primary_endpoint.is_valid())
    {
        m_primary_endpoint = wallet_endpoint;
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
            self->m_logger->error("[Solo] Connection to wallet {} not successful — connection is preserved, awaiting reconnect",
                wallet_endpoint.to_string());
            return;
        }

        // Connection and authentication succeeded
        self->m_logger->info("[Solo] Connected and authenticated — starting work.");

        // Start timers once only (guarded by flags)
        auto const print_statistics_interval = self->m_config.get_print_statistics_interval();
        if (!self->m_stats_timers_started)
        {
            self->m_stats_timers_started = true;
            self->m_timer_manager.start_stats_collector_timer(print_statistics_interval, weak_self);
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
                    snap.has_failover_configured = wm->m_config.has_failover();
                    snap.using_failover          = false;
                    snap.primary_fail_count      = 0;
                    snap.failover_max_retries    = wm->m_config.get_failover_max_retries();
                    snap.active_endpoint_str  = wm->m_primary_endpoint.is_valid() ? wm->m_primary_endpoint.to_string() : "";
                    snap.standby_endpoint_str = "";
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

    bool workers_run = !m_workers.empty();

    // Send session status via NodeSession (handles both lanes internally)
    if (m_primary_node_session && m_primary_node_session->is_authenticated())
    {
        auto solo_protocol = m_primary_node_session->get_primary_protocol();
        if (solo_protocol)
        {
            // NodeSession handles SIM Link internally, so we don't need to track secondary separately
            auto pkt = solo_protocol->build_session_status_packet(false, workers_run, false);
            if (pkt && !pkt->empty())
                m_primary_node_session->transmit(pkt);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Worker Control Methods
// ═══════════════════════════════════════════════════════════════════════

void Worker_manager::collect_worker_statistics()
{
    std::lock_guard<std::mutex> lock(m_worker_mutex);
    for (auto& worker : m_workers)
    {
        if (worker)
        {
            worker->update_statistics(*m_stats_collector);
        }
    }
}

void Worker_manager::check_template_health()
{
    // Connection is sacred — never tear it down.
    // Only action: if authenticated and no valid template, request one.
    auto solo_protocol = m_primary_node_session
        ? m_primary_node_session->get_primary_protocol() : nullptr;
    if (!solo_protocol) return;

    if (!solo_protocol->is_authenticated()) return;

    auto* tmpl = solo_protocol->get_template_interface();
    if (!tmpl || tmpl->has_valid_template()) return;  // already have work — nothing to do

    // No valid template: send a GET_BLOCK politely
    auto work_payload = m_primary_node_session->request_work(false);
    if (work_payload && !work_payload->empty()) {
        m_primary_node_session->transmit(work_payload);
        m_logger->info("[Worker_manager] GET_BLOCK sent (health-check path)");
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
