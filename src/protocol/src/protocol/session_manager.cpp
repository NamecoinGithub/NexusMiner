#include "protocol/session_manager.hpp"
#include "protocol/hex_prefix_utils.hpp"
#include "protocol/serialization_helpers.hpp"
#include "network/connection.hpp"
#include "packet.hpp"
#include "miner_opcodes.hpp"
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <limits>
#include <sstream>

namespace nexusminer {
namespace protocol {

// Session management constants
constexpr uint16_t MIN_KEEPALIVE_HOURS = 1;
constexpr uint16_t MAX_KEEPALIVE_HOURS = 168;
constexpr auto KEEPALIVE_EARLY_INTERVAL = std::chrono::seconds(10);   // First ping after auth
constexpr auto KEEPALIVE_TCP_INTERVAL   = std::chrono::seconds(45);   // TCP keepalive ping
constexpr uint16_t KEEPALIVE_REGULAR_INTERVAL_DEFAULT = 12;           // Default hours fallback (2 pings per 24h node window)

namespace {

constexpr std::array<uint8_t, 4> CLEARED_PREVBLOCK_SUFFIX{0, 0, 0, 0};

uint64_t now_epoch_seconds()
{
    return static_cast<uint64_t>(std::time(nullptr));
}

const char* lane_name(ProtocolLane lane)
{
    switch (lane) {
        case ProtocolLane::LEGACY:
            return "LEGACY";
        case ProtocolLane::STATELESS:
            return "STATELESS";
        default:
            return "UNKNOWN";
    }
}

const char* session_event_kind_name(SessionManager::SessionEventKind kind)
{
    switch (kind) {
        case SessionManager::SessionEventKind::AUTH_INIT: return "auth_init";
        case SessionManager::SessionEventKind::AUTH_SUCCESS: return "auth_success";
        case SessionManager::SessionEventKind::SESSION_START: return "session_start";
        case SessionManager::SessionEventKind::REWARD_BIND_SENT: return "reward_bind_sent";
        case SessionManager::SessionEventKind::REWARD_BIND_RESULT: return "reward_bind_result";
        case SessionManager::SessionEventKind::STATUS_ACK_ACCEPTED: return "status_ack_accepted";
        case SessionManager::SessionEventKind::STATUS_ACK_REJECTED: return "status_ack_rejected";
        case SessionManager::SessionEventKind::KEEPALIVE_ACK: return "keepalive_ack";
        case SessionManager::SessionEventKind::STALE_PACKET_DROPPED: return "stale_packet_dropped";
        case SessionManager::SessionEventKind::EPOCH_MISMATCH: return "epoch_mismatch";
        case SessionManager::SessionEventKind::RECOVERY_REQUESTED: return "recovery_requested";
        case SessionManager::SessionEventKind::RECOVERY_HEALTHY: return "recovery_healthy";
        case SessionManager::SessionEventKind::FORCED_REAUTH: return "forced_reauth";
        case SessionManager::SessionEventKind::SESSION_RESET: return "session_reset";
        case SessionManager::SessionEventKind::SUBMIT_SENT: return "submit_sent";
        case SessionManager::SessionEventKind::SUBMIT_ACCEPTED: return "submit_accepted";
        case SessionManager::SessionEventKind::SUBMIT_REJECTED: return "submit_rejected";
    }

    return "unknown";
}

const char* session_state_name(SessionManager::SessionState state)
{
    switch (state) {
        case SessionManager::SessionState::DISCONNECTED:
            return "DISCONNECTED";
        case SessionManager::SessionState::AUTHENTICATING:
            return "AUTHENTICATING";
        case SessionManager::SessionState::AUTHENTICATED:
            return "AUTHENTICATED";
        case SessionManager::SessionState::ACTIVE:
            return "ACTIVE";
        case SessionManager::SessionState::EXPIRED:
            return "EXPIRED";
    }

    return "UNKNOWN";
}

const char* reward_state_name(SessionManager::RewardState state)
{
    switch (state) {
        case SessionManager::RewardState::NONE: return "NONE";
        case SessionManager::RewardState::REQUIRED: return "REQUIRED";
        case SessionManager::RewardState::BINDING: return "BINDING";
        case SessionManager::RewardState::BOUND: return "BOUND";
        case SessionManager::RewardState::REJECTED: return "REJECTED";
        case SessionManager::RewardState::STALE: return "STALE";
    }

    return "UNKNOWN";
}

const char* recovery_state_name(SessionManager::RecoveryState state)
{
    switch (state) {
        case SessionManager::RecoveryState::HEALTHY: return "HEALTHY";
        case SessionManager::RecoveryState::SOFT_REFRESH_REQUESTED: return "SOFT_REFRESH_REQUESTED";
        case SessionManager::RecoveryState::RECOVERY_PENDING: return "RECOVERY_PENDING";
        case SessionManager::RecoveryState::RECOVERY_IN_PROGRESS: return "RECOVERY_IN_PROGRESS";
        case SessionManager::RecoveryState::FORCED_REAUTH: return "FORCED_REAUTH";
        case SessionManager::RecoveryState::RECONNECT_REQUIRED: return "RECONNECT_REQUIRED";
    }

    return "UNKNOWN";
}

const char* expiry_state_name(SessionManager::ExpiryState state)
{
    switch (state) {
        case SessionManager::ExpiryState::FRESH: return "FRESH";
        case SessionManager::ExpiryState::KEEPALIVE_MISMATCH_WARNING: return "KEEPALIVE_MISMATCH_WARNING";
        case SessionManager::ExpiryState::STALE_ACK_IGNORED: return "STALE_ACK_IGNORED";
        case SessionManager::ExpiryState::EXPIRED_ACCEPTED: return "EXPIRED_ACCEPTED";
        case SessionManager::ExpiryState::EXPIRED_REJECTED: return "EXPIRED_REJECTED";
        case SessionManager::ExpiryState::AUTH_TIMEOUT: return "AUTH_TIMEOUT";
        case SessionManager::ExpiryState::DEAD_SESSION_TIMEOUT: return "DEAD_SESSION_TIMEOUT";
    }

    return "UNKNOWN";
}

} // namespace

SessionManager::SessionManager(uint16_t keepalive_interval_hours,
                               std::shared_ptr<asio::io_context> io_context)
    : m_session{}
    , m_keepalive_interval_hours(keepalive_interval_hours)
    , m_preserve_genesis_on_disconnect(true)  // Enable genesis preservation for reconnection support
    , m_protocol_lane(ProtocolLane::UNKNOWN)  // Initialize to UNKNOWN, must be set before use
    , m_io_context(io_context)
    , m_keepalive_timer(nullptr)
    , m_keepalive_active(false)
    , m_logger(spdlog::get("logger"))
{
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
    
    // Clamp keepalive interval to reasonable range
    if (m_keepalive_interval_hours < MIN_KEEPALIVE_HOURS) m_keepalive_interval_hours = MIN_KEEPALIVE_HOURS;
    if (m_keepalive_interval_hours > MAX_KEEPALIVE_HOURS) m_keepalive_interval_hours = MAX_KEEPALIVE_HOURS;

    // Initialize session to disconnected state
    m_session.created_at = now_epoch_seconds();
    m_session.last_activity = m_session.created_at;
    m_session.session_id = 0;
    m_session.state = SessionState::DISCONNECTED;
    m_session.reward_state = RewardState::NONE;
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.keepalive_count = 0;

    m_logger->info("[SessionManager] Initialized with keepalive interval: {} hours",
                   m_keepalive_interval_hours);
}

SessionManager::~SessionManager()
{
    stop_keepalive_timer();
    end_session();
}

void SessionManager::start_session(uint32_t session_id,
                                   const std::vector<uint8_t>& session_key,
                                   const std::vector<uint8_t>& tritium_genesis)
{
    stop_keepalive_timer();

    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        if (m_session.state != SessionState::AUTHENTICATING) {
            clear_session_event_journal_locked();
        }
        m_session.session_key = session_key;
        transition_to_authenticated_locked(session_id, tritium_genesis);
    }

    m_logger->info("[SessionManager] Session started - ID: 0x{:08X}, epoch={}",
                   session_id, get_runtime_snapshot().session_epoch);

    if (!session_key.empty()) {
        m_logger->info("[SessionManager] Session key received: {} bytes", session_key.size());
    }

    if (!tritium_genesis.empty()) {
        m_logger->info("[SessionManager] Tritium genesis bound to session: {} bytes",
                      tritium_genesis.size());
    }
}

void SessionManager::commit_authenticated_session(uint32_t session_id,
                                                  const std::vector<uint8_t>& pubkey,
                                                  const std::string& key_id,
                                                  const std::vector<uint8_t>& tritium_genesis)
{
    stop_keepalive_timer();

    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        if (m_session.state != SessionState::AUTHENTICATING) {
            clear_session_event_journal_locked();
        }
        m_session.falcon_pubkey = pubkey;
        m_session.falcon_key_id = key_id;
        m_session.session_key.clear();
        transition_to_authenticated_locked(session_id, tritium_genesis);
    }

    m_logger->info("[SessionManager] Session started - ID: 0x{:08X}, epoch={}",
                   session_id, get_runtime_snapshot().session_epoch);

    if (!pubkey.empty()) {
        m_logger->info("[SessionManager] Falcon identity committed: {} bytes", pubkey.size());
    }

    if (!tritium_genesis.empty()) {
        m_logger->info("[SessionManager] Tritium genesis bound to session: {} bytes",
                       tritium_genesis.size());
    }
}

void SessionManager::begin_auth_handshake(const std::string& detail)
{
    stop_keepalive_timer();

    std::lock_guard<std::mutex> lock(m_session_mutex);
    const auto retained_reward_address = m_session.reward_address_string;
    const auto retained_reward_source = m_session.reward_binding_source;
    const auto retained_chacha20_session_key = m_session.chacha20_session_key;
    const auto retained_chacha20_key_fingerprint = m_session.chacha20_key_fingerprint;
    const bool retained_chacha20_ready = m_session.chacha20_ready;
    clear_runtime_session_locked(true, true);
    m_session.reward_address_string = retained_reward_address;
    m_session.reward_binding_source = retained_reward_source;
    m_session.chacha20_session_key = retained_chacha20_session_key;
    m_session.chacha20_key_fingerprint = retained_chacha20_key_fingerprint;
    m_session.chacha20_ready = retained_chacha20_ready;
    m_session.reward_state = retained_reward_address.empty() ? RewardState::NONE
                                                             : RewardState::REQUIRED;
    m_session.state = SessionState::AUTHENTICATING;
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.recovery_reason.clear();
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    clear_session_event_journal_locked();
    record_session_event_locked(SessionEventKind::AUTH_INIT,
                                detail.empty() ? "authentication handshake started" : detail);
}

void SessionManager::begin_reward_binding(const std::string& reward_address,
                                          const std::vector<uint8_t>& reward_hash,
                                          const std::string& source)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_hash = reward_hash;
    m_session.reward_bound = false;
    m_session.reward_binding_source = source;
    m_session.reward_state = reward_address.empty() ? RewardState::NONE : RewardState::BINDING;
    m_session.ready_for_submit = false;
    m_session.ready_for_get_block = false;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BIND_SENT,
                                reward_address.empty()
                                    ? "reward binding requested"
                                    : ("reward binding requested for " + reward_address));
}

void SessionManager::commit_reward_bound(const std::string& reward_address,
                                         const std::vector<uint8_t>& reward_hash,
                                         const std::string& source)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_hash = reward_hash;
    m_session.reward_bound = true;
    m_session.reward_binding_source = source;
    m_session.reward_state = reward_address.empty() ? RewardState::NONE : RewardState::BOUND;
    m_session.last_reward_bind_time = now_epoch_seconds();
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BIND_RESULT,
                                std::string("accepted") +
                                    (source.empty() ? "" : (" via " + source)));
}

void SessionManager::commit_reward_rejected(const std::string& reward_address,
                                            const std::string& source,
                                            const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_hash.clear();
    m_session.reward_bound = false;
    m_session.reward_binding_source = source;
    m_session.reward_state = reward_address.empty() ? RewardState::NONE : RewardState::REJECTED;
    m_session.ready_for_submit = false;
    m_session.ready_for_get_block = false;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BIND_RESULT,
                                std::string("rejected") +
                                    (source.empty() ? "" : (" via " + source)) +
                                    (reason.empty() ? "" : (": " + reason)));
}

void SessionManager::note_keepalive_ack(bool accepted, const std::string& detail)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_activity = now_epoch_seconds();
    if (accepted) {
        if (m_session.state == SessionState::AUTHENTICATED) {
            m_session.state = SessionState::ACTIVE;
        }
        m_session.expiry_state = ExpiryState::FRESH;
        m_session.expiry_reason.clear();
        record_session_event_locked(SessionEventKind::KEEPALIVE_ACK,
                                    detail.empty() ? "keepalive ack accepted" : detail);
        return;
    }

    m_session.expiry_state = ExpiryState::KEEPALIVE_MISMATCH_WARNING;
    m_session.expiry_reason = detail;
    record_session_event_locked(SessionEventKind::KEEPALIVE_ACK,
                                detail.empty() ? "keepalive ack rejected" : detail);
}

void SessionManager::mark_soft_refresh_requested(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.recovery_state = RecoveryState::SOFT_REFRESH_REQUESTED;
    m_session.recovery_reason = reason;
    m_session.last_activity = now_epoch_seconds();
    record_session_event_locked(SessionEventKind::RECOVERY_REQUESTED,
                                reason.empty() ? "soft refresh requested" : reason);
}

void SessionManager::mark_recovery_required(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.recovery_state = RecoveryState::RECOVERY_PENDING;
    m_session.recovery_reason = reason;
    m_session.last_activity = now_epoch_seconds();
    record_session_event_locked(SessionEventKind::RECOVERY_REQUESTED,
                                reason.empty() ? "recovery required" : reason);
}

void SessionManager::mark_recovery_healthy(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);

    if (m_session.recovery_state == RecoveryState::FORCED_REAUTH ||
        m_session.recovery_state == RecoveryState::RECONNECT_REQUIRED ||
        m_session.state == SessionState::EXPIRED) {
        m_logger->debug("[SessionManager] mark_recovery_healthy suppressed (state={}, recovery_state={})",
                        session_state_name(m_session.state),
                        recovery_state_name(m_session.recovery_state));
        return;
    }

    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.recovery_reason.clear();
    m_session.last_activity = now_epoch_seconds();
    record_session_event_locked(SessionEventKind::RECOVERY_HEALTHY,
                                reason.empty() ? "recovery healthy" : reason);
}

void SessionManager::mark_session_expired(const std::string& reason)
{
    bool notify = false;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        notify = (m_session.state != SessionState::EXPIRED);
        m_session.state = SessionState::EXPIRED;
        m_session.expiry_state = ExpiryState::EXPIRED_ACCEPTED;
        m_session.expiry_reason = reason;
        m_session.recovery_state = RecoveryState::FORCED_REAUTH;
        m_session.recovery_reason = reason;
        m_session.ready_for_submit = false;
        m_session.ready_for_get_block = false;
        if (m_session.reward_bound) {
            m_session.reward_state = RewardState::STALE;
        }
        m_session.last_activity = now_epoch_seconds();
        update_replay_allowances_locked();
        record_session_event_locked(SessionEventKind::FORCED_REAUTH,
                                    reason.empty() ? "session marked expired" : reason);
    }

    if (notify && m_session_expired_handler) {
        m_session_expired_handler();
    }
}

void SessionManager::clear_for_disconnect(const std::string& reward_address,
                                          const std::string& reward_source,
                                          const std::string& reason,
                                          bool preserve_genesis)
{
    std::chrono::seconds uptime;
    uint32_t session_id;
    uint32_t keepalive_count;
    SessionState prev_state;
    std::string retained_reward_address;
    std::string retained_reward_source;

    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        prev_state = m_session.state;
        session_id = m_session.session_id;
        keepalive_count = m_session.keepalive_count;
        retained_reward_address = reward_address.empty() ? m_session.reward_address_string : reward_address;
        retained_reward_source = reward_source.empty() ? m_session.reward_binding_source : reward_source;

        if (prev_state != SessionState::DISCONNECTED) {
            uptime = get_session_uptime_locked();
        }

        clear_runtime_session_locked(preserve_genesis, false);
        m_session.reward_address_string = retained_reward_address;
        m_session.reward_binding_source = retained_reward_source;
        m_session.reward_state = retained_reward_address.empty() ? RewardState::NONE
                                                                 : RewardState::REQUIRED;
        m_session.recovery_state = RecoveryState::RECONNECT_REQUIRED;
        m_session.recovery_reason = reason;
        m_session.expiry_state = ExpiryState::FRESH;
        m_session.expiry_reason.clear();
        update_replay_allowances_locked();
        record_session_event_locked(SessionEventKind::SESSION_RESET,
                                    reason.empty() ? "session cleared for disconnect" : reason);
    }

    stop_keepalive_timer();

    if (prev_state != SessionState::DISCONNECTED) {
        m_logger->info("[SessionManager] Session ended - ID: 0x{:08X}, Uptime: {}s, Keepalives: {}",
                      session_id, uptime.count(), keepalive_count);
    }
}

void SessionManager::clear_for_reauth(const std::string& reward_address,
                                      const std::string& reward_source,
                                      const std::string& reason,
                                      bool preserve_genesis)
{
    stop_keepalive_timer();

    std::lock_guard<std::mutex> lock(m_session_mutex);
    const auto retained_reward_address = reward_address.empty() ? m_session.reward_address_string : reward_address;
    const auto retained_reward_source = reward_source.empty() ? m_session.reward_binding_source : reward_source;
    clear_runtime_session_locked(preserve_genesis, true);
    m_session.reward_address_string = retained_reward_address;
    m_session.reward_binding_source = retained_reward_source;
    m_session.reward_state = retained_reward_address.empty() ? RewardState::NONE
                                                             : RewardState::REQUIRED;
    m_session.recovery_state = RecoveryState::FORCED_REAUTH;
    m_session.recovery_reason = reason;
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::SESSION_RESET,
                                reason.empty() ? "session cleared for reauth" : reason);
}

void SessionManager::end_session()
{
    clear_for_disconnect({}, {}, "", m_preserve_genesis_on_disconnect);
}

void SessionManager::set_connection(std::shared_ptr<network::Connection> connection)
{
    m_connection = connection;
}

void SessionManager::start_keepalive_timer()
{
    if (!m_io_context) {
        m_logger->warn("[SessionManager] Keepalive timer unavailable - missing io_context");
        return;
    }

    if (!m_keepalive_timer) {
        m_keepalive_timer = std::make_shared<asio::steady_timer>(*m_io_context);
    }

    m_keepalive_active = true;

    auto self = shared_from_this();
    uint64_t generation = m_keepalive_generation.load();
    m_keepalive_timer->expires_after(KEEPALIVE_EARLY_INTERVAL);
    m_keepalive_timer->async_wait([self, generation](const asio::error_code& error) {
        if (error || !self->m_keepalive_active || !self->is_active()) {
            return;
        }
        // Check if this timer callback is stale
        if (generation != self->m_keepalive_generation.load()) {
            return;
        }

        self->send_keepalive("early");
        self->schedule_regular_keepalives(self);
    });

    m_logger->info("[SessionManager] Keepalive timer started (early: {}s, TCP ping: {}s, config interval: {}h)",
                  KEEPALIVE_EARLY_INTERVAL.count(), KEEPALIVE_TCP_INTERVAL.count(), m_keepalive_interval_hours);
}

void SessionManager::stop_keepalive_timer()
{
    m_keepalive_active = false;
    ++m_keepalive_generation;  // invalidate all pending timer lambdas
    if (m_keepalive_timer) {
        m_keepalive_timer->cancel();
    }
}

void SessionManager::schedule_regular_keepalives(const std::shared_ptr<SessionManager>& self)
{
    if (!m_keepalive_timer || !m_keepalive_active) {
        return;
    }

    // Use 45s TCP keepalive interval to prevent node dropping the connection.
    // The node's block cache times out after 90 seconds — 45s gives us 2 pings
    // per 90s window with comfortable margin.
    // Note: m_keepalive_interval_hours is a config-driven session cache concept
    // retained for potential future use (e.g., session expiry checks), but it
    // does NOT control the TCP ping cadence which must be fixed at 45s.
    uint64_t generation = m_keepalive_generation.load();
    m_keepalive_timer->expires_after(KEEPALIVE_TCP_INTERVAL);
    m_keepalive_timer->async_wait([self, generation](const asio::error_code& error) {
        if (error || !self->m_keepalive_active || !self->is_active()) {
            return;
        }
        // Check if this timer callback is stale
        if (generation != self->m_keepalive_generation.load()) {
            return;
        }

        self->send_keepalive("regular");
        self->schedule_regular_keepalives(self);
    });
}

void SessionManager::send_keepalive(const char* cadence)
{
    auto connection = m_connection.lock();
    if (!connection) {
        m_logger->warn("[SessionManager] Keepalive skipped - no active connection");
        stop_keepalive_timer();
        return;
    }

    auto payload = build_keepalive_packet();
    if (!payload || payload->empty()) {
        m_logger->warn("[SessionManager] Keepalive skipped - no session packet");
        return;
    }

    uint32_t session_id;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        session_id = m_session.session_id;
        m_session.last_activity = now_epoch_seconds();
    }

    connection->transmit(payload);
    record_keepalive();
    m_logger->info("[SessionManager] Keepalive sent ({}) for session 0x{:08X}",
                  cadence, session_id);
}

network::Shared_payload SessionManager::build_keepalive_packet() const
{
    uint32_t session_id;
    ProtocolLane lane;
    std::array<uint8_t, 4> prevblock_suffix;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        session_id = m_session.session_id;
        lane = m_protocol_lane;
        prevblock_suffix = m_session.prevblock_suffix;
    }

    if (session_id == 0) {
        return network::Shared_payload{};
    }

    // Validate protocol lane is set - UNKNOWN lane is not allowed
    if (lane == ProtocolLane::UNKNOWN) {
        m_logger->error("[SessionManager] build_keepalive_packet() called with UNKNOWN protocol lane");
        m_logger->error("[SessionManager]   Cannot send SESSION_KEEPALIVE without knowing the protocol lane");
        m_logger->error("[SessionManager]   This indicates a configuration or initialization error");
        return network::Shared_payload{};
    }

    // v2 keepalive payload: [session_id(4 LE)][miner_prevblock_suffix(4 raw bytes)]
    std::vector<uint8_t> payload;
    serialization::append_uint32_le(payload, session_id);
    payload.insert(payload.end(), prevblock_suffix.begin(), prevblock_suffix.end());

    // Build lane-aware packet based on protocol lane
    // On stateless lane, use mirror-mapped SESSION_KEEPALIVE (0xD0D4)
    // On legacy lane, use legacy SESSION_KEEPALIVE (212)
    bool use_stateless_opcode = (lane == ProtocolLane::STATELESS);

    Packet packet = use_stateless_opcode
        ? Packet{ LLP::StatelessMining::SESSION_KEEPALIVE,  // already uint16_t
                  std::make_shared<network::Payload>(payload) }
        : Packet{ static_cast<uint8_t>(Packet::SESSION_KEEPALIVE),
                  std::make_shared<network::Payload>(payload) };

    return packet.get_bytes();
}

network::Shared_payload SessionManager::build_session_status_packet(
    bool degraded, bool has_template, bool workers_running, bool secondary_up) const
{
    using namespace ::LLP::SessionStatusOpcodes;

    uint32_t session_id;
    ProtocolLane lane;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        session_id = m_session.session_id;
        lane = m_protocol_lane;
    }

    if (session_id == 0)
        return network::Shared_payload{};

    if (lane == ProtocolLane::UNKNOWN) {
        m_logger->error("[SessionManager] build_session_status_packet() called with UNKNOWN protocol lane");
        return network::Shared_payload{};
    }

    uint32_t status_flags = 0;
    if (degraded)        status_flags |= MINER_DEGRADED;
    if (has_template)    status_flags |= MINER_HAS_TEMPLATE;
    if (workers_running) status_flags |= MINER_WORKERS_ACTIVE;
    if (secondary_up)    status_flags |= MINER_SECONDARY_UP;

    ::LLP::SessionStatusFrame frame;
    frame.session_id   = session_id;
    frame.status_flags = status_flags;
    auto payload = frame.Serialize();

    bool use_stateless = (lane == ProtocolLane::STATELESS);

    // Build lane-aware packet following the same framing as build_keepalive_packet()
    Packet packet = use_stateless
        ? Packet{ static_cast<uint16_t>(SESSION_STATUS),
                  std::make_shared<network::Payload>(payload) }
        : Packet{ static_cast<uint8_t>(SESSION_STATUS_LEGACY),
                  std::make_shared<network::Payload>(payload) };

    return packet.get_bytes();
}

void SessionManager::record_keepalive()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_keepalive = std::chrono::system_clock::now();
    m_session.keepalive_count++;
    m_session.last_activity = now_epoch_seconds();

    // Transition to ACTIVE state after first keepalive
    if (m_session.state == SessionState::AUTHENTICATED) {
        m_logger->info("[SessionManager] State transition: {} -> {}",
                       session_state_name(m_session.state),
                       session_state_name(SessionState::ACTIVE));
        m_session.state = SessionState::ACTIVE;
    }
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();

    auto uptime = get_session_uptime_locked();
    m_logger->info("[SessionManager] Keepalive #{} sent - Session uptime: {}h",
                  m_session.keepalive_count, uptime.count() / 3600);
}

void SessionManager::set_state(SessionState state)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    if (m_session.state != state) {
        m_logger->info("[SessionManager] State transition: {} -> {}",
                      session_state_name(m_session.state),
                      session_state_name(state));

        m_session.state = state;
        if (state != SessionState::DISCONNECTED) {
            m_session.last_activity = now_epoch_seconds();
        }

        if (state == SessionState::AUTHENTICATING) {
            clear_session_event_journal_locked();
            record_session_event_locked(SessionEventKind::AUTH_INIT, "authentication handshake started");
        } else if (state == SessionState::EXPIRED) {
            m_session.expiry_state = ExpiryState::EXPIRED_ACCEPTED;
            m_session.recovery_state = RecoveryState::FORCED_REAUTH;
            record_session_event_locked(SessionEventKind::FORCED_REAUTH, "session marked expired");
        }

        if (state == SessionState::EXPIRED && m_session_expired_handler)
            m_session_expired_handler();
    }
}

bool SessionManager::is_active() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return (m_session.state == SessionState::AUTHENTICATED ||
            m_session.state == SessionState::ACTIVE);
}

SessionManager::SessionState SessionManager::get_state() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.state;
}

uint32_t SessionManager::get_session_id() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.session_id;
}

uint64_t SessionManager::get_session_epoch() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.session_epoch;
}

std::vector<uint8_t> SessionManager::get_session_key() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.session_key;
}

std::vector<uint8_t> SessionManager::get_tritium_genesis() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.session_genesis;
}

void SessionManager::set_tritium_genesis(const std::vector<uint8_t>& genesis)
{
    if (genesis.size() != 32) {
        m_logger->warn("[SessionManager] Invalid Tritium genesis size: {} (expected 32 bytes)",
                      genesis.size());
        return;
    }

    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.session_genesis = genesis;
    m_session.last_activity = now_epoch_seconds();
    m_logger->info("[SessionManager] Tritium genesis set: {} bytes", genesis.size());
}

void SessionManager::set_connection_metadata(const std::string& local_endpoint,
                                             const std::string& remote_endpoint,
                                             bool connected)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.local_endpoint = local_endpoint;
    m_session.remote_endpoint = remote_endpoint;
    m_session.connected = connected;
    m_session.last_activity = now_epoch_seconds();
}

void SessionManager::set_falcon_identity(const std::vector<uint8_t>& pubkey,
                                         const std::string& key_id,
                                         bool authenticated)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.falcon_pubkey = pubkey;
    m_session.falcon_key_id = key_id;
    m_session.falcon_authenticated = authenticated;
    m_session.last_activity = now_epoch_seconds();
}

void SessionManager::reset_session_credentials()
{
    clear_for_reauth({}, {}, "session credentials reset", true);
}

void SessionManager::set_chacha20_session_key(const std::vector<uint8_t>& session_key,
                                              const std::string& fingerprint,
                                              bool ready)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.chacha20_session_key = session_key;
    m_session.chacha20_key_fingerprint = fingerprint;
    m_session.chacha20_ready = ready;
    m_session.last_activity = now_epoch_seconds();
}

void SessionManager::set_reward_binding(const std::string& reward_address,
                                        const std::vector<uint8_t>& reward_hash,
                                        bool bound,
                                        const std::string& source)
{
    if (bound) {
        commit_reward_bound(reward_address, reward_hash, source);
        return;
    }

    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_hash = reward_hash;
    m_session.reward_bound = false;
    m_session.reward_binding_source = source;
    m_session.reward_state = reward_address.empty() ? RewardState::NONE : RewardState::REQUIRED;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BIND_RESULT,
                                std::string("pending") +
                                    (source.empty() ? "" : (" via " + source)));
}

void SessionManager::set_channel_state(uint32_t channel,
                                       bool ready_for_submit,
                                       bool ready_for_get_block)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.channel = channel;
    m_session.ready_for_submit = ready_for_submit;
    m_session.ready_for_get_block = ready_for_get_block;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
}

void SessionManager::mark_activity()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_activity = now_epoch_seconds();
}

bool SessionManager::is_reward_bound() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.reward_bound;
}

bool SessionManager::reward_binding_required() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return !m_session.reward_address_string.empty() && !m_session.reward_bound;
}

SessionManager::RewardBindReadiness SessionManager::get_reward_bind_readiness() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);

    RewardBindReadiness readiness;

    if (m_session.reward_address_string.empty()) {
        readiness.reason = "no reward address configured in authoritative session state";
        return readiness;
    }

    if (!m_session.authenticated) {
        readiness.reason = "authoritative session is not authenticated";
        return readiness;
    }

    if (m_session.session_id == 0) {
        readiness.reason = "authoritative session is authenticated but missing session_id";
        return readiness;
    }

    if (m_session.reward_bound || m_session.reward_state == RewardState::BOUND) {
        readiness.reason = "reward address is already bound for the authoritative session";
        return readiness;
    }

    if (m_session.session_genesis.empty()) {
        readiness.reason = "authoritative session is missing Tritium genesis required for reward encryption";
        return readiness;
    }

    if (m_session.chacha20_session_key.empty()) {
        readiness.reason = "authoritative session is missing the ChaCha20 reward/session key";
        return readiness;
    }

    if (!m_session.chacha20_ready) {
        readiness.reason = "authoritative ChaCha20 reward/session key is not marked ready";
        return readiness;
    }

    readiness.ready = true;
    readiness.reason = "ready";
    return readiness;
}

bool SessionManager::can_submit_work() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.ready_for_submit;
}

bool SessionManager::can_request_get_block() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.ready_for_get_block;
}

bool SessionManager::allow_deferred_push_replay() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.deferred_push_replay_allowed;
}

bool SessionManager::allow_get_block_replay() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.get_block_replay_allowed;
}

bool SessionManager::validate_miner_session(std::string* reason) const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return validate_miner_session_container_locked(m_session, reason);
}

std::string SessionManager::build_miner_session_diagnostics() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);

    std::ostringstream oss;
    std::string consistency_reason;
    const bool consistency = validate_miner_session_container_locked(m_session, &consistency_reason);

    oss << "MINER SESSION CONTAINER\n"
        << "- remote endpoint: " << (m_session.remote_endpoint.empty() ? "<unset>" : m_session.remote_endpoint) << '\n'
        << "- local endpoint: " << (m_session.local_endpoint.empty() ? "<unset>" : m_session.local_endpoint) << '\n'
        << "- active lane: " << lane_name(m_session.active_lane) << '\n'
        << "- connected: " << (m_session.connected ? "YES" : "NO") << '\n'
        << "- authenticated: " << (m_session.authenticated ? "YES" : "NO") << '\n'
        << "- falcon_key_id: " << (m_session.falcon_key_id.empty() ? "<unset>" : m_session.falcon_key_id) << '\n'
        << "- session_id: 0x" << std::hex << std::setw(8) << std::setfill('0') << m_session.session_id << std::dec << '\n'
        << "- session_epoch: " << m_session.session_epoch << '\n'
        << "- session_genesis: " << (m_session.session_genesis.empty() ? "<unset>" : format_hex_prefix(m_session.session_genesis, 8)) << '\n'
        << "- chacha20_key_fingerprint: " << (m_session.chacha20_key_fingerprint.empty() ? "<unset>" : m_session.chacha20_key_fingerprint) << '\n'
        << "- reward_address_string: " << (m_session.reward_address_string.empty() ? "<unset>" : m_session.reward_address_string) << '\n'
        << "- reward_hash: " << (m_session.reward_hash.empty() ? "<unset>" : format_hex_prefix(m_session.reward_hash, 8)) << '\n'
        << "- reward_state: " << reward_state_name(m_session.reward_state) << '\n'
        << "- prevblock_suffix: " << format_hex_prefix(m_session.prevblock_suffix, 4) << '\n'
        << "- reward_binding_source: " << (m_session.reward_binding_source.empty() ? "<unset>" : m_session.reward_binding_source) << '\n'
        << "- channel: " << m_session.channel << '\n'
        << "- recovery_state: " << recovery_state_name(m_session.recovery_state) << '\n'
        << "- recovery_reason: " << (m_session.recovery_reason.empty() ? "<unset>" : m_session.recovery_reason) << '\n'
        << "- expiry_state: " << expiry_state_name(m_session.expiry_state) << '\n'
        << "- expiry_reason: " << (m_session.expiry_reason.empty() ? "<unset>" : m_session.expiry_reason) << '\n'
        << "- replay_allowances: deferred_push=" << (m_session.deferred_push_replay_allowed ? "YES" : "NO")
        << " get_block=" << (m_session.get_block_replay_allowed ? "YES" : "NO")
        << " queued_partial=" << (m_session.queued_replay_survives_partial_readiness ? "YES" : "NO") << '\n'
        << "- consistency: " << (consistency ? "PASS" : "FAIL") << " (" << consistency_reason << ")\n"
        << "SESSION EVENT JOURNAL";
    if (m_session_event_journal.empty()) {
        oss << "\n- <empty>";
    } else {
        for (const auto& event : m_session_event_journal) {
            oss << "\n- [" << event.timestamp << "] "
                << session_event_kind_name(event.kind)
                << " sid=0x" << std::hex << std::setw(8) << std::setfill('0') << event.session_id.get()
                << std::dec
                << " epoch=" << event.session_epoch.get();
            if (!event.detail.empty()) {
                oss << " detail=" << event.detail;
            }
        }
    }
    return oss.str();
}

const char* SessionManager::session_event_kind_name(SessionEventKind kind)
{
    return protocol::session_event_kind_name(kind);
}

const char* SessionManager::reward_state_name(RewardState state)
{
    return protocol::reward_state_name(state);
}

const char* SessionManager::recovery_state_name(RecoveryState state)
{
    return protocol::recovery_state_name(state);
}

const char* SessionManager::expiry_state_name(ExpiryState state)
{
    return protocol::expiry_state_name(state);
}

void SessionManager::clear_session_event_journal_locked()
{
    m_session_event_journal.clear();
}

void SessionManager::record_session_event_locked(SessionEventKind kind, const std::string& detail)
{
    m_session_event_journal.push_back(SessionEvent{
        now_epoch_seconds(),
        kind,
        SessionId(m_session.session_id),
        SessionEpoch(m_session.session_epoch),
        detail
    });

    while (m_session_event_journal.size() > SESSION_EVENT_JOURNAL_CAPACITY) {
        m_session_event_journal.pop_front();
    }
}

void SessionManager::record_session_event(SessionEventKind kind, const std::string& detail)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    record_session_event_locked(kind, detail);
}

std::vector<SessionManager::SessionEvent> SessionManager::get_session_event_journal() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return std::vector<SessionEvent>(m_session_event_journal.begin(), m_session_event_journal.end());
}

std::string SessionManager::build_session_event_journal() const
{
    const auto journal = get_session_event_journal();

    std::ostringstream oss;
    oss << "SESSION EVENT JOURNAL";
    if (journal.empty()) {
        oss << "\n- <empty>";
        return oss.str();
    }

    for (const auto& event : journal) {
        oss << "\n- [" << event.timestamp << "] "
            << session_event_kind_name(event.kind)
            << " sid=0x" << std::hex << std::setw(8) << std::setfill('0') << event.session_id.get()
            << std::dec
            << " epoch=" << event.session_epoch.get();
        if (!event.detail.empty()) {
            oss << " detail=" << event.detail;
        }
    }

    return oss.str();
}

bool SessionManager::validate_miner_session_container_locked(const MinerSessionContainer& session,
                                                             std::string* reason)
{
    auto fail = [&](const std::string& message) {
        if (reason) {
            *reason = message;
        }
        return false;
    };

    if (session.connected && session.active_lane == ProtocolLane::UNKNOWN) {
        return fail("connected session has UNKNOWN lane");
    }

    if (session.authenticated) {
        if (session.session_id == 0) {
            return fail("authenticated session missing session_id");
        }
        if (!session.falcon_authenticated) {
            return fail("authenticated session missing Falcon auth");
        }
    }

    if (session.chacha20_ready) {
        if (session.session_genesis.empty()) {
            return fail("ChaCha20 ready without session genesis");
        }
        if (session.chacha20_session_key.empty()) {
            return fail("ChaCha20 ready without session key");
        }
        if (format_hex_prefix(session.chacha20_session_key, 8) != session.chacha20_key_fingerprint) {
            return fail("ChaCha20 fingerprint does not match stored key");
        }
    }

    if (!session.reward_address_string.empty() && session.ready_for_submit && !session.reward_bound) {
        return fail("submit marked ready before reward binding");
    }

    if (session.reward_bound && !session.reward_address_string.empty() && session.reward_hash.empty()) {
        return fail("reward bound without decoded reward hash");
    }

    if (session.reward_bound && session.reward_state != RewardState::BOUND) {
        return fail("reward bound flag disagrees with reward state");
    }

    if (!session.reward_bound && session.reward_state == RewardState::BOUND) {
        return fail("reward state marked BOUND without reward_bound flag");
    }

    if (session.deferred_push_replay_allowed && !session.authenticated) {
        return fail("deferred replay allowed without authenticated session");
    }

    if (session.get_block_replay_allowed && !session.ready_for_get_block) {
        return fail("GET_BLOCK replay allowed before readiness");
    }

    if (session.queued_replay_survives_partial_readiness && !session.authenticated) {
        return fail("queued replay survival enabled without authenticated session");
    }

    if (reason) {
        *reason = "PASS";
    }
    return true;
}

std::chrono::seconds SessionManager::get_session_uptime_locked() const
{
    if (m_session.state == SessionState::DISCONNECTED) {
        return std::chrono::seconds(0);
    }

    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(
        now - m_session.session_start);
}

std::chrono::seconds SessionManager::get_session_uptime() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return get_session_uptime_locked();
}

std::chrono::seconds SessionManager::get_time_until_keepalive() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    if (m_session.state != SessionState::AUTHENTICATED &&
        m_session.state != SessionState::ACTIVE) {
        return std::chrono::seconds(0);
    }

    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_session.last_keepalive);

    auto interval_seconds = std::chrono::hours(m_keepalive_interval_hours);
    auto remaining = interval_seconds - elapsed;

    return std::max(remaining, std::chrono::seconds(0));
}

SessionManager::RuntimeSessionSnapshot SessionManager::get_runtime_snapshot() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session;
}

SessionManager::SessionInfo SessionManager::get_session_info() const
{
    return get_runtime_snapshot();
}

void SessionManager::set_prevblock_suffix(const std::array<uint8_t, 4>& suffix)
{
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        m_session.prevblock_suffix = suffix;
    }
    m_logger->debug("[SessionManager] prevblock_suffix updated: {:02x}{:02x}{:02x}{:02x}",
                   suffix[0], suffix[1], suffix[2], suffix[3]);
}

void SessionManager::transition_to_authenticated_locked(
    uint32_t session_id,
    const std::vector<uint8_t>& tritium_genesis)
{
    if (m_session.session_epoch == std::numeric_limits<uint64_t>::max()) {
        // Saturate at max rather than wrapping to 0 so stale-packet guards never
        // observe a "new" epoch that is numerically older than prior sessions.
        m_logger->warn("[SessionManager] Session epoch overflow avoided; saturating at max epoch value");
    } else {
        ++m_session.session_epoch;
    }

    m_session.session_id = session_id;
    if (!tritium_genesis.empty()) {
        m_session.session_genesis = tritium_genesis;
    }
    m_session.state = SessionState::AUTHENTICATED;
    m_session.authenticated = (session_id != 0);
    m_session.falcon_authenticated = (session_id != 0);
    m_session.created_at = now_epoch_seconds();
    m_session.ready_for_submit = false;
    m_session.ready_for_get_block = false;
    m_session.reward_state = m_session.reward_address_string.empty() ? RewardState::NONE
                                                                     : RewardState::REQUIRED;
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.recovery_reason.clear();
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();
    m_session.session_start = std::chrono::system_clock::now();
    m_session.last_keepalive = m_session.session_start;
    m_session.keepalive_count = 0;
    m_session.last_auth_time = now_epoch_seconds();
    m_session.last_activity = m_session.last_auth_time;
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::AUTH_SUCCESS,
                                "session authenticated with node");
    std::ostringstream session_detail;
    session_detail << "session_id=0x" << std::hex << std::setw(8) << std::setfill('0')
                   << session_id << std::dec;
    record_session_event_locked(SessionEventKind::SESSION_START, session_detail.str());
}

void SessionManager::clear_runtime_session_locked(bool preserve_genesis,
                                                  bool clear_prevblock_suffix)
{
    m_session.session_id = 0;
    m_session.session_key.clear();
    m_session.chacha20_session_key.clear();
    m_session.chacha20_key_fingerprint.clear();
    m_session.chacha20_ready = false;
    m_session.authenticated = false;
    m_session.falcon_authenticated = false;
    m_session.reward_bound = false;
    m_session.reward_hash.clear();
    m_session.reward_state = m_session.reward_address_string.empty() ? RewardState::NONE
                                                                     : RewardState::REQUIRED;
    if (clear_prevblock_suffix) {
        m_session.prevblock_suffix = CLEARED_PREVBLOCK_SUFFIX;
    }
    m_session.ready_for_submit = false;
    m_session.ready_for_get_block = false;
    if (!preserve_genesis) {
        m_session.session_genesis.clear();
    }
    m_session.state = SessionState::DISCONNECTED;
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();
    m_session.keepalive_count = 0;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
}

void SessionManager::update_replay_allowances_locked()
{
    m_session.deferred_push_replay_allowed = m_session.authenticated;
    m_session.get_block_replay_allowed = m_session.ready_for_get_block;
    m_session.queued_replay_survives_partial_readiness =
        m_session.authenticated &&
        (m_session.reward_bound || m_session.ready_for_get_block || m_session.ready_for_submit);
}

void SessionManager::set_keepalive_interval(uint16_t hours)
{
    // Clamp to reasonable range
    if (hours < MIN_KEEPALIVE_HOURS) hours = MIN_KEEPALIVE_HOURS;
    if (hours > MAX_KEEPALIVE_HOURS) hours = MAX_KEEPALIVE_HOURS;
    
    if (m_keepalive_interval_hours != hours) {
        m_logger->info("[SessionManager] Keepalive interval changed: {} -> {} hours",
                      m_keepalive_interval_hours, hours);
        m_keepalive_interval_hours = hours;

        // If timer is running, reschedule it with the new interval immediately
        // Note: cancel() is safe - it triggers pending async_wait with operation_aborted error,
        // which is handled by the error check in schedule_regular_keepalives callback
        if (m_keepalive_active && m_keepalive_timer) {
            auto self = shared_from_this();
            m_keepalive_timer->cancel();
            schedule_regular_keepalives(self);
        }
    }
}

void SessionManager::set_protocol_lane(ProtocolLane lane)
{
    ProtocolLane old_lane = ProtocolLane::UNKNOWN;
    {
        // Keep protocol-lane and session-container updates under the same guard
        // so lane switches cannot observe partial state or require lock ordering.
        std::lock_guard<std::mutex> lock(m_session_mutex);
        old_lane = m_protocol_lane;
        m_protocol_lane = lane;
        m_session.active_lane = lane;
        m_session.last_activity = now_epoch_seconds();
    }

    if (old_lane != lane) {
        m_logger->info("[SessionManager] Protocol lane changed: {} -> {}",
                       lane_name(old_lane), lane_name(lane));
    }
}

uint16_t SessionManager::map_auth_opcode(uint8_t legacy_opcode) const
{
    ProtocolLane lane;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        lane = m_protocol_lane;
    }

    if (lane == ProtocolLane::STATELESS) {
        return static_cast<uint16_t>(0xD000 | legacy_opcode);  // Mirror-map
    }
    return static_cast<uint16_t>(legacy_opcode);  // Legacy as-is
}

} // namespace protocol
} // namespace nexusminer
