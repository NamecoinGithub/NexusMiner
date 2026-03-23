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

constexpr uint16_t MIN_KEEPALIVE_HOURS = 1;
constexpr uint16_t MAX_KEEPALIVE_HOURS = 168;
constexpr auto KEEPALIVE_EARLY_INTERVAL = std::chrono::seconds(10);
constexpr auto KEEPALIVE_TCP_INTERVAL   = std::chrono::seconds(45);

namespace {

constexpr std::array<uint8_t, 4> CLEARED_PREVBLOCK_SUFFIX{0, 0, 0, 0};

uint64_t now_epoch_seconds()
{
    return static_cast<uint64_t>(std::time(nullptr));
}

const char* lane_name(ProtocolLane lane)
{
    switch (lane) {
        case ProtocolLane::LEGACY:    return "LEGACY";
        case ProtocolLane::STATELESS: return "STATELESS";
        default:                      return "UNKNOWN";
    }
}

const char* session_state_name(SessionManager::SessionState state)
{
    switch (state) {
        case SessionManager::SessionState::DISCONNECTED:  return "DISCONNECTED";
        case SessionManager::SessionState::AUTHENTICATING: return "AUTHENTICATING";
        case SessionManager::SessionState::AUTHENTICATED: return "AUTHENTICATED";
        case SessionManager::SessionState::DEGRADED:      return "DEGRADED";
        default:                                          return "UNKNOWN";
    }
}

} // namespace

// ── Static name helpers ───────────────────────────────────────────────────────

const char* SessionManager::session_event_kind_name(SessionEventKind kind)
{
    switch (kind) {
        case SessionEventKind::AUTH_INIT:          return "auth_init";
        case SessionEventKind::AUTH_SUCCESS:       return "auth_success";
        case SessionEventKind::SESSION_START:      return "session_start";
        case SessionEventKind::REWARD_BIND_SENT:   return "reward_bind_sent";
        case SessionEventKind::REWARD_BOUND:       return "reward_bind_result";
        case SessionEventKind::KEEPALIVE_ACK:      return "keepalive_ack";
        case SessionEventKind::KEEPALIVE_MISSED:   return "keepalive_missed";
        case SessionEventKind::STATUS_ACK_ACCEPTED: return "status_ack_accepted";
        case SessionEventKind::STATUS_ACK_REJECTED: return "status_ack_rejected";
        case SessionEventKind::DEGRADED:           return "forced_reauth";
        case SessionEventKind::DISCONNECTED:       return "disconnected";
        case SessionEventKind::SESSION_RESET:      return "session_reset";
        case SessionEventKind::SUBMIT_SENT:        return "submit_sent";
        case SessionEventKind::SUBMIT_ACCEPTED:    return "submit_accepted";
        case SessionEventKind::SUBMIT_REJECTED:    return "submit_rejected";
        case SessionEventKind::STALE_PACKET_DROPPED: return "stale_packet_dropped";
        case SessionEventKind::EPOCH_MISMATCH:     return "epoch_mismatch";
        case SessionEventKind::RECOVERY_REQUESTED: return "recovery_requested";
        case SessionEventKind::RECOVERY_HEALTHY:   return "recovery_healthy";
    }
    return "unknown";
}

const char* SessionManager::reward_state_name(RewardState state)
{
    switch (state) {
        case RewardState::NONE:     return "NONE";
        case RewardState::REQUIRED: return "REQUIRED";
        case RewardState::BINDING:  return "BINDING";
        case RewardState::BOUND:    return "BOUND";
        case RewardState::REJECTED: return "REJECTED";
        case RewardState::STALE:    return "STALE";
    }
    return "UNKNOWN";
}

const char* SessionManager::recovery_state_name(RecoveryState state)
{
    switch (state) {
        case RecoveryState::HEALTHY:                  return "HEALTHY";
        case RecoveryState::RECOVERY_PENDING:         return "RECOVERY_PENDING";
        case RecoveryState::RECOVERY_IN_PROGRESS:     return "RECOVERY_IN_PROGRESS";
        case RecoveryState::FORCED_REAUTH:            return "FORCED_REAUTH";
        case RecoveryState::RECONNECT_REQUIRED:       return "RECONNECT_REQUIRED";
    }
    return "UNKNOWN";
}

const char* SessionManager::expiry_state_name(ExpiryState state)
{
    switch (state) {
        case ExpiryState::FRESH:                      return "FRESH";
        case ExpiryState::KEEPALIVE_MISMATCH_WARNING: return "KEEPALIVE_MISMATCH_WARNING";
        case ExpiryState::STALE_ACK_IGNORED:          return "STALE_ACK_IGNORED";
        case ExpiryState::EXPIRED_ACCEPTED:           return "EXPIRED_ACCEPTED";
        case ExpiryState::EXPIRED_REJECTED:           return "EXPIRED_REJECTED";
        case ExpiryState::AUTH_TIMEOUT:               return "AUTH_TIMEOUT";
        case ExpiryState::DEAD_SESSION_TIMEOUT:       return "DEAD_SESSION_TIMEOUT";
    }
    return "UNKNOWN";
}

// ── Constructors ──────────────────────────────────────────────────────────────

SessionManager::SessionManager(std::shared_ptr<asio::io_context> io_context)
    : SessionManager(12, std::move(io_context))
{
}

SessionManager::SessionManager(uint16_t keepalive_interval_hours,
                               std::shared_ptr<asio::io_context> io_context)
    : m_session{}
    , m_keepalive_interval_hours(keepalive_interval_hours)
    , m_preserve_genesis_on_disconnect(true)
    , m_protocol_lane(ProtocolLane::UNKNOWN)
    , m_io_context(std::move(io_context))
    , m_keepalive_timer(nullptr)
    , m_keepalive_active(false)
    , m_logger(spdlog::get("logger"))
{
    if (!m_logger) {
        m_logger = spdlog::default_logger();
    }
    if (m_keepalive_interval_hours < MIN_KEEPALIVE_HOURS)
        m_keepalive_interval_hours = MIN_KEEPALIVE_HOURS;
    if (m_keepalive_interval_hours > MAX_KEEPALIVE_HOURS)
        m_keepalive_interval_hours = MAX_KEEPALIVE_HOURS;

    m_session.created_at = now_epoch_seconds();
    m_session.last_activity = m_session.created_at;
    m_session.state = SessionState::DISCONNECTED;
    m_session.reward_state = RewardState::NONE;
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.expiry_state = ExpiryState::FRESH;
}

SessionManager::~SessionManager()
{
    stop_keepalive_timer();
}

// ── Private helpers ───────────────────────────────────────────────────────────

void SessionManager::clear_runtime_session_locked(bool preserve_genesis,
                                                   bool clear_prevblock_suffix)
{
    const auto saved_genesis   = m_session.session_genesis;
    const auto saved_addr      = m_session.reward_address_string;
    const auto saved_addr_new  = m_session.reward_address;
    const auto saved_src       = m_session.reward_binding_source;
    const auto saved_suffix    = m_session.prevblock_suffix;
    const auto created_at      = m_session.created_at;

    m_session = SessionInfo{};
    m_session.created_at = created_at;
    m_session.last_activity = now_epoch_seconds();
    m_session.state = SessionState::DISCONNECTED;
    m_session.reward_state = RewardState::NONE;
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.expiry_state = ExpiryState::FRESH;

    if (preserve_genesis) {
        m_session.session_genesis = saved_genesis;
    }
    if (!clear_prevblock_suffix) {
        m_session.prevblock_suffix = saved_suffix;
    }
}

void SessionManager::transition_to_authenticated_locked(uint32_t session_id,
                                                         const std::vector<uint8_t>& tritium_genesis)
{
    ++m_session.session_epoch;
    m_session.session_id = session_id;
    m_session.state = SessionState::AUTHENTICATED;
    m_session.authenticated = true;
    m_session.falcon_authenticated = true;
    m_session.last_auth_time = now_epoch_seconds();
    m_session.last_activity = m_session.last_auth_time;
    m_session.session_start = m_session.last_auth_time;
    m_session.session_start_tp = std::chrono::system_clock::now();
    m_session.active_lane = m_protocol_lane;
    if (!tritium_genesis.empty()) {
        m_session.session_genesis = tritium_genesis;
    }
    update_replay_allowances_locked();

    record_session_event_locked(SessionEventKind::AUTH_SUCCESS, "authenticated");
    std::ostringstream sid_oss;
    sid_oss << "session_id=0x" << std::hex << std::setw(8) << std::setfill('0') << session_id;
    record_session_event_locked(SessionEventKind::SESSION_START, sid_oss.str());
}

void SessionManager::update_replay_allowances_locked()
{
    // Derivation rules:
    //   ready_for_get_block: requires authentication only
    //   ready_for_submit:    requires authentication AND reward binding
    //   replay allowances mirror the same logic
    const bool authenticated = (m_session.state == SessionState::AUTHENTICATED);
    m_session.deferred_push_replay_allowed = authenticated;
    m_session.get_block_replay_allowed = authenticated;
    m_session.ready_for_get_block = authenticated;
    m_session.ready_for_submit = authenticated && m_session.reward_bound;
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

// ── Core lifecycle (new minimal API) ─────────────────────────────────────────

void SessionManager::begin_auth()
{
    begin_auth_handshake("auth started");
}

void SessionManager::commit_authenticated(uint32_t session_id, ProtocolLane lane,
                                          const std::string& reward_address)
{
    m_protocol_lane = lane;
    commit_authenticated_session(session_id, {}, {}, {});
    if (!reward_address.empty()) {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        m_session.reward_address = reward_address;
        m_session.reward_address_string = reward_address;
        m_session.reward_state = RewardState::REQUIRED;
    }
}

void SessionManager::commit_reward_bound(const std::string& reward_address,
                                         const std::string& source)
{
    commit_reward_bound(reward_address, std::vector<uint8_t>{}, source);
}

void SessionManager::mark_degraded(const std::string& reason)
{
    mark_session_expired(reason);
}

// ── Backward-compat lifecycle ─────────────────────────────────────────────────

void SessionManager::begin_auth_handshake(const std::string& detail)
{
    stop_keepalive_timer();

    std::lock_guard<std::mutex> lock(m_session_mutex);
    const auto retained_reward_address = m_session.reward_address_string;
    const auto retained_reward_address_new = m_session.reward_address;
    const auto retained_reward_source = m_session.reward_binding_source;
    const auto retained_chacha20_session_key = m_session.chacha20_session_key;
    const auto retained_chacha20_key_fingerprint = m_session.chacha20_key_fingerprint;
    const bool retained_chacha20_ready = m_session.chacha20_ready;
    clear_runtime_session_locked(true, true);
    m_session.reward_address_string = retained_reward_address;
    m_session.reward_address = retained_reward_address_new;
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
        if (!pubkey.empty()) {
            m_session.falcon_pubkey = pubkey;
        }
        if (!key_id.empty()) {
            m_session.falcon_key_id = key_id;
        }
        transition_to_authenticated_locked(session_id, tritium_genesis);
    }
    m_logger->info("[SessionManager] Session started - ID: 0x{:08X}, epoch={}",
                   session_id, get_session_epoch());
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
        if (!session_key.empty()) {
            m_session.session_key = session_key;
        }
        transition_to_authenticated_locked(session_id, tritium_genesis);
    }
    m_logger->info("[SessionManager] Session started - ID: 0x{:08X}, epoch={}",
                   session_id, get_session_epoch());
}

void SessionManager::mark_session_expired(const std::string& reason)
{
    bool notify = false;
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        notify = (m_session.state != SessionState::DEGRADED);
        m_session.state = SessionState::DEGRADED;
        m_session.authenticated = false;
        m_session.expiry_state = ExpiryState::EXPIRED_ACCEPTED;
        m_session.expiry_reason = reason;
        m_session.recovery_state = RecoveryState::FORCED_REAUTH;
        m_session.recovery_reason = reason;
        m_session.ready_for_submit = false;
        m_session.ready_for_get_block = false;
        m_session.deferred_push_replay_allowed = false;
        m_session.get_block_replay_allowed = false;
        if (m_session.reward_bound) {
            m_session.reward_state = RewardState::STALE;
        }
        m_session.last_activity = now_epoch_seconds();
        record_session_event_locked(SessionEventKind::DEGRADED,
                                    reason.empty() ? "session marked expired" : reason);
    }
    if (notify && m_session_expired_handler) {
        m_session_expired_handler();
    }
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
        m_session.state == SessionState::DEGRADED) {
        return;
    }
    m_session.recovery_state = RecoveryState::HEALTHY;
    m_session.recovery_reason.clear();
    m_session.last_activity = now_epoch_seconds();
    record_session_event_locked(SessionEventKind::RECOVERY_HEALTHY,
                                reason.empty() ? "recovery healthy" : reason);
}

void SessionManager::clear_for_disconnect(const std::string& reward_address,
                                          const std::string& reward_source,
                                          const std::string& reason,
                                          bool preserve_genesis)
{
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        const auto retained_reward_address =
            reward_address.empty() ? m_session.reward_address_string : reward_address;
        const auto retained_reward_source =
            reward_source.empty() ? m_session.reward_binding_source : reward_source;

        clear_runtime_session_locked(preserve_genesis, false);
        m_session.reward_address_string = retained_reward_address;
        m_session.reward_address = retained_reward_address;
        m_session.reward_binding_source = retained_reward_source;
        m_session.reward_state = retained_reward_address.empty() ? RewardState::NONE
                                                                 : RewardState::REQUIRED;
        m_session.recovery_state = RecoveryState::RECONNECT_REQUIRED;
        m_session.recovery_reason = reason;
        m_session.expiry_state = ExpiryState::FRESH;
        update_replay_allowances_locked();
        record_session_event_locked(SessionEventKind::SESSION_RESET,
                                    reason.empty() ? "session cleared for disconnect" : reason);
    }
    stop_keepalive_timer();
}

void SessionManager::clear_for_reauth(const std::string& reward_address,
                                      const std::string& reward_source,
                                      const std::string& reason,
                                      bool preserve_genesis)
{
    stop_keepalive_timer();
    std::lock_guard<std::mutex> lock(m_session_mutex);
    const auto retained_reward_address =
        reward_address.empty() ? m_session.reward_address_string : reward_address;
    const auto retained_reward_source =
        reward_source.empty() ? m_session.reward_binding_source : reward_source;
    clear_runtime_session_locked(preserve_genesis, true);
    m_session.reward_address_string = retained_reward_address;
    m_session.reward_address = retained_reward_address;
    m_session.reward_binding_source = retained_reward_source;
    m_session.reward_state = retained_reward_address.empty() ? RewardState::NONE
                                                             : RewardState::REQUIRED;
    m_session.recovery_state = RecoveryState::FORCED_REAUTH;
    m_session.recovery_reason = reason;
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::SESSION_RESET,
                                reason.empty() ? "session cleared for reauth" : reason);
}

void SessionManager::end_session()
{
    clear_for_disconnect({}, {}, "", m_preserve_genesis_on_disconnect);
}

// ── Reward binding ────────────────────────────────────────────────────────────

void SessionManager::begin_reward_binding(const std::string& addr,
                                          const std::vector<uint8_t>& hash,
                                          const std::string& src)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = addr;
    m_session.reward_address = addr;
    m_session.reward_hash = hash;
    m_session.reward_bound = false;
    m_session.reward_binding_source = src;
    m_session.reward_state = addr.empty() ? RewardState::NONE : RewardState::BINDING;
    m_session.ready_for_submit = false;
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BIND_SENT,
                                addr.empty() ? "reward binding requested"
                                             : "reward binding requested for " + addr);
}

void SessionManager::commit_reward_bound(const std::string& reward_address,
                                         const std::vector<uint8_t>& reward_hash,
                                         const std::string& source)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_address = reward_address;
    m_session.reward_hash = reward_hash;
    m_session.reward_bound = true;
    m_session.reward_binding_source = source;
    m_session.reward_state = reward_address.empty() ? RewardState::NONE : RewardState::BOUND;
    m_session.last_reward_bind_time = now_epoch_seconds();
    m_session.last_activity = now_epoch_seconds();
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BOUND,
                                "accepted" + (source.empty() ? "" : " via " + source));
}

void SessionManager::commit_reward_rejected(const std::string& addr,
                                            const std::string& src,
                                            const std::string& rsn)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = addr;
    m_session.reward_address = addr;
    m_session.reward_hash.clear();
    m_session.reward_bound = false;
    m_session.reward_binding_source = src;
    m_session.reward_state = addr.empty() ? RewardState::NONE : RewardState::REJECTED;
    m_session.ready_for_submit = false;
    update_replay_allowances_locked();
    record_session_event_locked(SessionEventKind::REWARD_BOUND,
                                "rejected" + (src.empty() ? "" : " via " + src)
                                + (rsn.empty() ? "" : ": " + rsn));
}

// ── Keepalive ack / note ──────────────────────────────────────────────────────

void SessionManager::note_keepalive_ack(bool accepted, const std::string& detail)
{
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        m_session.last_activity = now_epoch_seconds();
        if (accepted) {
            m_session.expiry_state = ExpiryState::FRESH;
            m_session.expiry_reason.clear();
            record_session_event_locked(SessionEventKind::KEEPALIVE_ACK,
                                        detail.empty() ? "keepalive ack accepted" : detail);
        } else {
            m_session.expiry_state = ExpiryState::KEEPALIVE_MISMATCH_WARNING;
            m_session.expiry_reason = detail;
            record_session_event_locked(SessionEventKind::KEEPALIVE_ACK,
                                        detail.empty() ? "keepalive ack rejected" : detail);
        }
    }
    if (accepted) {
        record_keepalive_ack(true);
    }
}

void SessionManager::record_keepalive_ack(bool accepted)
{
    if (accepted) {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        if (m_session.state == SessionState::AUTHENTICATED) {
            m_session.state = SessionState::ACTIVE;
        }
    }
}

void SessionManager::record_keepalive()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_keepalive = std::chrono::system_clock::now();
    m_session.keepalive_count++;
    m_session.last_activity = now_epoch_seconds();
    if (m_session.state == SessionState::AUTHENTICATED) {
        m_session.state = SessionState::ACTIVE;
    }
    m_session.expiry_state = ExpiryState::FRESH;
    m_session.expiry_reason.clear();
}

// ── No-op setters ─────────────────────────────────────────────────────────────

void SessionManager::set_connection_metadata(const std::string& local,
                                             const std::string& remote,
                                             bool connected)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.local_endpoint = local;
    m_session.remote_endpoint = remote;
    m_session.connected = connected;
    m_session.active_lane = m_protocol_lane;
}

void SessionManager::set_falcon_identity(const std::vector<uint8_t>& pubkey,
                                          const std::string& key_id, bool authenticated)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.falcon_pubkey = pubkey;
    m_session.falcon_key_id = key_id;
    m_session.falcon_authenticated = authenticated;
}

void SessionManager::reset_session_credentials()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.falcon_pubkey.clear();
    m_session.falcon_key_id.clear();
    m_session.falcon_authenticated = false;
    m_session.chacha20_session_key.clear();
    m_session.chacha20_key_fingerprint.clear();
    m_session.chacha20_ready = false;
    m_session.ready_for_submit = false;
    m_session.ready_for_get_block = false;
}

void SessionManager::set_chacha20_session_key(const std::vector<uint8_t>& key,
                                               const std::string& fingerprint, bool ready)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.chacha20_session_key = key;
    m_session.chacha20_key_fingerprint = fingerprint;
    m_session.chacha20_ready = ready;
}

void SessionManager::set_reward_binding(const std::string& addr,
                                        const std::vector<uint8_t>& hash,
                                        bool bound,
                                        const std::string& src)
{
    // Delegates to the appropriate commit method
    if (bound) {
        commit_reward_bound(addr, hash, src);
    } else {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        m_session.reward_address_string = addr;
        m_session.reward_address = addr;
        m_session.reward_hash = hash;
        m_session.reward_bound = false;
        m_session.reward_binding_source = src;
        m_session.reward_state = addr.empty() ? RewardState::NONE : RewardState::REQUIRED;
        update_replay_allowances_locked();
    }
}

void SessionManager::set_channel_state(uint32_t channel,
                                       bool ready_for_submit,
                                       bool ready_for_get_block)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.channel = channel;
    if (ready_for_submit) m_session.ready_for_submit = ready_for_submit;
    if (ready_for_get_block) m_session.ready_for_get_block = ready_for_get_block;
}

void SessionManager::mark_activity()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_activity = now_epoch_seconds();
}

void SessionManager::set_tritium_genesis(const std::vector<uint8_t>& genesis)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.session_genesis = genesis;
}

void SessionManager::set_keepalive_interval(uint16_t hours)
{
    m_keepalive_interval_hours = hours;
    if (m_keepalive_interval_hours < MIN_KEEPALIVE_HOURS)
        m_keepalive_interval_hours = MIN_KEEPALIVE_HOURS;
    if (m_keepalive_interval_hours > MAX_KEEPALIVE_HOURS)
        m_keepalive_interval_hours = MAX_KEEPALIVE_HOURS;
}

void SessionManager::set_keepalive_interval_seconds(uint32_t /*seconds*/)
{
    // no-op in minimal design — TCP keepalive is fixed at 45s
}

void SessionManager::set_prevblock_suffix(const std::array<uint8_t, 4>& suffix)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.prevblock_suffix = suffix;
}

void SessionManager::set_protocol_lane(ProtocolLane lane)
{
    m_protocol_lane = lane;
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.active_lane = lane;
}

void SessionManager::set_connection(std::shared_ptr<network::Connection> connection)
{
    m_connection = connection;
}

void SessionManager::set_state(SessionState state)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.state = state;
    m_session.authenticated = (state == SessionState::AUTHENTICATED);
}

// ── State queries ─────────────────────────────────────────────────────────────

bool SessionManager::is_authenticated() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.authenticated;
}

bool SessionManager::is_degraded() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.state == SessionState::DEGRADED;
}

bool SessionManager::is_reward_bound() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.reward_bound;
}

bool SessionManager::can_submit() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.authenticated && m_session.reward_bound;
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

bool SessionManager::reward_binding_required() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return !m_session.reward_address_string.empty() && !m_session.reward_bound;
}

SessionManager::RewardBindReadiness SessionManager::get_reward_bind_readiness() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    RewardBindReadiness r;
    if (!m_session.authenticated) {
        r.reason = "not authenticated";
        return r;
    }
    if (m_session.reward_address_string.empty()) {
        r.reason = "no reward address configured";
        return r;
    }
    if (m_session.reward_bound) {
        r.reason = "already bound";
        return r;
    }
    r.ready = true;
    r.reason = "ready";
    return r;
}

bool SessionManager::validate_miner_session(std::string* reason) const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return validate_miner_session_container_locked(m_session, reason);
}

// static
bool SessionManager::validate_miner_session_container_locked(const SessionInfo& session,
                                                              std::string* reason)
{
    auto fail = [&](const std::string& msg) {
        if (reason) *reason = msg;
        return false;
    };

    if (!session.authenticated) {
        return fail("session not authenticated");
    }
    if (session.session_id == 0) {
        return fail("authenticated session missing session_id");
    }
    if (reason) *reason = "PASS";
    return true;
}

std::string SessionManager::build_miner_session_diagnostics() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    std::string consistency_reason;
    const bool consistency = validate_miner_session_container_locked(m_session, &consistency_reason);

    std::ostringstream oss;
    oss << "MINER SESSION CONTAINER\n"
        << "- active lane: "   << lane_name(m_session.active_lane) << '\n'
        << "- authenticated: " << (m_session.authenticated ? "YES" : "NO") << '\n'
        << "- session_id: 0x"  << std::hex << std::setw(8) << std::setfill('0')
                               << m_session.session_id << std::dec << '\n'
        << "- session_epoch: " << m_session.session_epoch << '\n'
        << "- reward_address: " << (m_session.reward_address_string.empty()
                                     ? "<unset>" : m_session.reward_address_string) << '\n'
        << "- reward_bound: "  << (m_session.reward_bound ? "YES" : "NO") << '\n'
        << "- reward_state: "  << reward_state_name(m_session.reward_state) << '\n'
        << "- prevblock_suffix: " << format_hex_prefix(m_session.prevblock_suffix, 4) << '\n'
        << "- recovery_state: "<< recovery_state_name(m_session.recovery_state) << '\n'
        << "- expiry_state: "  << expiry_state_name(m_session.expiry_state) << '\n'
        << "- consistency: "   << (consistency ? "PASS" : "FAIL")
                               << " (" << consistency_reason << ")\n";
    oss << "SESSION EVENT JOURNAL";
    if (m_session_event_journal.empty()) {
        oss << "\n- <empty>";
    } else {
        for (const auto& ev : m_session_event_journal) {
            oss << "\n- [" << ev.timestamp << "] "
                << session_event_kind_name(ev.kind)
                << " sid=0x" << std::hex << std::setw(8) << std::setfill('0')
                << ev.session_id.get() << std::dec
                << " epoch=" << ev.session_epoch.get();
            if (!ev.detail.empty()) oss << " detail=" << ev.detail;
        }
    }
    return oss.str();
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

SessionManager::SessionState SessionManager::get_state() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.state;
}

SessionManager::SessionInfo SessionManager::get_session_info() const
{
    return get_runtime_snapshot();
}

SessionManager::RuntimeSessionSnapshot SessionManager::get_runtime_snapshot() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session;
}

std::chrono::seconds SessionManager::get_session_uptime_locked() const
{
    if (m_session.session_start == 0) return std::chrono::seconds(0);
    const auto now = now_epoch_seconds();
    if (now < m_session.session_start) return std::chrono::seconds(0);
    return std::chrono::seconds(now - m_session.session_start);
}

std::chrono::seconds SessionManager::get_session_uptime() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return get_session_uptime_locked();
}

std::vector<uint8_t> SessionManager::get_session_key() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.chacha20_session_key;
}

std::vector<uint8_t> SessionManager::get_tritium_genesis() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session.session_genesis;
}

uint16_t SessionManager::map_auth_opcode(uint8_t legacy_opcode) const
{
    if (m_protocol_lane == ProtocolLane::STATELESS) {
        return static_cast<uint16_t>(0xD000 | legacy_opcode);
    }
    return static_cast<uint16_t>(legacy_opcode);
}

// ── Session event journal ─────────────────────────────────────────────────────

void SessionManager::record_session_event(SessionEventKind kind, const std::string& detail)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    record_session_event_locked(kind, detail);
}

std::vector<SessionManager::SessionEvent> SessionManager::get_session_event_journal() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return std::vector<SessionEvent>(m_session_event_journal.begin(),
                                     m_session_event_journal.end());
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
    for (const auto& ev : journal) {
        oss << "\n- [" << ev.timestamp << "] "
            << session_event_kind_name(ev.kind)
            << " sid=0x" << std::hex << std::setw(8) << std::setfill('0')
            << ev.session_id.get() << std::dec
            << " epoch=" << ev.session_epoch.get();
        if (!ev.detail.empty()) oss << " detail=" << ev.detail;
    }
    return oss.str();
}

// ── Keepalive timer ───────────────────────────────────────────────────────────

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
        if (error || !self->m_keepalive_active || !self->is_active()) return;
        if (generation != self->m_keepalive_generation.load()) return;
        self->send_keepalive("early");
        self->schedule_regular_keepalives(self);
    });
    m_logger->info("[SessionManager] Keepalive timer started (early: {}s, TCP ping: {}s)",
                  KEEPALIVE_EARLY_INTERVAL.count(), KEEPALIVE_TCP_INTERVAL.count());
}

void SessionManager::stop_keepalive_timer()
{
    m_keepalive_active = false;
    ++m_keepalive_generation;
    if (m_keepalive_timer) {
        m_keepalive_timer->cancel();
    }
}

void SessionManager::schedule_regular_keepalives(const std::shared_ptr<SessionManager>& self)
{
    if (!m_keepalive_timer || !m_keepalive_active) return;
    uint64_t generation = m_keepalive_generation.load();
    m_keepalive_timer->expires_after(KEEPALIVE_TCP_INTERVAL);
    m_keepalive_timer->async_wait([self, generation](const asio::error_code& error) {
        if (error || !self->m_keepalive_active || !self->is_active()) return;
        if (generation != self->m_keepalive_generation.load()) return;
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
    if (session_id == 0) return {};
    if (lane == ProtocolLane::UNKNOWN) {
        m_logger->error("[SessionManager] build_keepalive_packet(): UNKNOWN protocol lane");
        return {};
    }

    std::vector<uint8_t> payload;
    serialization::append_uint32_le(payload, session_id);
    payload.insert(payload.end(), prevblock_suffix.begin(), prevblock_suffix.end());

    Packet packet = (lane == ProtocolLane::STATELESS)
        ? Packet{ LLP::StatelessMining::SESSION_KEEPALIVE,
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
    if (session_id == 0) return {};
    if (lane == ProtocolLane::UNKNOWN) {
        m_logger->error("[SessionManager] build_session_status_packet(): UNKNOWN protocol lane");
        return {};
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

    Packet packet = (lane == ProtocolLane::STATELESS)
        ? Packet{ static_cast<uint16_t>(SESSION_STATUS),
                  std::make_shared<network::Payload>(payload) }
        : Packet{ static_cast<uint8_t>(SESSION_STATUS_LEGACY),
                  std::make_shared<network::Payload>(payload) };

    return packet.get_bytes();
}

} // namespace protocol
} // namespace nexusminer
