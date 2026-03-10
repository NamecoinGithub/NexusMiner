#include "protocol/session_manager.hpp"
#include "protocol/hex_prefix_utils.hpp"
#include "protocol/serialization_helpers.hpp"
#include "network/connection.hpp"
#include "packet.hpp"
#include "miner_opcodes.hpp"
#include <algorithm>
#include <ctime>
#include <iomanip>
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

bool validate_container_no_lock(const SessionManager::MinerSessionContainer& session, std::string* reason)
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

    if (reason) {
        *reason = "PASS";
    }
    return true;
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
        m_session.session_id = session_id;
        m_session.session_key = session_key;
        if (!tritium_genesis.empty()) {
            m_session.session_genesis = tritium_genesis;
        }
        m_session.state = SessionState::AUTHENTICATED;
        m_session.authenticated = (session_id != 0);
        m_session.falcon_authenticated = (session_id != 0);
        m_session.created_at = now_epoch_seconds();
        m_session.ready_for_submit = false;
        m_session.ready_for_get_block = false;
        m_session.reward_bound = false;
        m_session.session_start = std::chrono::system_clock::now();
        m_session.last_keepalive = m_session.session_start;
        m_session.keepalive_count = 0;
        m_session.last_auth_time = now_epoch_seconds();
        m_session.last_activity = m_session.last_auth_time;
    }

    m_logger->info("[SessionManager] Session started - ID: 0x{:08X}", session_id);

    if (!session_key.empty()) {
        m_logger->info("[SessionManager] Session key received: {} bytes", session_key.size());
    }

    if (!tritium_genesis.empty()) {
        m_logger->info("[SessionManager] Tritium genesis bound to session: {} bytes",
                      tritium_genesis.size());
    }
}

void SessionManager::end_session()
{
    std::chrono::seconds uptime;
    uint32_t session_id;
    uint32_t keepalive_count;
    SessionState prev_state;
    size_t genesis_size;

    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        prev_state = m_session.state;
        session_id = m_session.session_id;
        keepalive_count = m_session.keepalive_count;

        if (prev_state != SessionState::DISCONNECTED) {
            uptime = get_session_uptime_locked();
        }

        m_session.session_id = 0;
        m_session.session_key.clear();
        m_session.chacha20_session_key.clear();
        m_session.chacha20_key_fingerprint.clear();
        m_session.chacha20_ready = false;
        m_session.authenticated = false;
        m_session.falcon_authenticated = false;
        m_session.reward_bound = false;
        m_session.reward_hash.clear();
        m_session.ready_for_submit = false;
        m_session.ready_for_get_block = false;

        // Preserve tritium_genesis if configured (enables reconnection without reconfiguration)
        if (!m_preserve_genesis_on_disconnect) {
            m_session.session_genesis.clear();
        }
        genesis_size = m_session.session_genesis.size();

        m_session.state = SessionState::DISCONNECTED;
        m_session.keepalive_count = 0;
        m_session.last_activity = now_epoch_seconds();
    }

    stop_keepalive_timer();

    if (prev_state != SessionState::DISCONNECTED) {
        m_logger->info("[SessionManager] Session ended - ID: 0x{:08X}, Uptime: {}s, Keepalives: {}",
                      session_id, uptime.count(), keepalive_count);
    }

    if (m_preserve_genesis_on_disconnect && genesis_size > 0) {
        m_logger->debug("[SessionManager] Preserving tritium_genesis for reconnection ({} bytes)",
                       genesis_size);
    }
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
        prevblock_suffix = m_prevblock_suffix;
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

bool SessionManager::is_keepalive_due() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    if (m_session.state != SessionState::AUTHENTICATED &&
        m_session.state != SessionState::ACTIVE) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
        now - m_session.last_keepalive);

    return elapsed.count() >= m_keepalive_interval_hours;
}

void SessionManager::record_keepalive()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_keepalive = std::chrono::system_clock::now();
    m_session.keepalive_count++;
    m_session.last_activity = now_epoch_seconds();

    // Transition to ACTIVE state after first keepalive
    if (m_session.state == SessionState::AUTHENTICATED) {
        m_session.state = SessionState::ACTIVE;
    }

    auto uptime = get_session_uptime_locked();
    m_logger->info("[SessionManager] Keepalive #{} sent - Session uptime: {}h",
                  m_session.keepalive_count, uptime.count() / 3600);
}

void SessionManager::set_state(SessionState state)
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    if (m_session.state != state) {
        const char* state_names[] = {
            "DISCONNECTED", "AUTHENTICATING", "AUTHENTICATED", "ACTIVE", "EXPIRED"
        };

        m_logger->info("[SessionManager] State transition: {} -> {}",
                      state_names[static_cast<int>(m_session.state)],
                      state_names[static_cast<int>(state)]);

        m_session.state = state;
        if (state != SessionState::DISCONNECTED) {
            m_session.last_activity = now_epoch_seconds();
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
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.reward_address_string = reward_address;
    m_session.reward_hash = reward_hash;
    m_session.reward_bound = bound;
    m_session.reward_binding_source = source;
    if (bound) {
        m_session.last_reward_bind_time = now_epoch_seconds();
    }
    m_session.last_activity = now_epoch_seconds();
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
}

void SessionManager::mark_activity()
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    m_session.last_activity = now_epoch_seconds();
}

bool SessionManager::validate_miner_session(std::string* reason) const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return validate_container_no_lock(m_session, reason);
}

std::string SessionManager::build_miner_session_diagnostics() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);

    std::ostringstream oss;
    std::string consistency_reason;
    const bool consistency = validate_container_no_lock(m_session, &consistency_reason);

    oss << "MINER SESSION CONTAINER\n"
        << "- remote endpoint: " << (m_session.remote_endpoint.empty() ? "<unset>" : m_session.remote_endpoint) << '\n'
        << "- local endpoint: " << (m_session.local_endpoint.empty() ? "<unset>" : m_session.local_endpoint) << '\n'
        << "- active lane: " << lane_name(m_session.active_lane) << '\n'
        << "- connected: " << (m_session.connected ? "YES" : "NO") << '\n'
        << "- authenticated: " << (m_session.authenticated ? "YES" : "NO") << '\n'
        << "- falcon_key_id: " << (m_session.falcon_key_id.empty() ? "<unset>" : m_session.falcon_key_id) << '\n'
        << "- session_id: 0x" << std::hex << std::setw(8) << std::setfill('0') << m_session.session_id << std::dec << '\n'
        << "- session_genesis: " << (m_session.session_genesis.empty() ? "<unset>" : format_hex_prefix(m_session.session_genesis, 8)) << '\n'
        << "- chacha20_key_fingerprint: " << (m_session.chacha20_key_fingerprint.empty() ? "<unset>" : m_session.chacha20_key_fingerprint) << '\n'
        << "- reward_address_string: " << (m_session.reward_address_string.empty() ? "<unset>" : m_session.reward_address_string) << '\n'
        << "- reward_hash: " << (m_session.reward_hash.empty() ? "<unset>" : format_hex_prefix(m_session.reward_hash, 8)) << '\n'
        << "- reward_binding_source: " << (m_session.reward_binding_source.empty() ? "<unset>" : m_session.reward_binding_source) << '\n'
        << "- channel: " << m_session.channel << '\n'
        << "- consistency: " << (consistency ? "PASS" : "FAIL") << " (" << consistency_reason << ")";
    return oss.str();
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

SessionManager::SessionInfo SessionManager::get_session_info() const
{
    std::lock_guard<std::mutex> lock(m_session_mutex);
    return m_session;
}

void SessionManager::set_prevblock_suffix(const std::array<uint8_t, 4>& suffix)
{
    {
        std::lock_guard<std::mutex> lock(m_session_mutex);
        m_prevblock_suffix = suffix;
    }
    m_logger->debug("[SessionManager] prevblock_suffix updated: {:02x}{:02x}{:02x}{:02x}",
                   suffix[0], suffix[1], suffix[2], suffix[3]);
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
