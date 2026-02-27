#include "protocol/session_manager.hpp"
#include "network/connection.hpp"
#include "packet.hpp"
#include "miner_opcodes.hpp"
#include <algorithm>

namespace nexusminer {
namespace protocol {

// Session management constants
constexpr uint16_t MIN_KEEPALIVE_HOURS = 1;
constexpr uint16_t MAX_KEEPALIVE_HOURS = 168;
constexpr auto KEEPALIVE_EARLY_INTERVAL = std::chrono::seconds(10);   // First ping after auth
constexpr auto KEEPALIVE_TCP_INTERVAL   = std::chrono::seconds(45);   // TCP keepalive ping
constexpr uint16_t KEEPALIVE_REGULAR_INTERVAL_DEFAULT = 24;           // Default hours fallback

// SESSION_KEEPALIVE requests encode session_id as little-endian (wire format requirement).
static void append_uint32_le(std::vector<uint8_t>& dest, uint32_t value) {
    for (uint32_t i = 0; i < 4; ++i) {
        dest.push_back((value >> (i * 8)) & 0xFF);
    }
}

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
    m_session.session_id = session_id;
    m_session.session_key = session_key;
    m_session.tritium_genesis = tritium_genesis;
    m_session.state = SessionState::AUTHENTICATED;
    m_session.session_start = std::chrono::system_clock::now();
    m_session.last_keepalive = m_session.session_start;
    m_session.keepalive_count = 0;
    
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
    if (m_session.state != SessionState::DISCONNECTED) {
        auto uptime = get_session_uptime();
        m_logger->info("[SessionManager] Session ended - ID: 0x{:08X}, Uptime: {}s, Keepalives: {}",
                      m_session.session_id, uptime.count(), m_session.keepalive_count);
    }
    
    m_session.session_id = 0;
    m_session.session_key.clear();
    stop_keepalive_timer();
    
    // Preserve tritium_genesis if configured (enables reconnection without reconfiguration)
    if (!m_preserve_genesis_on_disconnect) {
        m_session.tritium_genesis.clear();
    } else {
        m_logger->debug("[SessionManager] Preserving tritium_genesis for reconnection ({} bytes)", 
                       m_session.tritium_genesis.size());
    }
    
    m_session.state = SessionState::DISCONNECTED;
    m_session.keepalive_count = 0;
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
    m_keepalive_timer->expires_after(KEEPALIVE_EARLY_INTERVAL);
    m_keepalive_timer->async_wait([self](const asio::error_code& error) {
        if (error || !self->m_keepalive_active || !self->is_active()) {
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
    m_keepalive_timer->expires_after(KEEPALIVE_TCP_INTERVAL);
    m_keepalive_timer->async_wait([self](const asio::error_code& error) {
        if (error || !self->m_keepalive_active || !self->is_active()) {
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

    connection->transmit(payload);
    m_logger->info("[SessionManager] Keepalive sent ({}) for session 0x{:08X}",
                  cadence, m_session.session_id);
}

network::Shared_payload SessionManager::build_keepalive_packet() const
{
    if (m_session.session_id == 0) {
        return network::Shared_payload{};
    }
    
    // Validate protocol lane is set - UNKNOWN lane is not allowed
    if (m_protocol_lane == ProtocolLane::UNKNOWN) {
        m_logger->error("[SessionManager] build_keepalive_packet() called with UNKNOWN protocol lane");
        m_logger->error("[SessionManager]   Cannot send SESSION_KEEPALIVE without knowing the protocol lane");
        m_logger->error("[SessionManager]   This indicates a configuration or initialization error");
        return network::Shared_payload{};
    }

    // v2 keepalive payload: [session_id(4 LE)][miner_prevblock_suffix(4 raw bytes)]
    std::vector<uint8_t> payload;
    append_uint32_le(payload, m_session.session_id);
    payload.insert(payload.end(), m_prevblock_suffix.begin(), m_prevblock_suffix.end());

    // Build lane-aware packet based on protocol lane
    // On stateless lane, use mirror-mapped SESSION_KEEPALIVE (0xD0D4)
    // On legacy lane, use legacy SESSION_KEEPALIVE (212)
    bool use_stateless_opcode = (m_protocol_lane == ProtocolLane::STATELESS);
    
    Packet packet = use_stateless_opcode
        ? Packet{ LLP::StatelessMining::SESSION_KEEPALIVE,  // already uint16_t
                  std::make_shared<network::Payload>(payload) }
        : Packet{ static_cast<uint8_t>(Packet::SESSION_KEEPALIVE),
                  std::make_shared<network::Payload>(payload) };
    
    return packet.get_bytes();
}

bool SessionManager::is_keepalive_due() const
{
    if (!is_active()) {
        return false;
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::hours>(
        now - m_session.last_keepalive);
    
    return elapsed.count() >= m_keepalive_interval_hours;
}

void SessionManager::record_keepalive()
{
    m_session.last_keepalive = std::chrono::system_clock::now();
    m_session.keepalive_count++;
    
    // Transition to ACTIVE state after first keepalive
    if (m_session.state == SessionState::AUTHENTICATED) {
        m_session.state = SessionState::ACTIVE;
    }
    
    auto uptime = get_session_uptime();
    m_logger->info("[SessionManager] Keepalive #{} sent - Session uptime: {}h",
                  m_session.keepalive_count, uptime.count() / 3600);
}

void SessionManager::set_state(SessionState state)
{
    if (m_session.state != state) {
        const char* state_names[] = {
            "DISCONNECTED", "AUTHENTICATING", "AUTHENTICATED", "ACTIVE", "EXPIRED"
        };
        
        m_logger->info("[SessionManager] State transition: {} -> {}",
                      state_names[static_cast<int>(m_session.state)],
                      state_names[static_cast<int>(state)]);
        
        m_session.state = state;

        if (state == SessionState::EXPIRED && m_session_expired_handler)
            m_session_expired_handler();
    }
}

bool SessionManager::is_active() const
{
    return (m_session.state == SessionState::AUTHENTICATED || 
            m_session.state == SessionState::ACTIVE);
}

void SessionManager::set_tritium_genesis(const std::vector<uint8_t>& genesis)
{
    if (genesis.size() != 32) {
        m_logger->warn("[SessionManager] Invalid Tritium genesis size: {} (expected 32 bytes)",
                      genesis.size());
        return;
    }
    
    m_session.tritium_genesis = genesis;
    m_logger->info("[SessionManager] Tritium genesis set: {} bytes", genesis.size());
}

std::chrono::seconds SessionManager::get_session_uptime() const
{
    if (m_session.state == SessionState::DISCONNECTED) {
        return std::chrono::seconds(0);
    }
    
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(
        now - m_session.session_start);
}

std::chrono::seconds SessionManager::get_time_until_keepalive() const
{
    if (!is_active()) {
        return std::chrono::seconds(0);
    }
    
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - m_session.last_keepalive);
    
    auto interval_seconds = std::chrono::hours(m_keepalive_interval_hours);
    auto remaining = interval_seconds - elapsed;
    
    return std::max(remaining, std::chrono::seconds(0));
}

void SessionManager::set_prevblock_suffix(const std::array<uint8_t, 4>& suffix)
{
    m_prevblock_suffix = suffix;
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
    if (m_protocol_lane != lane) {
        const char* old_lane = (m_protocol_lane == ProtocolLane::LEGACY) ? "Legacy (8-bit)" :
                               (m_protocol_lane == ProtocolLane::STATELESS) ? "Stateless (16-bit)" : "Unknown";
        const char* new_lane = (lane == ProtocolLane::LEGACY) ? "Legacy (8-bit)" :
                               (lane == ProtocolLane::STATELESS) ? "Stateless (16-bit)" : "Unknown";
        
        m_logger->info("[SessionManager] Protocol lane changed: {} -> {}", old_lane, new_lane);
        m_protocol_lane = lane;
    }
}

uint16_t SessionManager::map_auth_opcode(uint8_t legacy_opcode) const
{
    if (m_protocol_lane == ProtocolLane::STATELESS) {
        return static_cast<uint16_t>(0xD000 | legacy_opcode);  // Mirror-map
    }
    return static_cast<uint16_t>(legacy_opcode);  // Legacy as-is
}

} // namespace protocol
} // namespace nexusminer
