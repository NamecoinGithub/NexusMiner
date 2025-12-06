#include "protocol/session_manager.hpp"
#include <algorithm>

namespace nexusminer {
namespace protocol {

// Session management constants
constexpr uint16_t MIN_KEEPALIVE_HOURS = 1;
constexpr uint16_t MAX_KEEPALIVE_HOURS = 168;

SessionManager::SessionManager(uint16_t keepalive_interval_hours)
    : m_session{}
    , m_keepalive_interval_hours(keepalive_interval_hours)
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
    end_session();
}

void SessionManager::start_session(uint32_t session_id,
                                   const std::vector<uint8_t>& session_key,
                                   const std::vector<uint8_t>& tritium_genesis)
{
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
    m_session.tritium_genesis.clear();
    m_session.state = SessionState::DISCONNECTED;
    m_session.keepalive_count = 0;
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

void SessionManager::set_keepalive_interval(uint16_t hours)
{
    // Clamp to reasonable range
    if (hours < MIN_KEEPALIVE_HOURS) hours = MIN_KEEPALIVE_HOURS;
    if (hours > MAX_KEEPALIVE_HOURS) hours = MAX_KEEPALIVE_HOURS;
    
    if (m_keepalive_interval_hours != hours) {
        m_logger->info("[SessionManager] Keepalive interval changed: {} -> {} hours",
                      m_keepalive_interval_hours, hours);
        m_keepalive_interval_hours = hours;
    }
}

} // namespace protocol
} // namespace nexusminer
