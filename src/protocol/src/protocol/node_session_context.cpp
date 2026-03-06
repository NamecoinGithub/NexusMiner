#include "protocol/node_session_context.hpp"
#include "network/types.hpp"
#include <cstring>

namespace nexusminer {
namespace protocol {

NodeSessionContext::NodeSessionContext(std::shared_ptr<SessionManager> session_manager)
    : m_session_manager(std::move(session_manager))
{
}

uint32_t NodeSessionContext::get_session_id() const
{
    return m_session_manager ? m_session_manager->get_session_id() : 0;
}

bool NodeSessionContext::is_authenticated() const
{
    if (!m_session_manager) {
        return false;
    }
    auto state = m_session_manager->get_state();
    return state == SessionManager::SessionState::AUTHENTICATED ||
           state == SessionManager::SessionState::ACTIVE;
}

bool NodeSessionContext::is_active() const
{
    return m_session_manager ? m_session_manager->is_active() : false;
}

SessionManager::SessionState NodeSessionContext::get_state() const
{
    return m_session_manager ? m_session_manager->get_state()
                             : SessionManager::SessionState::DISCONNECTED;
}

void NodeSessionContext::start_session(uint32_t session_id,
                                       const std::vector<uint8_t>& session_key,
                                       const std::vector<uint8_t>& tritium_genesis)
{
    if (m_session_manager) {
        m_session_manager->start_session(session_id, session_key, tritium_genesis);
    }
}

void NodeSessionContext::end_session()
{
    if (m_session_manager) {
        m_session_manager->end_session();
    }
}

void NodeSessionContext::set_state(SessionManager::SessionState state)
{
    if (m_session_manager) {
        m_session_manager->set_state(state);
    }
}

network::Shared_payload NodeSessionContext::build_keepalive_packet() const
{
    return m_session_manager ? m_session_manager->build_keepalive_packet() : nullptr;
}

network::Shared_payload NodeSessionContext::build_session_status_packet(
    bool degraded,
    bool has_template,
    bool workers_running,
    bool secondary_up) const
{
    return m_session_manager ? m_session_manager->build_session_status_packet(
        degraded, has_template, workers_running, secondary_up) : nullptr;
}

void NodeSessionContext::start_keepalive_timer()
{
    if (m_session_manager) {
        m_session_manager->start_keepalive_timer();
    }
}

void NodeSessionContext::stop_keepalive_timer()
{
    if (m_session_manager) {
        m_session_manager->stop_keepalive_timer();
    }
}

void NodeSessionContext::set_keepalive_interval(uint16_t hours)
{
    if (m_session_manager) {
        m_session_manager->set_keepalive_interval(hours);
    }
}

uint16_t NodeSessionContext::get_keepalive_interval() const
{
    return m_session_manager ? m_session_manager->get_keepalive_interval() : 0;
}

void NodeSessionContext::set_protocol_lane(ProtocolLane lane)
{
    if (m_session_manager) {
        m_session_manager->set_protocol_lane(lane);
    }
}

void NodeSessionContext::set_connection(std::shared_ptr<network::Connection> connection)
{
    if (m_session_manager) {
        m_session_manager->set_connection(std::move(connection));
    }
}

void NodeSessionContext::set_tritium_genesis(const std::vector<uint8_t>& genesis)
{
    if (m_session_manager) {
        m_session_manager->set_tritium_genesis(genesis);
    }
}

std::vector<uint8_t> NodeSessionContext::get_tritium_genesis() const
{
    return m_session_manager ? m_session_manager->get_tritium_genesis() : std::vector<uint8_t>{};
}

std::vector<uint8_t> NodeSessionContext::get_session_key() const
{
    return m_session_manager ? m_session_manager->get_session_key() : std::vector<uint8_t>{};
}

std::chrono::seconds NodeSessionContext::get_session_uptime() const
{
    return m_session_manager ? m_session_manager->get_session_uptime() : std::chrono::seconds(0);
}

SessionManager::SessionInfo NodeSessionContext::get_session_info() const
{
    if (m_session_manager) {
        return m_session_manager->get_session_info();
    }
    return SessionManager::SessionInfo{};
}

void NodeSessionContext::set_session_expired_handler(SessionManager::SessionExpiredHandler handler)
{
    if (m_session_manager) {
        m_session_manager->set_session_expired_handler(std::move(handler));
    }
}

void NodeSessionContext::set_prevblock_suffix(const std::array<uint8_t, 4>& suffix)
{
    if (m_session_manager) {
        m_session_manager->set_prevblock_suffix(suffix);
    }
}

bool NodeSessionContext::parse_session_start(
    const std::vector<uint8_t>& packet_data,
    uint32_t& out_session_id,
    uint32_t& out_timeout,
    std::vector<uint8_t>& out_genesis)
{
    // SESSION_START wire format:
    // [0]      success (0x01)
    // [1..4]   session_id (little-endian uint32)
    // [5..8]   timeout (little-endian uint32, seconds)
    // [9..40]  genesis hash (optional, 32 bytes)

    if (packet_data.size() < 9) {
        return false;  // Minimum size: 1 + 4 + 4
    }

    // Check success byte
    if (packet_data[0] != 0x01) {
        return false;
    }

    // Parse session_id (little-endian)
    out_session_id = static_cast<uint32_t>(packet_data[1]) |
                    (static_cast<uint32_t>(packet_data[2]) << 8) |
                    (static_cast<uint32_t>(packet_data[3]) << 16) |
                    (static_cast<uint32_t>(packet_data[4]) << 24);

    // Parse timeout (little-endian)
    out_timeout = static_cast<uint32_t>(packet_data[5]) |
                 (static_cast<uint32_t>(packet_data[6]) << 8) |
                 (static_cast<uint32_t>(packet_data[7]) << 16) |
                 (static_cast<uint32_t>(packet_data[8]) << 24);

    // Parse optional genesis hash
    if (packet_data.size() >= 41) {
        out_genesis.resize(32);
        std::memcpy(out_genesis.data(), packet_data.data() + 9, 32);
    } else {
        out_genesis.clear();
    }

    return true;
}

} // namespace protocol
} // namespace nexusminer
