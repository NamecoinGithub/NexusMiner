#ifndef NEXUSMINER_PROTOCOL_SESSION_INGRESS_GATE_HPP
#define NEXUSMINER_PROTOCOL_SESSION_INGRESS_GATE_HPP

#include "protocol/session_manager.hpp"
#include "protocol_lane.hpp"
#include <string>

namespace nexusminer {
namespace protocol {

struct SessionOwnershipStamp
{
    uint32_t session_id{0};
    uint64_t session_epoch{0};

    bool valid() const
    {
        return session_id != 0 || session_epoch != 0;
    }

    void clear()
    {
        session_id = 0;
        session_epoch = 0;
    }
};

struct SessionIngressDecision
{
    bool allow{false};
    bool force_reauth{false};
    bool mark_degraded{false};
    std::string reason;
};

class SessionIngressGate
{
public:
    struct Input
    {
        bool has_authoritative_session{false};
        bool authoritative_session_valid{false};
        SessionManager::SessionInfo authoritative_session{};
        ProtocolLane packet_lane{ProtocolLane::UNKNOWN};
        bool validate_lane{false};
        bool allow_without_active_session{false};
        bool require_crypto_ready{false};
        bool require_reward_binding{false};
        uint32_t packet_session_id{0};
        SessionOwnershipStamp owner{};
    };

    static SessionIngressDecision preflight(const Input& input)
    {
        SessionIngressDecision decision;

        if (!input.has_authoritative_session) {
            decision.reason = "no authoritative session container";
            return decision;
        }

        if (!input.authoritative_session_valid) {
            decision.reason = "authoritative session container is inconsistent";
            return decision;
        }

        if (input.validate_lane &&
            input.authoritative_session.active_lane != ProtocolLane::UNKNOWN &&
            input.packet_lane != ProtocolLane::UNKNOWN &&
            input.authoritative_session.active_lane != input.packet_lane) {
            decision.reason = "packet lane mismatched authoritative session lane";
            decision.mark_degraded = true;
            return decision;
        }

        if (!input.allow_without_active_session && !input.authoritative_session.authenticated) {
            decision.reason = "authoritative session is not authenticated";
            decision.force_reauth = true;
            decision.mark_degraded = true;
            return decision;
        }

        if (input.require_crypto_ready && !input.authoritative_session.chacha20_ready) {
            decision.reason = "authoritative crypto context is not ready";
            decision.force_reauth = true;
            decision.mark_degraded = true;
            return decision;
        }

        if (input.require_reward_binding &&
            !input.authoritative_session.reward_address_string.empty() &&
            !input.authoritative_session.reward_bound) {
            decision.reason = "reward binding required by authoritative session";
            decision.force_reauth = true;
            decision.mark_degraded = true;
            return decision;
        }

        if (input.packet_session_id != 0 &&
            input.packet_session_id != input.authoritative_session.session_id) {
            decision.reason = "packet session id mismatched authoritative session";
            decision.mark_degraded = true;
            return decision;
        }

        if (input.owner.valid()) {
            if (input.owner.session_epoch != input.authoritative_session.session_epoch) {
                decision.reason = "packet ownership epoch mismatched authoritative session";
                decision.mark_degraded = true;
                return decision;
            }

            if (input.owner.session_id != 0 &&
                input.owner.session_id != input.authoritative_session.session_id) {
                decision.reason = "packet ownership session id mismatched authoritative session";
                decision.mark_degraded = true;
                return decision;
            }
        }

        decision.allow = true;
        decision.reason = "authoritative session preflight passed";
        return decision;
    }
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_SESSION_INGRESS_GATE_HPP
