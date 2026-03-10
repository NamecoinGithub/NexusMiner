#ifndef NEXUSMINER_PROTOCOL_PACKET_INGRESS_PREFLIGHT_HPP
#define NEXUSMINER_PROTOCOL_PACKET_INGRESS_PREFLIGHT_HPP

#include "protocol/session_manager.hpp"
#include "protocol/session_semantic_types.hpp"
#include "protocol_lane.hpp"
#include <string>

namespace nexusminer {
namespace protocol {

struct SessionOwnershipStamp
{
    SessionId session_id{};
    SessionEpoch session_epoch{};

    bool valid() const
    {
        // Ownership stamps are only captured from authenticated sessions after
        // SessionManager::start_session() advances the authoritative epoch, so
        // {0,0} remains the sentinel for "no correlatable owner".
        return !session_id.empty() && !session_epoch.empty();
    }

    void clear()
    {
        session_id.clear();
        session_epoch.clear();
    }
};

struct PacketIngressDecision
{
    bool allow_processing{false};
    bool force_reauth{false};
    bool drop_as_stale{false};
    bool mark_degraded{false};
    std::string reason;
};

class PacketIngressPreflight
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
        SessionId packet_session_id{};
        SessionOwnershipStamp owner{};
    };

    static PacketIngressDecision evaluate(const Input& input)
    {
        PacketIngressDecision decision;

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

        if (!input.packet_session_id.empty() &&
            input.packet_session_id.get() != input.authoritative_session.session_id) {
            decision.reason = "packet session id mismatched authoritative session";
            decision.drop_as_stale = true;
            decision.mark_degraded = true;
            return decision;
        }

        if (input.owner.valid()) {
            if (input.owner.session_epoch.get() != input.authoritative_session.session_epoch) {
                decision.reason = "packet ownership epoch mismatched authoritative session";
                decision.drop_as_stale = true;
                decision.mark_degraded = true;
                return decision;
            }

            if (!input.owner.session_id.empty() &&
                input.owner.session_id.get() != input.authoritative_session.session_id) {
                decision.reason = "packet ownership session id mismatched authoritative session";
                decision.drop_as_stale = true;
                decision.mark_degraded = true;
                return decision;
            }
        }

        decision.allow_processing = true;
        decision.reason = "authoritative session preflight passed";
        return decision;
    }
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_PROTOCOL_PACKET_INGRESS_PREFLIGHT_HPP
