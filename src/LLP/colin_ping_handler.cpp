/*__________________________________________________________________________________________

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

            (c) Copyright The Nexus Developers 2014 - 2025

            Distributed under the MIT software license, see the accompanying
            file COPYING or http://www.opensource.org/licenses/mit-license.php.

            "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#include "LLP/colin_ping_handler.h"
#include <chrono>

namespace LLP
{

    uint64_t ColinPingHandler::get_time_us()
    {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<microseconds>(
                system_clock::now().time_since_epoch()).count());
    }


    std::vector<uint8_t> ColinPingHandler::HandlePing(
        const std::vector<uint8_t>& payload,
        bool stateless)
    {
        /* 1. Stamp receive time first — before any processing for accuracy */
        uint64_t recv_us = get_time_us();

        /* 2. Parse PingFrame */
        ReceivedPingFrame ping;
        if(!ping.Parse(payload))
        {
            if(m_logger)
                m_logger->warn("[Colin PING] Malformed PingFrame received — discarding");
            return {};
        }

        m_last_ping = ping;
        ++m_ping_count;

        /* 3. Log node health flags if any warnings are set */
        log_node_health(ping);

        /* 4. Build PongFrame echo */
        PongFrame pong = PongFrame::BuildFromPing(ping, recv_us, stateless);

        /* 5. Fill telemetry (safe defaults if no source registered) */
        if(m_telemetry)
        {
            pong.miner_hash_rate     = m_telemetry->GetHashRateKHs();
            pong.miner_temp_cdeg     = m_telemetry->GetTempCdeg();
            pong.miner_threads       = m_telemetry->GetThreadCount();
            pong.miner_queue_depth   = m_telemetry->GetQueueDepth();
            pong.miner_health_flags  = m_telemetry->GetHealthFlags();
        }

        if(m_logger)
            m_logger->debug("[Colin PING] Seq #{} NodeHeight={} RTT-echo: stamp sent",
                ping.sequence, ping.unified_height);

        /* 6. Serialize and return */
        return pong.Serialize();
    }


    void ColinPingHandler::log_node_health(const ReceivedPingFrame& ping) const
    {
        if(!m_logger) return;
        uint8_t f = ping.health_flags;
        if(f == 0) return;

        m_logger->warn("[Colin PING] Node health flags for ping #{}:", ping.sequence);

        if(f & ReceivedPingFrame::NFLAG_STALE_TEMPLATE)
            m_logger->warn("  [Colin PING] NODE: STALE_TEMPLATE_DETECTED");
        if(f & ReceivedPingFrame::NFLAG_RATE_LIMITED)
            m_logger->warn("  [Colin PING] NODE: RATE_LIMITED");
        if(f & ReceivedPingFrame::NFLAG_SIM_LINK_ACTIVE)
            m_logger->info("  [Colin PING] NODE: SIM_LINK_ACTIVE");
        if(f & ReceivedPingFrame::NFLAG_DEDUP_HIT)
            m_logger->warn("  [Colin PING] NODE: DEDUP_HIT (duplicate submission detected)");
        if(f & ReceivedPingFrame::NFLAG_CHANNEL_MISMATCH)
            m_logger->warn("  [Colin PING] NODE: CHANNEL_MISMATCH");
        if(f & ReceivedPingFrame::NFLAG_HIGH_REJECT_RATE)
            m_logger->warn("  [Colin PING] NODE: HIGH_REJECTION_RATE (>20%)");
        if(f & ReceivedPingFrame::NFLAG_FIRST_CONNECT)
            m_logger->info("  [Colin PING] NODE: FIRST_CONNECT (new session)");
        if(f & ReceivedPingFrame::NFLAG_NODE_SYNCING)
            m_logger->warn("  [Colin PING] NODE: NODE_SYNCING (work may be stale)");
    }

} // namespace LLP
