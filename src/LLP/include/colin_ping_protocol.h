/*__________________________________________________________________________________________

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

            (c) Copyright The Nexus Developers 2014 - 2025

            Distributed under the MIT software license, see the accompanying
            file COPYING or http://www.opensource.org/licenses/mit-license.php.

            "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#pragma once
#ifndef NEXUSMINER_LLP_INCLUDE_COLIN_PING_PROTOCOL_H
#define NEXUSMINER_LLP_INCLUDE_COLIN_PING_PROTOCOL_H

#include <cstdint>
#include <vector>
#include <cassert>

namespace LLP
{

    //=========================================================================
    // UN-MIRRORED STATELESS-ONLY OPCODES
    // These DO NOT follow the 0xD000|legacy mirror formula.
    // They are STATELESS PORT ONLY — never valid on legacy port.
    // ALL carry DATA payloads — never header-only.
    //=========================================================================

    /** KeepAlive V2 — stateless-only session keepalive with data payload **/
    namespace KeepAliveV2Opcodes
    {
        /** KEEPALIVE_V2 (0xD100)
         *
         *  Sent by miner → node to keep authenticated stateless session alive.
         *  DATA-bearing: 8-byte payload (big-endian):
         *    [0-3]  uint32_t  sequence            Monotonic miner keepalive counter
         *    [4-7]  uint32_t  hashPrevBlock_lo32  Low 32 bits of miner's current prevHash (fork canary)
         *
         *  NOT a mirror of legacy PING (0xFD). Completely independent opcode.
         *  Legacy port: use bare PING (0xFD, header-only).
         **/
        static constexpr uint16_t KEEPALIVE_V2     = 0xD100;

        /** KEEPALIVE_V2_ACK (0xD101)
         *
         *  Sent by node → miner in response to KEEPALIVE_V2.
         *  DATA-bearing: 32-byte payload (big-endian):
         *    [0-3]   uint32_t  sequence            Echo of miner's sequence
         *    [4-7]   uint32_t  hashPrevBlock_lo32  Echo of miner's prevHash canary
         *    [8-11]  uint32_t  unified_height      Node's unified block height
         *    [12-15] uint32_t  hash_tip_lo32       Low 32 bits of node's hashBestChain
         *    [16-19] uint32_t  prime_height        Node's Prime channel height
         *    [20-23] uint32_t  hash_height         Node's Hash channel height
         *    [24-27] uint32_t  stake_height        Node's Stake channel height
         *    [28-31] uint32_t  fork_score          0=healthy, >0=divergence magnitude
         **/
        static constexpr uint16_t KEEPALIVE_V2_ACK = 0xD101;

        /** Payload sizes (different for each direction) **/
        static constexpr uint32_t KEEPALIVE_V2_PAYLOAD_SIZE     = 8;   // miner → node
        static constexpr uint32_t KEEPALIVE_V2_ACK_PAYLOAD_SIZE = 32;  // node → miner
    }

    /** Colin AI Diagnostic PING/PONG Opcodes
     *
     *  Piggybacked on every 60-second Colin Agent emit_report() cycle.
     *  Node sends PingFrame → Miner replies with PongFrame immediately.
     *
     *  Stateless lane (16-bit) ONLY:
     *    PING_DIAG: 0xD0E0
     *    PONG_DIAG: 0xD0E1
     *
     *  NOT mirrored from any legacy opcode. Stateless port only.
     **/
    namespace ColinDiagOpcodes
    {
        static constexpr uint16_t PING_DIAG_STATELESS = 0xD0E0;
        static constexpr uint16_t PONG_DIAG_STATELESS = 0xD0E1;
        static constexpr uint16_t PING_DIAG_LEGACY    = 0x00E0;
        static constexpr uint16_t PONG_DIAG_LEGACY    = 0x00E1;

        /** Canonical stateless-only names (un-mirrored, data-bearing) **/
        static constexpr uint16_t PING_DIAG  = PING_DIAG_STATELESS;  // 0xD0E0
        static constexpr uint16_t PONG_DIAG  = PONG_DIAG_STATELESS;  // 0xD0E1

        /** Exact payload size for both PING_DIAG and PONG_DIAG **/
        static constexpr uint32_t PAYLOAD_SIZE = 64;
    }

    /** Wire frame size — both PingFrame and PongFrame are exactly 64 bytes on the wire. **/
    static constexpr size_t COLIN_FRAME_SIZE = 64;
    /** ReceivedPingFrame
     *
     *  Parsed representation of the 64-byte PingFrame received from the node.
     *
     *  Wire layout (big-endian):
     *    [0-1]   uint16_t opcode              0xD0E0 or 0xE0
     *    [2-3]   uint16_t version             0x0001
     *    [4-7]   uint32_t sequence            Node's monotonic counter
     *    [8-15]  uint64_t timestamp_send_us   Node send timestamp (µs since epoch)
     *    [16-19] uint32_t unified_height      Chain unified height at node send time
     *    [20-23] uint32_t channel_height      Channel-specific height
     *    [24-27] uint32_t prime_pushes_30s    Prime template pushes (last ~30s)
     *    [28-31] uint32_t hash_pushes_30s     Hash template pushes (last ~30s)
     *    [32-35] uint32_t blocks_submitted    Our submissions this interval
     *    [36-39] uint32_t blocks_accepted     Our accepted this interval
     *    [40-43] uint32_t blocks_rejected     Our rejected this interval
     *    [44-47] uint32_t get_block_count     Our GET_BLOCK count this interval
     *    [48]    uint8_t  health_flags        Node-side health flags (see below)
     *    [49]    uint8_t  channel_id          0x01=PRIME, 0x02=HASH
     *    [50-51] uint16_t reserved            0x0000
     *    [52-63] uint8_t  padding[12]         Zero
     *
     *  health_flags (node side):
     *    Bit 7  STALE_TEMPLATE_DETECTED
     *    Bit 6  RATE_LIMITED
     *    Bit 5  SIM_LINK_ACTIVE
     *    Bit 4  DEDUP_HIT
     *    Bit 3  CHANNEL_MISMATCH
     *    Bit 2  HIGH_REJECTION_RATE
     *    Bit 1  FIRST_CONNECT
     *    Bit 0  NODE_SYNCING
     **/
    struct ReceivedPingFrame
    {
        uint16_t opcode{0};
        uint16_t version{0};
        uint32_t sequence{0};
        uint64_t timestamp_send_us{0};
        uint32_t unified_height{0};
        uint32_t channel_height{0};
        uint32_t prime_pushes_30s{0};
        uint32_t hash_pushes_30s{0};
        uint32_t blocks_submitted{0};
        uint32_t blocks_accepted{0};
        uint32_t blocks_rejected{0};
        uint32_t get_block_count{0};
        uint8_t  health_flags{0};
        uint8_t  channel_id{0};
        bool     valid{false};

        /* Node health_flags bit constants */
        static constexpr uint8_t NFLAG_STALE_TEMPLATE   = 0x80;
        static constexpr uint8_t NFLAG_RATE_LIMITED      = 0x40;
        static constexpr uint8_t NFLAG_SIM_LINK_ACTIVE   = 0x20;
        static constexpr uint8_t NFLAG_DEDUP_HIT         = 0x10;
        static constexpr uint8_t NFLAG_CHANNEL_MISMATCH  = 0x08;
        static constexpr uint8_t NFLAG_HIGH_REJECT_RATE  = 0x04;
        static constexpr uint8_t NFLAG_FIRST_CONNECT     = 0x02;
        static constexpr uint8_t NFLAG_NODE_SYNCING      = 0x01;

        /** Parse — deserialize 64-byte wire buffer into this struct.
         *  @param[in] data  Raw wire bytes (must be >= COLIN_FRAME_SIZE)
         *  @return true if parse succeeded (correct size and version)
         **/
        bool Parse(const std::vector<uint8_t>& data)
        {
            if(data.size() < COLIN_FRAME_SIZE) return false;

            auto rd16 = [&](int o) -> uint16_t {
                return (static_cast<uint16_t>(data[o]) << 8) | data[o+1];
            };
            auto rd32 = [&](int o) -> uint32_t {
                return (static_cast<uint32_t>(data[o])   << 24)
                     | (static_cast<uint32_t>(data[o+1]) << 16)
                     | (static_cast<uint32_t>(data[o+2]) <<  8)
                     |  static_cast<uint32_t>(data[o+3]);
            };
            auto rd64 = [&](int o) -> uint64_t {
                return (static_cast<uint64_t>(rd32(o)) << 32)
                     |  static_cast<uint64_t>(rd32(o+4));
            };

            opcode             = rd16(0);
            version            = rd16(2);
            sequence           = rd32(4);
            timestamp_send_us  = rd64(8);
            unified_height     = rd32(16);
            channel_height     = rd32(20);
            prime_pushes_30s   = rd32(24);
            hash_pushes_30s    = rd32(28);
            blocks_submitted   = rd32(32);
            blocks_accepted    = rd32(36);
            blocks_rejected    = rd32(40);
            get_block_count    = rd32(44);
            health_flags       = data[48];
            channel_id         = data[49];

            valid = (version == 0x0001);
            return valid;
        }
    };


    /** PongFrame
     *
     *  64-byte response from miner to node. Echoes ping fields, adds live telemetry.
     *
     *  Wire layout (big-endian):
     *    [0-1]   uint16_t opcode              0xD0E1 stateless / 0xE1 legacy
     *    [2-3]   uint16_t version             Echo of PingFrame version
     *    [4-7]   uint32_t sequence            Echo of PingFrame sequence
     *    [8-15]  uint64_t timestamp_send_us   Echo of PingFrame timestamp_send_us
     *    [16-23] uint64_t timestamp_recv_us   Miner receive time (µs since epoch)
     *    [24-27] uint32_t miner_hash_rate     kH/s (or chains/s for Prime channel)
     *    [28-31] uint32_t miner_temp_cdeg     Temperature * 10 Celsius (0 = unavailable)
     *    [32-35] uint32_t miner_threads       Active mining thread count
     *    [36-39] uint32_t miner_queue_depth   Work queue depth
     *    [40]    uint8_t  miner_health_flags  Miner health bit field (see below)
     *    [41]    uint8_t  echo_channel_id     Echo of PingFrame channel_id
     *    [42-43] uint16_t reserved            0x0000
     *    [44-63] uint8_t  padding[20]         Zero-fill
     *
     *  miner_health_flags:
     *    Bit 7  OVERHEATING
     *    Bit 6  LOW_MEMORY
     *    Bit 5  QUEUE_FULL
     *    Bit 4  HASH_RATE_DROP  (>20% drop vs previous ping)
     *    Bit 3  STALE_WORK_DETECTED
     *    Bit 2  RECONNECT_RECOVERY
     *    Bit 1  WORK_REJECTED_LOCAL
     *    Bit 0  IDLE
     **/
    struct PongFrame
    {
        uint16_t opcode{0};
        uint16_t version{0x0001};
        uint32_t sequence{0};
        uint64_t timestamp_send_us{0};   // echo
        uint64_t timestamp_recv_us{0};   // miner receive time
        uint32_t miner_hash_rate{0};
        uint32_t miner_temp_cdeg{0};
        uint32_t miner_threads{0};
        uint32_t miner_queue_depth{0};
        uint8_t  miner_health_flags{0};
        uint8_t  echo_channel_id{0};

        /* miner_health_flags bit constants */
        static constexpr uint8_t MFLAG_OVERHEATING         = 0x80;
        static constexpr uint8_t MFLAG_LOW_MEMORY          = 0x40;
        static constexpr uint8_t MFLAG_QUEUE_FULL          = 0x20;
        static constexpr uint8_t MFLAG_HASH_RATE_DROP      = 0x10;
        static constexpr uint8_t MFLAG_STALE_WORK          = 0x08;
        static constexpr uint8_t MFLAG_RECONNECT_RECOVERY  = 0x04;
        static constexpr uint8_t MFLAG_WORK_REJECTED_LOCAL = 0x02;
        static constexpr uint8_t MFLAG_IDLE                = 0x01;

        /** BuildFromPing — populate echo fields from a received PingFrame.
         *  Call this immediately on PING_DIAG receipt to stamp recv time.
         **/
        static PongFrame BuildFromPing(const ReceivedPingFrame& ping,
                                       uint64_t recv_time_us,
                                       bool stateless_lane)
        {
            PongFrame p;
            p.opcode            = stateless_lane
                                  ? ColinDiagOpcodes::PONG_DIAG_STATELESS
                                  : ColinDiagOpcodes::PONG_DIAG_LEGACY;
            p.version           = ping.version;
            p.sequence          = ping.sequence;
            p.timestamp_send_us = ping.timestamp_send_us;
            p.timestamp_recv_us = recv_time_us;
            p.echo_channel_id   = ping.channel_id;
            return p;
        }

        /** Serialize — produce COLIN_FRAME_SIZE (64-byte) big-endian wire vector **/
        std::vector<uint8_t> Serialize() const
        {
            /* PongFrame wire layout: 44 bytes of fields + 20 bytes padding = 64 total.
             * Padding occupies bytes [44-63] per the wire format spec above. */
            static constexpr size_t PONG_PADDING_SIZE = COLIN_FRAME_SIZE - 44;

            std::vector<uint8_t> v;
            v.reserve(COLIN_FRAME_SIZE);

            auto push16 = [&](uint16_t x){
                v.push_back((x >> 8) & 0xFF);
                v.push_back( x       & 0xFF);
            };
            auto push32 = [&](uint32_t x){
                v.push_back((x >> 24) & 0xFF);
                v.push_back((x >> 16) & 0xFF);
                v.push_back((x >>  8) & 0xFF);
                v.push_back( x        & 0xFF);
            };
            auto push64 = [&](uint64_t x){
                push32(static_cast<uint32_t>(x >> 32));
                push32(static_cast<uint32_t>(x & 0xFFFFFFFF));
            };

            push16(opcode);
            push16(version);
            push32(sequence);
            push64(timestamp_send_us);
            push64(timestamp_recv_us);
            push32(miner_hash_rate);
            push32(miner_temp_cdeg);
            push32(miner_threads);
            push32(miner_queue_depth);
            v.push_back(miner_health_flags);
            v.push_back(echo_channel_id);
            push16(0x0000);                                          // reserved
            for(size_t i = 0; i < PONG_PADDING_SIZE; ++i) v.push_back(0x00);  // padding [44-63]

            assert(v.size() == COLIN_FRAME_SIZE);
            return v;
        }
    };

    //=========================================================================
    // OPCODE CLASSIFICATION HELPERS (miner side)
    //=========================================================================

    /** IsUnmirroredDataOpcode
     *
     *  Returns true if the 16-bit opcode is one of the un-mirrored,
     *  stateless-only, DATA-bearing opcodes.
     *
     *  These must NEVER be received or sent on the legacy lane.
     *
     **/
    inline bool IsUnmirroredDataOpcode(uint16_t opcode)
    {
        return opcode == KeepAliveV2Opcodes::KEEPALIVE_V2
            || opcode == KeepAliveV2Opcodes::KEEPALIVE_V2_ACK
            || opcode == ColinDiagOpcodes::PING_DIAG
            || opcode == ColinDiagOpcodes::PONG_DIAG;
    }

    /** GetExpectedPayloadSize
     *
     *  Returns the required exact payload length (bytes) for fixed-size opcodes.
     *  Returns 0 for variable-length or header-only opcodes.
     *
     **/
    inline uint32_t GetExpectedPayloadSize(uint16_t opcode)
    {
        if(opcode == KeepAliveV2Opcodes::KEEPALIVE_V2)
            return KeepAliveV2Opcodes::KEEPALIVE_V2_PAYLOAD_SIZE;     // 8

        if(opcode == KeepAliveV2Opcodes::KEEPALIVE_V2_ACK)
            return KeepAliveV2Opcodes::KEEPALIVE_V2_ACK_PAYLOAD_SIZE; // 28

        if(opcode == ColinDiagOpcodes::PING_DIAG
        || opcode == ColinDiagOpcodes::PONG_DIAG)
            return ColinDiagOpcodes::PAYLOAD_SIZE;     // 64

        return 0;  // variable or header-only
    }

    /** GetUnmirroredOpcodeName
     *
     *  Human-readable name for un-mirrored stateless opcodes (for debug logging).
     *
     **/
    inline const char* GetUnmirroredOpcodeName(uint16_t opcode)
    {
        switch(opcode)
        {
            case KeepAliveV2Opcodes::KEEPALIVE_V2:      return "KEEPALIVE_V2";
            case KeepAliveV2Opcodes::KEEPALIVE_V2_ACK:  return "KEEPALIVE_V2_ACK";
            case ColinDiagOpcodes::PING_DIAG:            return "PING_DIAG";
            case ColinDiagOpcodes::PONG_DIAG:            return "PONG_DIAG";
            default:                                      return "UNKNOWN_UNMIRRORED";
        }
    }

    //=========================================================================
    // KeepAliveV2Frame — 8-byte payload for KEEPALIVE_V2 (miner → node, send side)
    //=========================================================================

    /** KeepAliveV2Frame — 8-byte miner → node payload for KEEPALIVE_V2 **/
    struct KeepAliveV2Frame
    {
        uint32_t sequence{0};
        uint32_t hashPrevBlock_lo32{0};  // low 32 bits of miner's current prevHash (fork canary)

        static constexpr uint32_t PAYLOAD_SIZE = 8;

        /** Serialize — 8-byte big-endian wire format **/
        std::vector<uint8_t> Serialize() const
        {
            std::vector<uint8_t> v;
            v.reserve(8);
            v.push_back((sequence           >> 24) & 0xFF);
            v.push_back((sequence           >> 16) & 0xFF);
            v.push_back((sequence           >>  8) & 0xFF);
            v.push_back( sequence                  & 0xFF);
            v.push_back((hashPrevBlock_lo32  >> 24) & 0xFF);
            v.push_back((hashPrevBlock_lo32  >> 16) & 0xFF);
            v.push_back((hashPrevBlock_lo32  >>  8) & 0xFF);
            v.push_back( hashPrevBlock_lo32         & 0xFF);
            return v;
        }

        /** Parse — deserialize 8-byte wire buffer **/
        bool Parse(const std::vector<uint8_t>& data)
        {
            if(data.size() < 8) return false;
            sequence           = (uint32_t(data[0])<<24)|(uint32_t(data[1])<<16)
                               |(uint32_t(data[2])<<8)  | uint32_t(data[3]);
            hashPrevBlock_lo32 = (uint32_t(data[4])<<24)|(uint32_t(data[5])<<16)
                               |(uint32_t(data[6])<<8)  | uint32_t(data[7]);
            return true;
        }
    };

    //=========================================================================
    // KeepAliveV2AckFrame — 32-byte payload for KEEPALIVE_V2_ACK (node → miner)
    //=========================================================================

    /** KeepAliveV2AckFrame — 32-byte node → miner payload (receive side)
     *
     *  After parsing, call IsForkDetected() to check for chain divergence.
     *  Feed unified_height / prime_height / hash_height / stake_height to the
     *  Unified Block Height Manager.
     *  Feed fork_score to the Fork Resolution Manager.
     **/
    struct KeepAliveV2AckFrame
    {
        uint32_t sequence{0};
        uint32_t hashPrevBlock_lo32{0};  // echo of what miner sent
        uint32_t unified_height{0};      // node's unified block height
        uint32_t hash_tip_lo32{0};       // low 32 bits of node's hashBestChain
        uint32_t prime_height{0};        // node's Prime channel height
        uint32_t hash_height{0};         // node's Hash channel height
        uint32_t stake_height{0};        // node's Stake channel height
        uint32_t fork_score{0};          // 0 = healthy, >0 = divergence magnitude

        static constexpr uint32_t PAYLOAD_SIZE = 32;

        /** IsForkDetected
         *
         *  Returns true if the node's chain tip low-32 doesn't match the miner's
         *  prevHash canary OR if the node's Fork Detection Manager reports non-zero score.
         *
         *  @param[in] myHashPrevBlock_lo32  The value miner sent in the request
         *  @return true if fork detected, false if chains agree
         **/
        bool IsForkDetected(uint32_t myHashPrevBlock_lo32) const
        {
            return (hash_tip_lo32 != myHashPrevBlock_lo32) || (fork_score > 0);
        }

        /** Parse — deserialize 32-byte wire buffer **/
        bool Parse(const std::vector<uint8_t>& data)
        {
            if(data.size() < 32) return false;
            auto r32 = [&](int o) -> uint32_t {
                return (uint32_t(data[o  ]) << 24) | (uint32_t(data[o+1]) << 16)
                     | (uint32_t(data[o+2]) <<  8) |  uint32_t(data[o+3]);
            };
            sequence           = r32(0);
            hashPrevBlock_lo32 = r32(4);
            unified_height     = r32(8);
            hash_tip_lo32      = r32(12);
            prime_height       = r32(16);
            hash_height        = r32(20);
            stake_height       = r32(24);
            fork_score         = r32(28);
            return true;
        }
    };

} // namespace LLP

#endif
