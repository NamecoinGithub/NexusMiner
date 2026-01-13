#ifndef NEXUSMINER_LLP_MINER_OPCODES_HPP
#define NEXUSMINER_LLP_MINER_OPCODES_HPP

/**
 * @file miner_opcodes.hpp
 * @brief Centralized LLP packet header opcodes for NexusMiner
 * 
 * This file defines all LLP packet opcodes used by NexusMiner, synchronized
 * with LLL-TAO's Phase 2 stateless miner implementation (src/LLP/types/miner.h).
 * 
 * IMPORTANT: These values MUST match the node implementation exactly for protocol
 * compatibility. Any changes should be coordinated with LLL-TAO repository updates.
 * 
 * Protocol Documentation: See docs/mining-llp-protocol.md for detailed flow
 */

#include <cstdint>

namespace nexusminer
{
namespace LLP
{

/**
 * LLP Packet Header Opcodes (Legacy uint8_t opcodes)
 * 
 * These opcodes define the message types in the Lower Level Protocol (LLP)
 * used for communication between NexusMiner and LLL-TAO mining servers.
 * 
 * NOTE: These are legacy uint8_t opcodes. For new stateless mining protocol,
 * see StatelessMining namespace below with uint16_t opcodes (0xD000+ range).
 */
enum MinerOpcodes : std::uint8_t
{
    // ============================================================================
    // DATA PACKETS (0-127)
    // These packets carry payload data and include a 4-byte length field
    // ============================================================================
    
    /** Block template data from node to miner */
    BLOCK_DATA = 0,
    
    /** Submit solved block from miner to node */
    SUBMIT_BLOCK = 1,
    
    /** Current blockchain height notification */
    BLOCK_HEIGHT = 2,
    
    /** Set mining channel (1=Prime, 2=Hash) */
    SET_CHANNEL = 3,
    
    /** Block reward information */
    BLOCK_REWARD = 4,
    
    /** Set coinbase address for rewards */
    SET_COINBASE = 5,
    
    /** Good block notification (valid but not best) */
    GOOD_BLOCK = 6,
    
    /** Orphaned block notification */
    ORPHAN_BLOCK = 7,
    
    // ============================================================================
    // POOL-SPECIFIC PACKETS (8-13)
    // These are NexusMiner extensions for pool mining compatibility
    // NOT used in solo stateless mining to LLL-TAO nodes
    // ============================================================================
    
    /** Pool login request (pool-only) */
    LOGIN = 8,
    
    /** Hashrate reporting (pool-only) */
    HASHRATE = 9,
    
    /** Work assignment from pool (pool-only) */
    WORK = 10,
    
    /** Pool login success v2 (pool-only) */
    LOGIN_V2_SUCCESS = 11,
    
    /** Pool login failure v2 (pool-only) */
    LOGIN_V2_FAIL = 12,
    
    /** Pool notification message (pool-only) */
    POOL_NOTIFICATION = 13,
    
    // ============================================================================
    // DATA REQUESTS (64-127)
    // Request packets with data payload
    // ============================================================================
    
    /** Request block validation */
    CHECK_BLOCK = 64,
    
    /** Subscribe to block notifications */
    SUBSCRIBE = 65,
    
    // ============================================================================
    // REQUEST PACKETS (128-199)
    // These are command packets with no payload (length = 0)
    // ============================================================================
    
    /** Request new block template */
    GET_BLOCK = 129,
    
    /** Request current blockchain height */
    GET_HEIGHT = 130,
    
    /** Request current block reward */
    GET_REWARD = 131,
    
    // ============================================================================
    // SERVER COMMANDS (132-135)
    // Commands from node to miner, or legacy pool commands
    // ============================================================================
    
    /** Clear miner's block cache (from LLL-TAO) */
    CLEAR_MAP = 132,
    
    /** Get current mining round info (from LLL-TAO) */
    GET_ROUND = 133,
    
    // ============================================================================
    // POOL-ONLY LEGACY OPCODES (overlapping values - use with caution!)
    // These legacy pool opcodes reuse the same numeric values as CLEAR_MAP/GET_ROUND
    // They are only valid when communicating with pool servers, NOT LLL-TAO nodes.
    // The numeric overlap is intentional for backward compatibility with pools.
    // ============================================================================
    
    /** Get payout info (pool-only, overlaps CLEAR_MAP) */
    GET_PAYOUT = 132,
    
    /** Get hashrate info (pool-only, overlaps GET_ROUND) */
    GET_HASHRATE = 133,
    
    /** Pool login success (legacy pool-only) */
    LOGIN_SUCCESS = 134,
    
    /** Pool login failure (legacy pool-only) */
    LOGIN_FAIL = 135,
    
    // ============================================================================
    // RESPONSE PACKETS (200-206)
    // Acknowledgments and status responses from node
    // ============================================================================
    
    /** Block accepted by node */
    ACCEPT = 200,
    BLOCK_ACCEPTED = 200,  // Alias for clarity
    
    /** Block rejected by node */
    REJECT = 201,
    BLOCK_REJECTED = 201,  // Alias for clarity
    
    /** Coinbase address set successfully */
    COINBASE_SET = 202,
    
    /** Coinbase address setting failed */
    COINBASE_FAIL = 203,
    
    // Legacy pool aliases (overlap with COINBASE_SET/FAIL)
    /** Block submitted (legacy pool, overlaps COINBASE_SET) */
    BLOCK = 202,
    
    /** Stale block (legacy pool, overlaps COINBASE_FAIL) */
    STALE = 203,
    
    /** New mining round started */
    NEW_ROUND = 204,
    
    /** Old/stale round */
    OLD_ROUND = 205,
    
    /** Channel selection acknowledged */
    CHANNEL_ACK = 206,
    
    // ============================================================================
    // FALCON AUTHENTICATION PACKETS (207-210)
    // Phase 2 stateless miner authentication using Falcon-512 signatures
    // These implement the challenge-response auth handshake
    // ============================================================================
    
    /**
     * MINER_AUTH_INIT: Miner initiates authentication
     * Direction: Miner -> Node
     * Payload (big-endian):
     *   [pubkey_len(2)] [pubkey bytes] [miner_id_len(2)] [miner_id string]
     */
    MINER_AUTH_INIT = 207,
    
    /**
     * MINER_AUTH_CHALLENGE: Node sends authentication challenge
     * Direction: Node -> Miner
     * Payload (big-endian):
     *   [nonce_len(2)] [nonce bytes]
     */
    MINER_AUTH_CHALLENGE = 208,
    
    /**
     * MINER_AUTH_RESPONSE: Miner sends signed challenge response
     * Direction: Miner -> Node
     * Payload (big-endian):
     *   [sig_len(2)] [signature bytes]
     */
    MINER_AUTH_RESPONSE = 209,
    
    /**
     * MINER_AUTH_RESULT: Node sends authentication result
     * Direction: Node -> Miner
     * Payload:
     *   [status(1)] [session_id(4, optional, little-endian)]
     *   status: 0x01 = success, 0x00 = failure
     */
    MINER_AUTH_RESULT = 210,
    
    // Aliases for backward compatibility
    MINER_AUTH_OK = 210,
    MINER_AUTH_FAIL = 210,  // Same opcode, status byte differentiates
    
    // ============================================================================
    // SESSION MANAGEMENT (211-212)
    // Phase 2 session handling (future use)
    // ============================================================================
    
    /** Start new mining session */
    SESSION_START = 211,
    
    /** Keep session alive (heartbeat) */
    SESSION_KEEPALIVE = 212,
    
    // ============================================================================
    // STATELESS MINING REWARD BINDING (213-214)
    // Phase 2 encrypted reward address binding after Falcon auth
    // ============================================================================
    
    /**
     * MINER_SET_REWARD: Miner sends encrypted reward address
     * Direction: Miner -> Node
     * Payload (ChaCha20 encrypted):
     *   [encrypted_address(32)] - Decrypted to 32-byte register address
     * NOTE: Must be sent AFTER successful MINER_AUTH_RESULT establishes ChaCha20
     */
    MINER_SET_REWARD = 213,
    
    /**
     * MINER_REWARD_RESULT: Node sends reward binding result
     * Direction: Node -> Miner
     * Payload (ChaCha20 encrypted):
     *   [status(1)] [msg_len(1, optional)] [message(variable, optional)]
     *   status: 0x01 = success, 0x00 = failure
     */
    MINER_REWARD_RESULT = 214,
    
    // ============================================================================
    // PUSH NOTIFICATIONS (216-218)
    // LLL-TAO PR #156: Event-driven block notifications (replaces polling)
    // ============================================================================
    
    /**
     * MINER_READY: Miner subscribes to push notifications
     * Direction: Miner -> Node
     * Payload: None (header-only)
     * Requirements:
     *   - Must be sent AFTER successful authentication
     *   - Must be sent AFTER SET_CHANNEL (1=Prime or 2=Hash)
     *   - Stake channel (0) is REJECTED
     * Response:
     *   - Immediate PRIME_BLOCK_AVAILABLE or HASH_BLOCK_AVAILABLE
     *   - Then pushed on every block validation
     */
    MINER_READY = 216,
    
    /**
     * PRIME_BLOCK_AVAILABLE: Node notifies Prime miners of new block
     * Direction: Node -> Miner (Prime channel only)
     * Payload: 12 bytes (big-endian)
     *   [0-3]   unified_height (uint32)
     *   [4-7]   prime_height (uint32)
     *   [8-11]  difficulty (uint32)
     * Triggered:
     *   - Immediately after MINER_READY
     *   - On every Prime block validation
     */
    PRIME_BLOCK_AVAILABLE = 217,
    
    /**
     * HASH_BLOCK_AVAILABLE: Node notifies Hash miners of new block
     * Direction: Node -> Miner (Hash channel only)
     * Payload: 12 bytes (big-endian)
     *   [0-3]   unified_height (uint32)
     *   [4-7]   hash_height (uint32)
     *   [8-11]  difficulty (uint32)
     * Triggered:
     *   - Immediately after MINER_READY
     *   - On every Hash block validation
     */
    HASH_BLOCK_AVAILABLE = 218,
    
    // ============================================================================
    // GENERIC PACKETS (253-254)
    // Protocol-level control messages
    // ============================================================================
    
    /** Keepalive ping */
    PING = 253,
    
    /** Close connection */
    CLOSE = 254
};

// ============================================================================
// NEW STATELESS MINING PROTOCOL (LLL-TAO PR #170)
// uint16_t opcodes in 0xD000+ range for GET_BLOCK/NEW_BLOCK push protocol
// ============================================================================

/**
 * @namespace StatelessMining
 * @brief NEW stateless mining protocol opcodes (uint16_t, 0xD000+ range)
 * 
 * This namespace contains the opcodes for the modern stateless mining protocol
 * implemented in LLL-TAO PR #170. These opcodes use uint16_t (2-byte) headers
 * instead of the legacy uint8_t (1-byte) headers.
 * 
 * KEY FEATURES:
 * - Push notifications (no polling!)
 * - 228-byte templates (12-byte metadata + 216-byte block)
 * - Immediate template delivery after MINER_READY
 * - NEW_BLOCK push updates when blockchain advances
 * 
 * WIRE FORMAT:
 * [header(2 bytes, big-endian)][length(4 bytes, big-endian)][payload]
 */
namespace StatelessMining {
    
    // ========================================================================
    // AUTHENTICATION (0xD000-0xD002)
    // ========================================================================
    
    /**
     * MINER_AUTH: Miner initiates Falcon authentication
     * Direction: Miner → Node
     * Payload: [genesis(32)][pubkey_len(2)][pubkey][miner_id_len(2)][miner_id]
     */
    constexpr uint16_t MINER_AUTH = 0xD000;
    
    /**
     * MINER_AUTH_RESPONSE: Node responds to authentication
     * Direction: Node → Miner
     * Payload: [status(1)][session_id(4, optional)]
     *   status: 0x01 = success, 0x00 = failure
     */
    constexpr uint16_t MINER_AUTH_RESPONSE = 0xD001;
    
    // ========================================================================
    // CONFIGURATION (0xD003-0xD006)
    // ========================================================================
    
    /**
     * MINER_SET_REWARD: Miner sends encrypted reward address
     * Direction: Miner → Node
     * Payload (ChaCha20 encrypted): [encrypted_address(32)]
     */
    constexpr uint16_t MINER_SET_REWARD = 0xD003;
    
    /**
     * MINER_REWARD_RESULT: Node confirms reward binding
     * Direction: Node → Miner
     * Payload (ChaCha20 encrypted): [status(1)][msg_len(1)][message(optional)]
     */
    constexpr uint16_t MINER_REWARD_RESULT = 0xD004;
    
    /**
     * SET_CHANNEL: Miner sets mining channel
     * Direction: Miner → Node
     * Payload: [channel(1)]  // 1=Prime, 2=Hash
     */
    constexpr uint16_t SET_CHANNEL = 0xD005;
    
    /**
     * CHANNEL_ACK: Node acknowledges channel selection
     * Direction: Node → Miner
     * Payload: [channel(1)]  // Confirmed channel
     */
    constexpr uint16_t CHANNEL_ACK = 0xD006;
    
    // ========================================================================
    // SUBSCRIPTION (0xD007)
    // ========================================================================
    
    /**
     * MINER_READY: Miner subscribes to push notifications
     * Direction: Miner → Node
     * Payload: None (header-only)
     * 
     * Requirements:
     * - Must be sent AFTER successful authentication
     * - Must be sent AFTER SET_CHANNEL
     * 
     * Response:
     * - Node sends GET_BLOCK immediately (228-byte template)
     * - Then sends NEW_BLOCK on every block validation
     */
    constexpr uint16_t MINER_READY = 0xD007;
    
    // ========================================================================
    // TEMPLATE DELIVERY (0xD008-0xD009) - THE KEY OPCODES!
    // ========================================================================
    
    /**
     * GET_BLOCK: Node sends initial mining template (PUSH!)
     * Direction: Node → Miner
     * Payload: 228 bytes (12-byte metadata + 216-byte block)
     * 
     * Metadata (12 bytes, big-endian):
     *   [0-3]   nUnifiedHeight  - Overall blockchain height
     *   [4-7]   nChannelHeight  - Channel-specific height
     *   [8-11]  nDifficulty     - Mining target (nBits)
     * 
     * Block (216 bytes):
     *   Full serialized block template for mining
     * 
     * Triggered:
     * - Immediately after MINER_READY (no polling needed!)
     * - When miner requests new work (if needed)
     */
    constexpr uint16_t GET_BLOCK = 0xD008;
    
    /**
     * NEW_BLOCK: Node pushes updated template when blockchain advances
     * Direction: Node → Miner (PUSH!)
     * Payload: 228 bytes (12-byte metadata + 216-byte block)
     * 
     * Same format as GET_BLOCK - node pushes this automatically!
     * 
     * Triggered:
     * - When a new block is validated on the blockchain
     * - Pushed to ALL subscribed miners (channel-specific)
     * 
     * Miner action:
     * - Abandon current work
     * - Switch to new template immediately
     * - Resume mining
     */
    constexpr uint16_t NEW_BLOCK = 0xD009;
    
    // ========================================================================
    // SOLUTION SUBMISSION (0xD00A-0xD00C)
    // ========================================================================
    
    /**
     * SUBMIT_BLOCK: Miner submits solved block
     * Direction: Miner → Node
     * Payload: 216 bytes (solved block)
     */
    constexpr uint16_t SUBMIT_BLOCK = 0xD00A;
    
    /**
     * BLOCK_ACCEPTED: Node accepts submitted block
     * Direction: Node → Miner
     * Payload: None or [height(4)][hash(32)] (optional)
     */
    constexpr uint16_t BLOCK_ACCEPTED = 0xD00B;
    
    /**
     * BLOCK_REJECTED: Node rejects submitted block
     * Direction: Node → Miner
     * Payload: [reason(1)]
     * 
     * Rejection reasons:
     */
    constexpr uint16_t BLOCK_REJECTED = 0xD00C;
    
    /**
     * @enum RejectionReason
     * @brief Reasons why a block might be rejected
     */
    enum RejectionReason : uint8_t {
        STALE       = 0x01,  // Block already found (height mismatch)
        INVALID_POW = 0x02,  // Proof-of-work doesn't meet difficulty
        INVALID_SIG = 0x03,  // Falcon signature verification failed
        DUPLICATE   = 0x04,  // Duplicate block submission
        FORK        = 0x05,  // Blockchain forked, block invalid
    };
    
} // namespace StatelessMining

} // namespace LLP
} // namespace nexusminer

#endif // NEXUSMINER_LLP_MINER_OPCODES_HPP
