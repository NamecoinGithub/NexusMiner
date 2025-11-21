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
 * LLP Packet Header Opcodes
 * 
 * These opcodes define the message types in the Lower Level Protocol (LLP)
 * used for communication between NexusMiner and LLL-TAO mining servers.
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
    
    // Note: GET_PAYOUT and GET_HASHRATE overlap with CLEAR_MAP/GET_ROUND
    // These are pool-only legacy opcodes that reuse the same values
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
    // GENERIC PACKETS (253-254)
    // Protocol-level control messages
    // ============================================================================
    
    /** Keepalive ping */
    PING = 253,
    
    /** Close connection */
    CLOSE = 254
};

} // namespace LLP
} // namespace nexusminer

#endif // NEXUSMINER_LLP_MINER_OPCODES_HPP
