#ifndef NEXUSMINER_LLP_STATELESS_BLOCK_UTILITY_HPP
#define NEXUSMINER_LLP_STATELESS_BLOCK_UTILITY_HPP

/**
 * @file stateless_block_utility.hpp
 * @brief Canonical encode/decode utility for the stateless mining lane
 *
 * StatelessBlockUtility centralises all block-template byte-decoding and
 * solved-block byte-encoding for the stateless mining protocol, plus performs
 * Disposable Falcon pre-checks before a SUBMIT_BLOCK is sent to the node.
 *
 * Namespace separation:
 *   Canonical inputs  — block.nHeight, block.nBits, block.nChannel,
 *                       block.hashPrevBlock, block.nNonce.  These drive
 *                       mining and ProofHash; they are never overwritten from
 *                       secondary sources.
 *   Diagnostic inputs — unified_height / channel_height from the 12-byte
 *                       metadata prefix and HeightTracker snapshot fields.
 *                       These are for Colin / staleness detection only.
 */

#include "LLP/block.hpp"
#include "network/types.hpp"
#include "protocol/height_tracker.hpp"
#include "protocol_lane.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Forward declaration – avoids a circular dep between LLP and protocol
namespace nexusminer { namespace protocol { class FalconSignatureWrapper; } }

namespace spdlog { class logger; }

namespace nexusminer {
namespace protocol {

/**
 * @brief Result of a decode_template() call
 *
 * Canonical fields come exclusively from the 216-byte Tritium block body.
 * Metadata fields (unified_height, channel_height, difficulty_nbits) come
 * from the 12-byte big-endian prefix and are DIAGNOSTIC/telemetry only.
 */
struct DecodedTemplate {
    // ── Diagnostic metadata (12-byte prefix, big-endian) ────────────────────
    /** Unified blockchain height — diagnostic; feed only to OnTemplateMetadata() */
    uint32_t unified_height{0};
    /** Channel-specific height — diagnostic; feed only to OnTemplateMetadata() */
    uint32_t channel_height{0};
    /** Mining difficulty (compact nBits) — diagnostic */
    uint32_t difficulty_nbits{0};

    // ── Canonical mining state (216-byte Tritium block) ──────────────────────
    /**
     * Decoded block header — the canonical source of truth for all mining
     * decisions: nVersion, hashPrevBlock, hashMerkleRoot, nChannel, nHeight,
     * nBits, nNonce.  Never overwrite these from the metadata prefix.
     */
    ::LLP::CBlock block;

    // ── Derived validation flags ─────────────────────────────────────────────
    /**
     * True when block.nHeight ≈ unified_height + 1 (within ±1 tolerance for
     * the tip-advance race).  A mismatch is a warning, not a hard reject.
     */
    bool metadata_consistent{false};
    /** True when block.nChannel equals the declared mining channel. */
    bool channel_consistent{false};

    /** True when the 228-byte payload was successfully decoded. */
    bool valid{false};
    /** Human-readable reason for failure (empty when valid == true). */
    std::string error_message;
};

/**
 * @brief Result of an encode_submit() call
 */
struct SubmitResult {
    /** False → do NOT send; block failed a pre-check. */
    bool valid{false};
    /** Human-readable rejection reason (logged by caller). */
    std::string rejection_reason;
    /**
     * Wire-encoded bytes (PacketBuilder-framed plaintext payload).
     * Non-null only when valid == true.
     *
     * For the STATELESS lane the first two bytes are 0xD0, 0x01 (opcode
     * 0xD001).  For the LEGACY lane the first byte is 0x01.
     *
     * Note: ChaCha20 encryption (required by the stateless lane before
     * sending to the node) is NOT applied here — the caller must encrypt
     * the payload portion and re-frame with PacketBuilder after calling
     * this function.  This design keeps the session-key material inside
     * Solo and makes encode_submit() fully unit-testable.
     */
    network::Shared_payload wire_bytes;
};

/**
 * @brief Canonical encode / decode utility for the stateless mining lane
 *
 * All methods are static — no instance state.
 */
class StatelessBlockUtility {
public:
    // ─── Wire-format constants ───────────────────────────────────────────────
    /** Total payload size for a STATELESS_GET_BLOCK (12 metadata + 216 block) */
    static constexpr size_t TEMPLATE_PAYLOAD_SIZE = 228;
    /** Size of the metadata prefix in a STATELESS_GET_BLOCK payload */
    static constexpr size_t METADATA_PREFIX_SIZE  = 12;
    /** Size of the Tritium block body */
    static constexpr size_t BLOCK_BODY_SIZE        = 216;

    // =========================================================================
    // Template decode  (Node → Miner)
    // =========================================================================

    /**
     * @brief Decode a 228-byte STATELESS_GET_BLOCK payload into a canonical struct.
     *
     * Canonical inputs extracted from the block body (bytes 12–227):
     *   block.nHeight, block.nChannel, block.nBits, block.hashPrevBlock,
     *   block.nNonce — these drive mining decisions.
     *
     * Diagnostic inputs from the metadata prefix (bytes 0–11, big-endian):
     *   unified_height, channel_height, difficulty_nbits — route only to
     *   HeightTracker::OnTemplateMetadata(), never to OnGetRound().
     *
     * @param raw_payload   The full 228-byte payload from the network packet.
     *                      Returns an invalid DecodedTemplate if the size is
     *                      not exactly 228 bytes.
     * @param mining_channel Mining channel the miner is configured for
     *                      (1 = Prime, 2 = Hash).  Used to populate
     *                      channel_consistent.
     * @param logger        Optional spdlog logger; may be nullptr.
     * @return DecodedTemplate — caller checks DecodedTemplate::valid before use.
     */
    static DecodedTemplate decode_template(const network::Payload& raw_payload,
                                           uint32_t mining_channel,
                                           std::shared_ptr<spdlog::logger> logger);

    // =========================================================================
    // Submit encode  (Miner → Node)  with pre-checks
    // =========================================================================

    /**
     * @brief Pre-check and wire-encode a solved block for submission.
     *
     * Pre-check sequence (canonical gates, in order):
     *  1. Nonce sanity:     solved_block.nNonce != 0
     *  2. Channel validity: solved_block.nChannel ∈ {1, 2}
     *  3. Height validity:  solved_block.nHeight > 0
     *  4. Staleness (warn, do not block — node is authoritative)
     *  5. Tip-moved  (warn, do not block)
     *  6. Falcon sign: if falcon != nullptr, sign serialized block and append
     *                  signature; if signing fails, return valid=false.
     *  7. Wire encode: PacketBuilder::build(lane, SUBMIT_BLOCK, payload).
     *
     * @param solved_block  Block header with nNonce filled by the worker.
     * @param vOffsets      Prime offsets (empty for hash channel).
     * @param falcon        Disposable Falcon wrapper; nullptr = skip signing.
     * @param lane          ProtocolLane::STATELESS → opcode 0xD001,
     *                      ProtocolLane::LEGACY    → opcode 0x01.
     * @param ht            Read-only HeightTracker snapshot for diagnostic
     *                      staleness / tip-moved pre-checks.  Does NOT write
     *                      back to the tracker.
     * @param logger        Optional spdlog logger; may be nullptr.
     * @return SubmitResult — check valid before sending wire_bytes.
     */
    static SubmitResult encode_submit(const ::LLP::CBlock& solved_block,
                                      const std::vector<uint8_t>& vOffsets,
                                      FalconSignatureWrapper* falcon,
                                      ProtocolLane lane,
                                      const HeightTracker::Snapshot& ht,
                                      std::shared_ptr<spdlog::logger> logger);

private:
    StatelessBlockUtility() = delete;
};

} // namespace protocol
} // namespace nexusminer

#endif // NEXUSMINER_LLP_STATELESS_BLOCK_UTILITY_HPP
