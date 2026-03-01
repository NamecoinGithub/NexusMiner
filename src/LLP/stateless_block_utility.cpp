/**
 * @file stateless_block_utility.cpp
 * @brief Implementation of StatelessBlockUtility
 *
 * Compiled as part of the `protocol` STATIC library (listed in
 * src/protocol/CMakeLists.txt) so that it can include both LLP headers
 * (block_utils.hpp) and protocol headers (falcon_wrapper.hpp,
 * packet_builder.hpp).
 */

#include "include/stateless_block_utility.hpp"

#include "block_utils.hpp"
#include "miner_opcodes.hpp"
#include "protocol/falcon_wrapper.hpp"
#include "protocol/packet_builder.hpp"
#include "spdlog/spdlog.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace nexusminer {
namespace protocol {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void append_u64_le(std::vector<uint8_t>& dest, uint64_t value) {
    for (int i = 0; i < 8; ++i)
        dest.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
}

static void append_u16_le(std::vector<uint8_t>& dest, uint16_t value) {
    dest.push_back(static_cast<uint8_t>(value & 0xFF));
    dest.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

static uint32_t read_u32_be(const network::Payload& buf, size_t offset) {
    return (static_cast<uint32_t>(buf[offset])     << 24) |
           (static_cast<uint32_t>(buf[offset + 1]) << 16) |
           (static_cast<uint32_t>(buf[offset + 2]) <<  8) |
            static_cast<uint32_t>(buf[offset + 3]);
}

// ---------------------------------------------------------------------------
// decode_template
// ---------------------------------------------------------------------------

DecodedTemplate StatelessBlockUtility::decode_template(
    const network::Payload& raw_payload,
    uint32_t mining_channel,
    std::shared_ptr<spdlog::logger> logger)
{
    DecodedTemplate result;

    // ── Size gate ────────────────────────────────────────────────────────────
    if (raw_payload.size() != TEMPLATE_PAYLOAD_SIZE) {
        result.error_message =
            "STATELESS_GET_BLOCK payload size " +
            std::to_string(raw_payload.size()) +
            " != " + std::to_string(TEMPLATE_PAYLOAD_SIZE) + " (expected)";
        if (logger)
            logger->error("[StatelessBlockUtility::decode_template] {}",
                          result.error_message);
        return result;
    }

    // ── Diagnostic metadata (bytes 0–11, big-endian) ─────────────────────────
    result.unified_height   = read_u32_be(raw_payload, 0);
    result.channel_height   = read_u32_be(raw_payload, 4);
    result.difficulty_nbits = read_u32_be(raw_payload, 8);

    if (logger)
        logger->debug("[StatelessBlockUtility::decode_template] "
                      "metadata: unified={} channel={} nBits=0x{:08x}",
                      result.unified_height, result.channel_height,
                      result.difficulty_nbits);

    // ── Canonical block body (bytes 12–227, 216-byte Tritium) ────────────────
    network::Payload block_bytes(raw_payload.begin() + METADATA_PREFIX_SIZE,
                                 raw_payload.end());
    try {
        result.block = llp_utils::deserialize_block_header(block_bytes);
    } catch (const std::exception& ex) {
        result.error_message =
            std::string("block body deserialization failed: ") + ex.what();
        if (logger)
            logger->error("[StatelessBlockUtility::decode_template] {}",
                          result.error_message);
        return result;
    }

    // ── Derived validation flags ─────────────────────────────────────────────
    // metadata_consistent: block.nHeight should equal unified_height + 1
    // (the template targets the NEXT block to be mined).  Allow ±1 for the
    // tip-advance race window.
    if (result.unified_height > 0 && result.block.nHeight > 0) {
        int32_t diff = static_cast<int32_t>(result.block.nHeight) -
                       static_cast<int32_t>(result.unified_height + 1);
        result.metadata_consistent = (diff >= -1 && diff <= 1);
    }

    result.channel_consistent =
        (result.block.nChannel == mining_channel);

    if (logger) {
        if (!result.metadata_consistent)
            logger->warn("[StatelessBlockUtility::decode_template] "
                         "metadata_consistent=false: block.nHeight={} vs "
                         "unified_height+1={}",
                         result.block.nHeight, result.unified_height + 1);
        if (!result.channel_consistent)
            logger->warn("[StatelessBlockUtility::decode_template] "
                         "channel_consistent=false: block.nChannel={} vs "
                         "mining_channel={}",
                         result.block.nChannel, mining_channel);
    }

    result.valid = true;
    return result;
}

// ---------------------------------------------------------------------------
// encode_submit
// ---------------------------------------------------------------------------

SubmitResult StatelessBlockUtility::encode_submit(
    const ::LLP::CBlock& solved_block,
    const std::vector<uint8_t>& /*vOffsets*/,
    FalconSignatureWrapper* falcon,
    ProtocolLane lane,
    const HeightTracker::Snapshot& ht,
    std::shared_ptr<spdlog::logger> logger)
{
    SubmitResult result;

    // ── Pre-check 1: Nonce sanity ────────────────────────────────────────────
    if (solved_block.nNonce == 0) {
        result.rejection_reason = "nNonce is zero — block not yet solved";
        if (logger)
            logger->error("[StatelessBlockUtility::encode_submit] {}",
                          result.rejection_reason);
        return result;
    }

    // ── Pre-check 2: Channel plausibility ───────────────────────────────────
    if (solved_block.nChannel != 1 && solved_block.nChannel != 2) {
        result.rejection_reason =
            "invalid nChannel " + std::to_string(solved_block.nChannel) +
            " (expected 1=Prime or 2=Hash)";
        if (logger)
            logger->error("[StatelessBlockUtility::encode_submit] {}",
                          result.rejection_reason);
        return result;
    }

    // ── Pre-check 3: Height plausibility ────────────────────────────────────
    if (solved_block.nHeight == 0) {
        result.rejection_reason =
            "nHeight is zero — template not yet received";
        if (logger)
            logger->error("[StatelessBlockUtility::encode_submit] {}",
                          result.rejection_reason);
        return result;
    }

    // ── Pre-check 4: Staleness (informational — node is authoritative) ────────
    if (ht.is_template_stale()) {
        if (logger)
            logger->warn("[StatelessBlockUtility::encode_submit] "
                         "template appears stale (channel_height={} >= "
                         "channel_target={}) — submitting anyway; "
                         "node is authoritative",
                         ht.channel_height, ht.channel_target);
    }

    // ── Pre-check 5: Tip-moved (informational) ────────────────────────────────
    if (ht.is_tip_moved()) {
        if (logger)
            logger->warn("[StatelessBlockUtility::encode_submit] "
                         "unified tip moved (unified_height={} > "
                         "template_unified_height={}) — submitting anyway",
                         ht.unified_height, ht.template_unified_height);
    }

    // ── Serialize the canonical block body ────────────────────────────────────
    // Tritium format (216 bytes): nVersion(4) hashPrevBlock(128)
    // hashMerkleRoot(64) nChannel(4) nHeight(4) nBits(4) nNonce(8)
    auto block_bytes = llp_utils::serialize_full_block(solved_block,
                                                        /*is_tritium=*/true);
    if (block_bytes.size() != BLOCK_BODY_SIZE) {
        result.rejection_reason =
            "serialized block size " + std::to_string(block_bytes.size()) +
            " != " + std::to_string(BLOCK_BODY_SIZE) + " (expected Tritium)";
        if (logger)
            logger->error("[StatelessBlockUtility::encode_submit] {}",
                          result.rejection_reason);
        return result;
    }

    // ── Pre-check 6: Disposable Falcon sign (optional) ───────────────────────
    std::vector<uint8_t> plaintext;

    if (falcon != nullptr) {
        // Timestamp for replay-protection (8 bytes LE)
        uint64_t ts = static_cast<uint64_t>(
            std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now()));

        // message_to_sign = block_bytes || timestamp
        std::vector<uint8_t> msg_to_sign;
        msg_to_sign.reserve(block_bytes.size() + 8);
        msg_to_sign.insert(msg_to_sign.end(),
                           block_bytes.begin(), block_bytes.end());
        append_u64_le(msg_to_sign, ts);

        auto sig_result = falcon->sign_payload(
            msg_to_sign, FalconSignatureWrapper::SignatureType::BLOCK);

        if (!sig_result.success) {
            result.rejection_reason =
                "Falcon signing failed: " + sig_result.error_message;
            if (logger)
                logger->error("[StatelessBlockUtility::encode_submit] {}",
                              result.rejection_reason);
            return result;
        }

        // plaintext = block_bytes || timestamp(8) || sig_len(2) || sig
        uint16_t sig_len = static_cast<uint16_t>(sig_result.signature.size());
        plaintext.reserve(block_bytes.size() + 8 + 2 + sig_len);
        plaintext.insert(plaintext.end(), block_bytes.begin(), block_bytes.end());
        append_u64_le(plaintext, ts);
        append_u16_le(plaintext, sig_len);
        plaintext.insert(plaintext.end(),
                         sig_result.signature.begin(),
                         sig_result.signature.end());

        if (logger)
            logger->debug("[StatelessBlockUtility::encode_submit] "
                          "signed: block({})+ts(8)+siglen(2)+sig({}) = {} bytes",
                          block_bytes.size(), sig_len, plaintext.size());
    } else {
        // No signing — payload is just the serialized block bytes
        plaintext = std::move(block_bytes);
        if (logger)
            logger->debug("[StatelessBlockUtility::encode_submit] "
                          "unsigned submit: {} bytes (no Falcon signature)",
                          plaintext.size());
    }

    // ── Pre-check 7: Wire encode ─────────────────────────────────────────────
    auto wire = PacketBuilder::build(lane, LLP::SUBMIT_BLOCK, plaintext);
    if (!wire || wire->empty()) {
        result.rejection_reason = "PacketBuilder::build returned empty result";
        if (logger)
            logger->error("[StatelessBlockUtility::encode_submit] {}",
                          result.rejection_reason);
        return result;
    }

    result.valid      = true;
    result.wire_bytes = wire;
    return result;
}

} // namespace protocol
} // namespace nexusminer
