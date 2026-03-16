#include "protocol/transport_crypto_selector.hpp"
#include "protocol/chacha20_wrapper.hpp"
#include <iostream>
#include <vector>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/null_sink.h"

using namespace nexusminer::protocol;

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char* name, bool condition)
{
    ++tests_run;
    std::cout << "  [" << (condition ? "PASS" : "FAIL") << "] " << name << std::endl;
    if (!condition) {
        ++tests_failed;
    }
}

static std::vector<uint8_t> test_key()
{
    std::vector<uint8_t> key(32);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i + 1);
    }
    return key;
}

static std::vector<uint8_t> test_plaintext(std::size_t n)
{
    std::vector<uint8_t> out(n);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(i & 0xFF);
    }
    return out;
}

int main()
{
    auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
    auto logger = std::make_shared<spdlog::logger>("logger", null_sink);
    spdlog::set_default_logger(logger);

    std::cout << "========================================" << std::endl;
    std::cout << "Transport Crypto Selector Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    const auto key = test_key();
    const auto plaintext = test_plaintext(128);
    const std::vector<uint8_t> aad{'T', 'E', 'S', 'T'};
    const std::vector<uint8_t> reward_aad{
        'R', 'E', 'W', 'A', 'R', 'D', '_', 'R', 'E', 'S', 'U', 'L', 'T'
    };

    // 1) mode selection + fallback
    {
        TransportCryptoSelector selector(logger);
        selector.configure("legacy");
        check("mode selection legacy", selector.active_mode() == "legacy");

        selector.configure("invalid-mode");
        check("invalid mode falls back to legacy", selector.active_mode() == "legacy");
    }

    // 2) legacy mode regression behavior
    {
        TransportCryptoSelector selector(logger);
        selector.configure("legacy");
        auto enc = selector.encrypt_packet(plaintext, key, 0, PacketCryptoPhase::PRE_AUTH, aad);
        check("legacy encrypt succeeds", enc.success);
        check("legacy frame includes nonce+cipher+tag",
              enc.data.size() == plaintext.size() + 12 + 16);

        auto dec = selector.decrypt_packet(enc.data, key, 0, PacketCryptoPhase::PRE_AUTH, aad);
        check("legacy decrypt succeeds", dec.success);
        check("legacy round-trip unchanged", dec.data == plaintext);
    }

    // 3) EVP happy path
    {
        TransportCryptoSelector selector(logger);
        selector.configure("evp");
        check("evp mode selected or safe fallback",
              selector.active_mode() == "evp" || selector.active_mode() == "legacy");

        if (selector.active_mode() == "evp") {
            constexpr uint32_t sid = 0x11223344;
            constexpr uint64_t epoch = 1;
            auto enc = selector.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp encrypt succeeds", enc.success);
            auto dec = selector.decrypt_packet(enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp decrypt succeeds", dec.success);
            check("evp round-trip matches", dec.data == plaintext);
        }
    }

    // 4) EVP duplicate / rewind nonce rejection
    {
        EVPAdapter evp(logger);
        if (evp.is_ready()) {
            constexpr uint32_t sid = 0xAABBCCDD;
            constexpr uint64_t epoch = 1;
            auto enc1 = evp.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp direct encrypt #1 succeeds", enc1.success);
            auto dec1 = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp direct decrypt #1 succeeds", dec1.success);

            auto duplicate = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp duplicate nonce rejected", !duplicate.success);
            check("evp duplicate nonce error code", duplicate.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::NONCE_REPLAY);

            auto enc2 = evp.encrypt_packet(test_plaintext(64), key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp direct encrypt #2 succeeds", enc2.success);
            auto dec2 = evp.decrypt_packet(enc2.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp direct decrypt #2 succeeds", dec2.success);

            auto rewind = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("evp rewind nonce rejected", !rewind.success);
            check("evp rewind nonce error code", rewind.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::NONCE_REPLAY);
        } else {
            check("evp adapter availability", true);
        }
    }

    // 5) SID mismatch => expected auth failure in SESSION_BOUND EVP mode
    {
        TransportCryptoSelector selector(logger);
        selector.configure("evp");
        if (selector.active_mode() == "evp") {
            constexpr uint32_t sid_ok = 0x01020304;
            constexpr uint32_t sid_bad = 0xDEADBEEF;
            constexpr uint64_t epoch = 1;
            auto enc = selector.encrypt_packet(plaintext, key, sid_ok, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("sid test encrypt succeeds", enc.success);
            auto bad = selector.decrypt_packet(enc.data, key, sid_bad, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("sid mismatch rejected", !bad.success);
            check("sid mismatch error code", bad.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::STALE_SESSION);
        } else {
            check("sid mismatch test skipped on legacy fallback", true);
        }
    }

    // 6) PRE_AUTH acceptance + SESSION_BOUND enforcement transition
    {
        TransportCryptoSelector selector(logger);
        selector.configure("evp");
        if (selector.active_mode() == "evp") {
            auto preauth = selector.encrypt_packet(plaintext, key, 0, PacketCryptoPhase::PRE_AUTH, aad);
            check("pre-auth encrypt accepted", preauth.success);
            auto preauth_dec = selector.decrypt_packet(preauth.data, key, 0, PacketCryptoPhase::PRE_AUTH, aad);
            check("pre-auth decrypt accepted", preauth_dec.success);

            auto postauth_reject = selector.decrypt_packet(preauth.data, key, 0x12345678, PacketCryptoPhase::SESSION_BOUND, aad, 0);
            check("post-auth enforces session-bound envelope", !postauth_reject.success);
        } else {
            check("phase transition test skipped on legacy fallback", true);
        }
    }

    // 7) AAD mismatch => auth failure in SESSION_BOUND EVP mode
    {
        TransportCryptoSelector selector(logger);
        selector.configure("evp");
        if (selector.active_mode() == "evp") {
            constexpr uint32_t sid = 0x8899AABB;
            constexpr uint64_t epoch = 1;
            const std::vector<uint8_t> aad_a{'M', 'S', 'G', '_', 'A'};
            const std::vector<uint8_t> aad_b{'M', 'S', 'G', '_', 'B'};
            auto enc = selector.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_a, epoch);
            check("aad mismatch encrypt succeeds", enc.success);
            auto dec = selector.decrypt_packet(enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_b, epoch);
            check("aad mismatch rejected", !dec.success);
            check("aad mismatch auth-failure code",
                  dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::AUTH_FAILURE);
        } else {
            check("aad mismatch test skipped on legacy fallback", true);
        }
    }

    // 8) tamper detection (ciphertext/tag)
    {
        EVPAdapter evp(logger);
        if (evp.is_ready()) {
            constexpr uint32_t sid = 0x0A0B0C0D;
            constexpr uint64_t epoch = 7;
            auto enc = evp.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("tamper test encrypt succeeds", enc.success);
            if (enc.success && enc.data.size() > 10) {
                auto tampered_cipher = enc.data;
                tampered_cipher[tampered_cipher.size() - 17] ^= 0x01;
                auto dec_cipher = evp.decrypt_packet(tampered_cipher, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
                check("tampered ciphertext rejected", !dec_cipher.success);
                check("tampered ciphertext auth-failure code", dec_cipher.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::AUTH_FAILURE);

                auto tampered_tag = enc.data;
                tampered_tag.back() ^= 0x80;
                auto dec_tag = evp.decrypt_packet(tampered_tag, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
                check("tampered tag rejected", !dec_tag.success);
                check("tampered tag auth-failure code", dec_tag.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::AUTH_FAILURE);
            }
        } else {
            check("tamper detection skipped on unavailable evp", true);
        }
    }

    // 9) stale epoch/session + reconnect/session rotate invalidation
    {
        EVPAdapter evp(logger);
        if (evp.is_ready()) {
            constexpr uint32_t sid = 0x41424344;
            constexpr uint64_t epoch1 = 1;
            constexpr uint64_t epoch2 = 2;
            auto enc_epoch1 = evp.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch1);
            check("epoch #1 encrypt succeeds", enc_epoch1.success);
            auto stale = evp.decrypt_packet(enc_epoch1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch2);
            check("stale epoch rejected", !stale.success);
            check("stale epoch code", stale.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::STALE_SESSION);

            auto enc_epoch2 = evp.encrypt_packet(test_plaintext(32), key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch2);
            check("epoch #2 encrypt succeeds", enc_epoch2.success);
            auto old_after_rotate = evp.decrypt_packet(enc_epoch1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch2);
            check("old context invalidated after rotate", !old_after_rotate.success);
            check("old context invalidated code", old_after_rotate.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::STALE_SESSION);
        } else {
            check("stale epoch/session test skipped on unavailable evp", true);
        }
    }

    // 10) malformed decode boundaries
    {
        EVPAdapter evp(logger);
        if (evp.is_ready()) {
            constexpr uint32_t sid = 0x53545556;
            constexpr uint64_t epoch = 3;
            auto enc = evp.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
            check("malformed test encrypt succeeds", enc.success);
            if (enc.success) {
                std::vector<uint8_t> truncated(enc.data.begin(), enc.data.begin() + 10);
                auto short_dec = evp.decrypt_packet(truncated, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
                check("short frame rejected", !short_dec.success);
                check("short frame code", short_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR);

                auto bad_version = enc.data;
                bad_version[0] = 0xFF;
                auto bad_version_dec = evp.decrypt_packet(bad_version, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
                check("bad version rejected", !bad_version_dec.success);
                check("bad version code", bad_version_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::FRAME_FORMAT_ERROR);

                auto bad_flags = enc.data;
                bad_flags[1] = 0x00;
                auto bad_flags_dec = evp.decrypt_packet(bad_flags, key, sid, PacketCryptoPhase::SESSION_BOUND, aad, epoch);
                check("bad flags rejected", !bad_flags_dec.success);
                check("bad flags code", bad_flags_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::PHASE_VIOLATION);
            }
        } else {
            check("malformed decode test skipped on unavailable evp", true);
        }
    }

    // 11) reward-result specific decode reasons and mode-lock contract checks
    {
        constexpr uint32_t sid = 0x53545557;
        constexpr uint64_t epoch = 4;
        constexpr uint32_t wrong_sid = 0x01020304;

        TransportCryptoSelector selector(logger);
        selector.configure("evp");
        if (selector.active_mode() == "evp") {
            auto reward_enc = selector.encrypt_packet(
                std::vector<uint8_t>{0x01}, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
            check("reward-result evp encrypt succeeds", reward_enc.success);

            auto reward_dec = selector.decrypt_packet(
                reward_enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
            check("reward-result evp decrypt succeeds", reward_dec.success);
            check("reward-result plaintext round-trip", reward_dec.data == std::vector<uint8_t>{0x01});

            std::vector<uint8_t> short_frame(packet_crypto_constants::EVP_REWARD_RESULT_MIN_FRAME_BYTES - 1, 0x00);
            auto short_dec = selector.decrypt_packet(
                short_frame, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
            check("reward-result short frame rejected", !short_dec.success);
            check("reward-result short frame code",
                  short_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::REWARD_RESULT_FRAME_TOO_SHORT);

            auto bad_flags = reward_enc.data;
            bad_flags[1] = 0x00;
            auto bad_flags_dec = selector.decrypt_packet(
                bad_flags, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
            check("reward-result flags mismatch rejected", !bad_flags_dec.success);
            check("reward-result flags mismatch code",
                  bad_flags_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::REWARD_RESULT_FLAGS_MISMATCH);

            auto sid_mismatch_dec = selector.decrypt_packet(
                reward_enc.data, key, wrong_sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
            check("reward-result sid mismatch rejected", !sid_mismatch_dec.success);
            check("reward-result sid mismatch code",
                  sid_mismatch_dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::REWARD_RESULT_SESSION_MISMATCH);
        } else {
            check("reward-result evp checks skipped on legacy fallback", true);
        }

        TransportCryptoSelector legacy_selector(logger);
        legacy_selector.configure("legacy");
        auto legacy_reward_enc = legacy_selector.encrypt_packet(
            std::vector<uint8_t>{0x01}, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
        check("reward-result legacy encrypt succeeds", legacy_reward_enc.success);
        auto legacy_reward_dec = legacy_selector.decrypt_packet(
            legacy_reward_enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, reward_aad, epoch);
        check("reward-result legacy frame accepted", legacy_reward_dec.success);
        check("reward-result legacy round-trip", legacy_reward_dec.data == std::vector<uint8_t>{0x01});
    }

    std::cout << "\nTests run: " << tests_run << ", failed: " << tests_failed << std::endl;
    return tests_failed == 0 ? 0 : 1;
}
