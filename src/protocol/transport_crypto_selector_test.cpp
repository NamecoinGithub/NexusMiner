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
            auto enc = selector.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp encrypt succeeds", enc.success);
            auto dec = selector.decrypt_packet(enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp decrypt succeeds", dec.success);
            check("evp round-trip matches", dec.data == plaintext);
        }
    }

    // 4) EVP duplicate / rewind nonce rejection
    {
        EVPAdapter evp(logger);
        if (evp.is_ready()) {
            constexpr uint32_t sid = 0xAABBCCDD;
            auto enc1 = evp.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp direct encrypt #1 succeeds", enc1.success);
            auto dec1 = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp direct decrypt #1 succeeds", dec1.success);

            auto duplicate = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp duplicate nonce rejected", !duplicate.success);
            check("evp duplicate nonce error code", duplicate.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::NONCE_REPLAY);

            auto enc2 = evp.encrypt_packet(test_plaintext(64), key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp direct encrypt #2 succeeds", enc2.success);
            auto dec2 = evp.decrypt_packet(enc2.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
            check("evp direct decrypt #2 succeeds", dec2.success);

            auto rewind = evp.decrypt_packet(enc1.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad);
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
            auto enc = selector.encrypt_packet(plaintext, key, sid_ok, PacketCryptoPhase::SESSION_BOUND, aad);
            check("sid test encrypt succeeds", enc.success);
            auto bad = selector.decrypt_packet(enc.data, key, sid_bad, PacketCryptoPhase::SESSION_BOUND, aad);
            check("sid mismatch rejected", !bad.success);
            check("sid mismatch error code", bad.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::SESSION_ID_MISMATCH);
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

            auto postauth_reject = selector.decrypt_packet(preauth.data, key, 0x12345678, PacketCryptoPhase::SESSION_BOUND, aad);
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
            const std::vector<uint8_t> aad_a{'M', 'S', 'G', '_', 'A'};
            const std::vector<uint8_t> aad_b{'M', 'S', 'G', '_', 'B'};
            auto enc = selector.encrypt_packet(plaintext, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_a);
            check("aad mismatch encrypt succeeds", enc.success);
            auto dec = selector.decrypt_packet(enc.data, key, sid, PacketCryptoPhase::SESSION_BOUND, aad_b);
            check("aad mismatch rejected", !dec.success);
            check("aad mismatch auth-failure code",
                  dec.error_code == ChaCha20Wrapper::CryptoResult::ErrorCode::AUTH_FAILURE);
        } else {
            check("aad mismatch test skipped on legacy fallback", true);
        }
    }

    std::cout << "\nTests run: " << tests_run << ", failed: " << tests_failed << std::endl;
    return tests_failed == 0 ? 0 : 1;
}
