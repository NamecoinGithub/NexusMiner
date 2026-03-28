#include <openssl/sha.h>

#include "qtv/QTVCapabilities.hpp"
#include "protocol/qtv_engine.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <gtest/gtest.h>

namespace {

struct Bucket
{
    int logical_id;
    int first_byte;
    int last_byte;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> tag;
};

struct FixtureEvent
{
    uint64_t epoch;
    int slot;
    int bucket_id;
    const char* tag_hex;
};

template <typename Container>
void append_bytes(std::vector<uint8_t>& out, const Container& container)
{
    out.insert(out.end(), container.begin(), container.end());
}

template <typename... Containers>
std::vector<uint8_t> concat_bytes(const Containers&... containers)
{
    std::vector<uint8_t> out;
    (append_bytes(out, containers), ...);
    return out;
}

std::vector<uint8_t> uint64le(uint64_t value)
{
    std::vector<uint8_t> bytes(8);
    for (std::size_t byte_index = 0; byte_index < bytes.size(); ++byte_index)
        bytes[byte_index] = static_cast<uint8_t>((value >> (byte_index * 8)) & 0xffu);
    return bytes;
}

template <typename... Containers>
std::vector<uint8_t> sha512_bytes(const Containers&... containers)
{
    const auto buffer = concat_bytes(containers...);
    std::vector<uint8_t> digest(SHA512_DIGEST_LENGTH);
    SHA512(buffer.data(), buffer.size(), digest.data());
    return digest;
}

std::string bytes_to_hex(const std::vector<uint8_t>& bytes)
{
    static const char* const HEX = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);

    for (uint8_t byte : bytes) {
        out.push_back(HEX[(byte >> 4) & 0x0f]);
        out.push_back(HEX[byte & 0x0f]);
    }

    return out;
}

std::vector<uint8_t> xor_bytes(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs)
{
    assert(lhs.size() == rhs.size());
    std::vector<uint8_t> out(lhs.size());

    for (std::size_t byte_index = 0; byte_index < lhs.size(); ++byte_index)
        out[byte_index] = static_cast<uint8_t>(lhs[byte_index] ^ rhs[byte_index]);

    return out;
}

std::vector<uint8_t> fixture_privkey()
{
    std::vector<uint8_t> privkey(2305);
    for (std::size_t byte_index = 0; byte_index < privkey.size(); ++byte_index)
        privkey[byte_index] = static_cast<uint8_t>((byte_index * 73 + 19) % 256);
    return privkey;
}

std::vector<uint8_t> fixture_message()
{
    static const std::string message = "laser-quantum-channel-v1";
    return std::vector<uint8_t>(message.begin(), message.end());
}

std::vector<Bucket> build_buckets(const std::vector<uint8_t>& privkey)
{
    const std::array<int, 4> lengths{577, 576, 576, 576};
    std::vector<Bucket> buckets;
    buckets.reserve(lengths.size());

    int first_byte = 1;
    std::size_t offset = 0;
    for (std::size_t bucket_index = 0; bucket_index < lengths.size(); ++bucket_index) {
        const int length = lengths[bucket_index];
        Bucket bucket;
        bucket.logical_id = static_cast<int>(bucket_index + 1);
        bucket.first_byte = first_byte;
        bucket.last_byte = first_byte + length - 1;
        bucket.payload.assign(privkey.begin() + static_cast<std::ptrdiff_t>(offset),
                              privkey.begin() + static_cast<std::ptrdiff_t>(offset + length));
        bucket.tag = sha512_bytes(
            bucket.payload,
            uint64le(static_cast<uint64_t>(bucket.logical_id)),
            uint64le(static_cast<uint64_t>(bucket.first_byte)),
            uint64le(static_cast<uint64_t>(bucket.last_byte)));
        buckets.push_back(bucket);

        offset += static_cast<std::size_t>(length);
        first_byte = bucket.last_byte + 1;
    }

    return buckets;
}

std::vector<uint8_t> chained_keystream(const std::vector<uint8_t>& tag, std::size_t length_bytes, uint64_t epoch)
{
    std::vector<uint8_t> stream;
    stream.reserve(length_bytes);

    uint64_t counter = 0;
    auto block = sha512_bytes(tag, uint64le(epoch), uint64le(counter));

    while (stream.size() < length_bytes) {
        append_bytes(stream, block);
        ++counter;
        block = sha512_bytes(block, tag, uint64le(epoch), uint64le(counter));
    }

    stream.resize(length_bytes);
    return stream;
}

std::vector<uint8_t> encode_bucket(const Bucket& bucket, uint64_t epoch)
{
    return xor_bytes(bucket.payload, chained_keystream(bucket.tag, bucket.payload.size(), epoch));
}

std::vector<uint8_t> laser_keystream(const std::vector<uint8_t>& working_vector,
                                     const Bucket& bucket,
                                     uint64_t epoch,
                                     int active_slot,
                                     int active_bucket_id,
                                     std::size_t length_bytes)
{
    std::vector<uint8_t> stream;
    stream.reserve(length_bytes);

    uint64_t counter = 0;
    auto block = sha512_bytes(
        working_vector,
        bucket.tag,
        uint64le(epoch),
        uint64le(static_cast<uint64_t>(active_slot)),
        uint64le(static_cast<uint64_t>(active_bucket_id)),
        uint64le(counter));

    while (stream.size() < length_bytes) {
        append_bytes(stream, block);
        ++counter;
        block = sha512_bytes(
            block,
            working_vector,
            bucket.tag,
            uint64le(epoch),
            uint64le(static_cast<uint64_t>(active_slot)),
            uint64le(static_cast<uint64_t>(active_bucket_id)),
            uint64le(counter));
    }

    stream.resize(length_bytes);
    return stream;
}

std::vector<uint8_t> encode_laser_tunnel(const std::vector<uint8_t>& message,
                                         const std::vector<uint8_t>& working_vector,
                                         const Bucket& bucket,
                                         uint64_t epoch,
                                         int active_slot,
                                         int active_bucket_id)
{
    return xor_bytes(
        message,
        laser_keystream(working_vector, bucket, epoch, active_slot, active_bucket_id, message.size()));
}

} // namespace
