#include "cpu/prime_validation.hpp"
#include "LLC/types/uint1024.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <gtest/gtest.h>

using boost_uint1024_t = boost::multiprecision::uint1024_t;

namespace
{
constexpr std::size_t kBoostUint1kLimbBytes = sizeof(boost::multiprecision::limb_type);

uint1024_t hex_roundtrip_reference(const boost_uint1024_t& value)
{
    std::stringstream stream;
    stream << std::hex << value;

    uint1024_t result;
    result.SetHex(stream.str());
    return result;
}

uint1024_t optimized_conversion(const boost_uint1024_t& value)
{
    uint1024_t result{};
    const auto limb_bytes = value.backend().size() * kBoostUint1kLimbBytes;
    if (limb_bytes > sizeof(result))
        throw std::runtime_error("Boost uint1024 limb storage exceeds LLC uint1024_t size");

    std::memcpy(&result, value.backend().limbs(), limb_bytes);
    return result;
}

TEST(PrimeValidationTest, test_optimized_conversion_matches_hex_roundtrip)
{
    const std::vector<boost_uint1024_t> samples = {
        0,
        1,
        2,
        0xFFFFFFFFu,
        boost_uint1024_t{0x1122334455667788ULL},
        (boost_uint1024_t{0x1122334455667788ULL} << 64) | boost_uint1024_t{0x99AABBCCDDEEFF00ULL},
        boost_uint1024_t{1} << 511,
        boost_uint1024_t{1} << 1023,
        (boost_uint1024_t{1} << 1000) | (boost_uint1024_t{1} << 512) | boost_uint1024_t{12345}
    };

    bool matches = true;
    for (const auto& sample : samples)
    {
        if (optimized_conversion(sample) != hex_roundtrip_reference(sample))
        {
            matches = false;
            break;
        }
    }

    EXPECT_TRUE(matches) << "Optimized uint1024 conversion matches legacy hex round-trip";
}

}
