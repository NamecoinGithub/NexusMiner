#include "cpu/prime_validation.hpp"
#include "LLC/types/uint1024.h"

#include <boost/multiprecision/cpp_int.hpp>

#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

using boost_uint1024_t = boost::multiprecision::uint1024_t;

namespace
{
int tests_run = 0;
int tests_failed = 0;

void print_result(const char* name, bool passed)
{
    ++tests_run;
    std::cout << (passed ? "  [PASS] " : "  [FAIL] ") << name << '\n';
    if (!passed)
        ++tests_failed;
}

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
    uint1024_t result;
    std::memcpy(&result, value.backend().limbs(), sizeof(result));
    return result;
}

void test_optimized_conversion_matches_hex_roundtrip()
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

    print_result("Optimized uint1024 conversion matches legacy hex round-trip", matches);
}

}

int main()
{
    test_optimized_conversion_matches_hex_roundtrip();

    if (tests_failed != 0)
    {
        std::cout << "\nprime_validation_test: " << tests_failed << " of " << tests_run
                  << " test(s) failed.\n";
        return 1;
    }

    std::cout << "\nprime_validation_test: all " << tests_run << " test(s) passed.\n";
    return 0;
}
