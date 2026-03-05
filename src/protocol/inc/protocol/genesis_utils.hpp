/*__________________________________________________________________________________________

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014]++

            (c) Copyright The Nexus Developers 2014 - 2023

            Distributed under the MIT software license, see the accompanying
            file COPYING or http://www.opensource.org/licenses/mit-license.php.

            "ad vocem populi" - To the Voice of the People

____________________________________________________________________________________________*/

#pragma once

#include <vector>
#include <cstdint>

namespace genesis_utils {

/**
 * @brief Validates that a genesis hash is non-zero
 *
 * Checks if the provided genesis hash contains at least one non-zero byte.
 * Used to verify that a genesis hash has been properly configured before
 * attempting cryptographic operations that depend on it.
 *
 * @param genesis The genesis hash as a byte vector
 * @return true if genesis is non-empty and contains at least one non-zero byte
 * @return false if genesis is empty or all bytes are zero
 */
inline bool is_valid_genesis(const std::vector<uint8_t>& genesis) {
    if (genesis.empty()) {
        return false;
    }
    // Early return optimization - stop at first non-zero byte
    for (uint8_t byte : genesis) {
        if (byte != 0) {
            return true;
        }
    }
    return false;
}

} // namespace genesis_utils
