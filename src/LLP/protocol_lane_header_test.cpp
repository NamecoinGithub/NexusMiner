/**
 * @file protocol_lane_header_test.cpp
 * @brief Unit tests for Protocol Lane Determination from PORT and Header Size
 *
 * Validates the relationship between:
 *   - Connection port → Protocol lane (LEGACY vs STATELESS)
 *   - Protocol lane → Header byte size (1-byte vs 2-byte)
 *   - Packet wire format (1-byte legacy header vs 2-byte stateless header)
 *   - Header-only vs data-bearing classification per lane
 *
 * Port-Lane-Header mapping:
 *   Port 8323  → LEGACY    → 1-byte header (uint8_t,  0x00-0xFF)
 *   Port 9323+ → STATELESS → 2-byte header (uint16_t, 0xD000-0xD0FF)
 */

#include "miner_opcodes.hpp"
#include "protocol_lane.hpp"
#include "packet.hpp"
#include <iostream>
#include <cstdint>
#include <gtest/gtest.h>

using namespace nexusminer;

// Fully qualified aliases to avoid ambiguity with global ::LLP namespace from block.hpp
namespace MinerLLP = nexusminer::LLP;
