#include <iostream>
#include <algorithm>
#include <cstdint>
#include "Util/include/exponential_backoff.h"
#include "protocol/inc/protocol/protocol_constants.hpp"
#include <gtest/gtest.h>

// Use constants from protocol_constants.hpp
using nexusminer::protocol::ProtocolConstants::MAX_SESSION_AUTH_RETRIES;
using nexusminer::protocol::ProtocolConstants::BASE_SESSION_RETRY_MS;
using nexusminer::protocol::ProtocolConstants::MAX_SESSION_RETRY_MS;

namespace
{
// Test helper using the new utility
uint32_t calculate_backoff_delay_ms(uint32_t attempt_count)
{
    nexusminer::util::ExponentialBackoff backoff{BASE_SESSION_RETRY_MS, MAX_SESSION_RETRY_MS};
    return backoff.calculate_delay_ms(attempt_count);
}
}
