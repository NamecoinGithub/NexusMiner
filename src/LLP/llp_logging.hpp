#ifndef NEXUSMINER_LLP_LOGGING_HPP
#define NEXUSMINER_LLP_LOGGING_HPP

#include <string>
#include <cstdint>
#include <cstdio>
#include <algorithm>
#include "network/types.hpp"

namespace nexusminer
{
	/** LLP Packet Header Codes (synchronized with LLL-TAO Phase 2) **/
	namespace LLP_Headers
	{
		enum
		{
			/** DATA PACKETS **/
			BLOCK_DATA = 0,
			SUBMIT_BLOCK = 1,
			BLOCK_HEIGHT = 2,
			SET_CHANNEL = 3,
			BLOCK_REWARD = 4,
			SET_COINBASE = 5,
			GOOD_BLOCK = 6,
			ORPHAN_BLOCK = 7,

			//POOL RELATED (NexusMiner extensions)
			LOGIN = 8,
			HASHRATE = 9,
			WORK = 10,
			LOGIN_V2_SUCCESS = 11,
			LOGIN_V2_FAIL = 12,
			POOL_NOTIFICATION = 13,

			/** DATA REQUESTS **/
			CHECK_BLOCK = 64,
			SUBSCRIBE = 65,

			/** REQUEST PACKETS **/
			GET_BLOCK = 129,
			GET_HEIGHT = 130,
			GET_REWARD = 131,

			/** SERVER COMMANDS **/
			CLEAR_MAP = 132,
			GET_ROUND = 133,

			// LEGACY POOL
			GET_PAYOUT = 132,  // Overlap - pool only
			GET_HASHRATE = 133,  // Overlap - pool only
			LOGIN_SUCCESS = 134,
			LOGIN_FAIL = 135,

			/** RESPONSE PACKETS **/
			ACCEPT = 200,
			BLOCK_ACCEPTED = 200,
			REJECT = 201,
			BLOCK_REJECTED = 201,
			COINBASE_SET = 202,
			COINBASE_FAIL = 203,

			/** ROUND VALIDATIONS **/
			NEW_ROUND = 204,
			OLD_ROUND = 205,
			CHANNEL_ACK = 206,

			/** AUTHENTICATION PACKETS (synchronized with LLL-TAO Phase 2) **/
			MINER_AUTH_INIT = 207,
			MINER_AUTH_CHALLENGE = 208,
			MINER_AUTH_RESPONSE = 209,
			MINER_AUTH_RESULT = 210,

			/** SESSION MANAGEMENT PACKETS (Phase 2) **/
			SESSION_START = 211,
			SESSION_KEEPALIVE = 212,

			// LEGACY
			BLOCK = 202,
			STALE = 203,

			/** GENERIC **/
			PING = 253,
			CLOSE = 254
		};
	}

	/** Get human-readable name for LLP packet header code **/
	inline const char* get_llp_header_name(std::uint8_t header)
	{
		switch(header)
		{
			case LLP_Headers::BLOCK_DATA: return "BLOCK_DATA";
			case LLP_Headers::SUBMIT_BLOCK: return "SUBMIT_BLOCK";
			case LLP_Headers::BLOCK_HEIGHT: return "BLOCK_HEIGHT";
			case LLP_Headers::SET_CHANNEL: return "SET_CHANNEL";
			case LLP_Headers::BLOCK_REWARD: return "BLOCK_REWARD";
			case LLP_Headers::SET_COINBASE: return "SET_COINBASE";
			case LLP_Headers::GOOD_BLOCK: return "GOOD_BLOCK";
			case LLP_Headers::ORPHAN_BLOCK: return "ORPHAN_BLOCK";
			case LLP_Headers::LOGIN: return "LOGIN";
			case LLP_Headers::HASHRATE: return "HASHRATE";
			case LLP_Headers::WORK: return "WORK";
			case LLP_Headers::LOGIN_V2_SUCCESS: return "LOGIN_V2_SUCCESS";
			case LLP_Headers::LOGIN_V2_FAIL: return "LOGIN_V2_FAIL";
			case LLP_Headers::POOL_NOTIFICATION: return "POOL_NOTIFICATION";
			case LLP_Headers::CHECK_BLOCK: return "CHECK_BLOCK";
			case LLP_Headers::SUBSCRIBE: return "SUBSCRIBE";
			case LLP_Headers::GET_BLOCK: return "GET_BLOCK";
			case LLP_Headers::GET_HEIGHT: return "GET_HEIGHT";
			case LLP_Headers::GET_REWARD: return "GET_REWARD";
			case LLP_Headers::CLEAR_MAP: return "CLEAR_MAP";
			case LLP_Headers::GET_ROUND: return "GET_ROUND";
			case LLP_Headers::LOGIN_SUCCESS: return "LOGIN_SUCCESS";
			case LLP_Headers::LOGIN_FAIL: return "LOGIN_FAIL";
			case LLP_Headers::ACCEPT: return "ACCEPT";
			case LLP_Headers::REJECT: return "REJECT";
			case LLP_Headers::COINBASE_SET: return "COINBASE_SET";
			case LLP_Headers::COINBASE_FAIL: return "COINBASE_FAIL";
			case LLP_Headers::NEW_ROUND: return "NEW_ROUND";
			case LLP_Headers::OLD_ROUND: return "OLD_ROUND";
			case LLP_Headers::CHANNEL_ACK: return "CHANNEL_ACK";
			case LLP_Headers::MINER_AUTH_INIT: return "MINER_AUTH_INIT";
			case LLP_Headers::MINER_AUTH_CHALLENGE: return "MINER_AUTH_CHALLENGE";
			case LLP_Headers::MINER_AUTH_RESPONSE: return "MINER_AUTH_RESPONSE";
			case LLP_Headers::MINER_AUTH_RESULT: return "MINER_AUTH_RESULT";
			case LLP_Headers::SESSION_START: return "SESSION_START";
			case LLP_Headers::SESSION_KEEPALIVE: return "SESSION_KEEPALIVE";
			case LLP_Headers::PING: return "PING";
			case LLP_Headers::CLOSE: return "CLOSE";
			default: return "UNKNOWN";
		}
	}

	/** Format payload bytes as hex string (up to max_bytes) **/
	inline std::string format_llp_payload_hex(network::Shared_payload const& payload, std::size_t max_bytes = 16)
	{
		if (!payload || payload->empty())
		{
			return "";
		}
		
		std::string result;
		std::size_t bytes_to_show = std::min(payload->size(), max_bytes);
		result.reserve(bytes_to_show * 3);
		
		for (std::size_t i = 0; i < bytes_to_show; ++i)
		{
			char buf[4];
			snprintf(buf, sizeof(buf), "%02x ", (*payload)[i]);
			result += buf;
		}
		
		if (payload->size() > max_bytes)
		{
			result += "...";
		}
		
		return result;
	}

}

#endif
