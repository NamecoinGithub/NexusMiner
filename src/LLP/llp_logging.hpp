#ifndef NEXUSMINER_LLP_LOGGING_HPP
#define NEXUSMINER_LLP_LOGGING_HPP

#include <string>
#include <cstdint>
#include <cstdio>
#include <algorithm>
#include "network/types.hpp"
#include "miner_opcodes.hpp"

namespace nexusminer
{
	/** LLP Packet Header Codes (use centralized definitions from miner_opcodes.hpp) **/
	namespace LLP_Headers
	{
		enum
		{
			/** DATA PACKETS **/
			BLOCK_DATA = LLP::BLOCK_DATA,
			SUBMIT_BLOCK = LLP::SUBMIT_BLOCK,
			BLOCK_HEIGHT = LLP::BLOCK_HEIGHT,
			SET_CHANNEL = LLP::SET_CHANNEL,
			BLOCK_REWARD = LLP::BLOCK_REWARD,
			SET_COINBASE = LLP::SET_COINBASE,
			GOOD_BLOCK = LLP::GOOD_BLOCK,
			ORPHAN_BLOCK = LLP::ORPHAN_BLOCK,

			//POOL RELATED (NexusMiner extensions)
			LOGIN = LLP::LOGIN,
			HASHRATE = LLP::HASHRATE,
			WORK = LLP::WORK,
			LOGIN_V2_SUCCESS = LLP::LOGIN_V2_SUCCESS,
			LOGIN_V2_FAIL = LLP::LOGIN_V2_FAIL,
			POOL_NOTIFICATION = LLP::POOL_NOTIFICATION,

			/** DATA REQUESTS **/
			CHECK_BLOCK = LLP::CHECK_BLOCK,
			SUBSCRIBE = LLP::SUBSCRIBE,

			/** REQUEST PACKETS **/
			GET_BLOCK = LLP::GET_BLOCK,
			GET_HEIGHT = LLP::GET_HEIGHT,
			GET_REWARD = LLP::GET_REWARD,

			/** SERVER COMMANDS **/
			CLEAR_MAP = LLP::CLEAR_MAP,
			GET_ROUND = LLP::GET_ROUND,

			// LEGACY POOL
			GET_PAYOUT = LLP::GET_PAYOUT,
			GET_HASHRATE = LLP::GET_HASHRATE,
			LOGIN_SUCCESS = LLP::LOGIN_SUCCESS,
			LOGIN_FAIL = LLP::LOGIN_FAIL,

			/** RESPONSE PACKETS **/
			ACCEPT = LLP::ACCEPT,
			BLOCK_ACCEPTED = LLP::BLOCK_ACCEPTED,
			REJECT = LLP::REJECT,
			BLOCK_REJECTED = LLP::BLOCK_REJECTED,
			COINBASE_SET = LLP::COINBASE_SET,
			COINBASE_FAIL = LLP::COINBASE_FAIL,

			/** ROUND VALIDATIONS **/
			NEW_ROUND = LLP::NEW_ROUND,
			OLD_ROUND = LLP::OLD_ROUND,
			CHANNEL_ACK = LLP::CHANNEL_ACK,

			/** AUTHENTICATION PACKETS (synchronized with LLL-TAO Phase 2) **/
			MINER_AUTH_INIT = LLP::MINER_AUTH_INIT,
			MINER_AUTH_CHALLENGE = LLP::MINER_AUTH_CHALLENGE,
			MINER_AUTH_RESPONSE = LLP::MINER_AUTH_RESPONSE,
			MINER_AUTH_RESULT = LLP::MINER_AUTH_RESULT,

			/** SESSION MANAGEMENT PACKETS (Phase 2) **/
			SESSION_START = LLP::SESSION_START,
			SESSION_KEEPALIVE = LLP::SESSION_KEEPALIVE,

			// LEGACY
			BLOCK = LLP::BLOCK,
			STALE = LLP::STALE,

			/** GENERIC **/
			PING = LLP::PING,
			CLOSE = LLP::CLOSE
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
