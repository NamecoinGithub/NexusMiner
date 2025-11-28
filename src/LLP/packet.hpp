#ifndef NEXUSPOOL_LLP_PACKET_HPP
#define NEXUSPOOL_LLP_PACKET_HPP

#include <vector>
#include <cstdint>
#include <memory>
#include <iterator>
#include "network/types.hpp"
#include "block.hpp"
#include "utils.hpp"
#include "miner_opcodes.hpp"
#include "llp_logging.hpp"

namespace nexusminer
{
	/** Class to handle sending and receiving of LLP Packets. **/
	class Packet
	{
	public:

		// Packet headers - use centralized definitions from miner_opcodes.hpp
		// These values MUST match the node implementation exactly for protocol compatibility
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

			//POOL RELATED (NexusMiner extensions for pool mining)
			LOGIN = LLP::LOGIN,
			HASHRATE = LLP::HASHRATE,
			WORK = LLP::WORK,
			LOGIN_V2_SUCCESS = LLP::LOGIN_V2_SUCCESS,
			LOGIN_V2_FAIL = LLP::LOGIN_V2_FAIL,
			POOL_NOTIFICATION = LLP::POOL_NOTIFICATION,

			/** DATA REQUESTS (from LLL-TAO) **/
			CHECK_BLOCK = LLP::CHECK_BLOCK,
			SUBSCRIBE = LLP::SUBSCRIBE,

			/** REQUEST PACKETS **/
			GET_BLOCK = LLP::GET_BLOCK,
			GET_HEIGHT = LLP::GET_HEIGHT,
			GET_REWARD = LLP::GET_REWARD,

			/** SERVER COMMANDS (from LLL-TAO) **/
			CLEAR_MAP = LLP::CLEAR_MAP,
			GET_ROUND = LLP::GET_ROUND,

			// LEGACY POOL (NexusMiner extensions - kept for pool compatibility)
			GET_PAYOUT = LLP::GET_PAYOUT,
			GET_HASHRATE = LLP::GET_HASHRATE,
			LOGIN_SUCCESS = LLP::LOGIN_SUCCESS,
			LOGIN_FAIL = LLP::LOGIN_FAIL,

			/** RESPONSE PACKETS **/
			// NOTE: LLL-TAO uses BLOCK_ACCEPTED (200) and BLOCK_REJECTED (201)
			// We keep ACCEPT/REJECT as aliases for backward compatibility
			ACCEPT = LLP::ACCEPT,
			BLOCK_ACCEPTED = LLP::BLOCK_ACCEPTED,
			REJECT = LLP::REJECT,
			BLOCK_REJECTED = LLP::BLOCK_REJECTED,
			COINBASE_SET = LLP::COINBASE_SET,
			COINBASE_FAIL = LLP::COINBASE_FAIL,

			/** ROUND VALIDATIONS (from LLL-TAO) **/
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

			// LEGACY - kept for pool compatibility
			BLOCK = LLP::BLOCK,
			STALE = LLP::STALE,

			/** GENERIC **/
			PING = LLP::PING,
			CLOSE = LLP::CLOSE
		};

		Packet()
			: m_header{ 255 }
			, m_length{ 0 }
			, m_is_valid{ false }
		{
		}

		Packet(std::uint8_t header, network::Payload const& data)
			: m_header{ header }
			, m_is_valid{ true }
		{
			m_data = std::make_shared<network::Payload>(data);
			m_length = m_data->size();
		}

		Packet(std::uint8_t header, network::Shared_payload data)
			: m_header{ header }
			, m_length{ 0 }
			, m_is_valid{ true }
		{
			if (data)
			{
				m_data = std::move(data);
				m_length = m_data->size();
			}
		}

		explicit Packet(std::uint8_t header)
			: m_header{ header }
			, m_length{ 0 }
			, m_is_valid{ true }
		{
		}

		// creates a packet from received buffer
		explicit Packet(network::Shared_payload buffer)
		{
			m_is_valid = true;
			if (buffer->empty())
			{
				m_header = 255;
				m_is_valid = false;
			}
			else
			{
				m_header = (*buffer)[0];
			}
			m_length = 0;
			if (buffer->size() > 1 && buffer->size() < 5)
			{
				m_is_valid = false;
			}
			else if (buffer->size() > 4)
			{
				m_length = ((*buffer)[1] << 24) + ((*buffer)[2] << 16) + ((*buffer)[3] << 8) + ((*buffer)[4]);
				m_data = std::make_shared<network::Payload>(buffer->begin() + 5, buffer->end());
			}
		}

		/** Components of an LLP Packet.
			BYTE 0       : Header
			BYTE 1 - 5   : Length
			BYTE 6 - End : Data      **/
		std::uint8_t		m_header;
		std::uint32_t		m_length;
		network::Shared_payload m_data;
		bool m_is_valid;

		/**
		 * @brief Check if packet header is a Falcon Authentication packet (207-212)
		 * 
		 * Authentication packets carry payloads despite having headers >= 128:
		 * - MINER_AUTH_INIT (207): pubkey data
		 * - MINER_AUTH_CHALLENGE (208): nonce data
		 * - MINER_AUTH_RESPONSE (209): signature data
		 * - MINER_AUTH_RESULT (210): status + optional session_id
		 * - SESSION_START (211), SESSION_KEEPALIVE (212): session data
		 */
		inline bool is_auth_packet() const
		{
			return (m_header >= MINER_AUTH_INIT && m_header <= SESSION_KEEPALIVE);
		}

		inline bool is_valid() const
		{
			if (!m_is_valid)
			{
				return false;
			}

			// Special case: LOGIN message (legacy compatibility)
			if (m_header == 0 && m_length == 0)
				return true;

			// Known header-only request packets (even if opcode < 128 for legacy compatibility)
			// Current opcodes: GET_HEIGHT=130, GET_BLOCK=129, PING=253 (all >= 128)
			// This check provides defensive compatibility if legacy implementations used < 128 values
			bool is_header_only_request = (m_header == GET_HEIGHT || 
			                                 m_header == GET_BLOCK || 
			                                 m_header == PING);

			// Header-only requests: no payload allowed
			if (is_header_only_request && m_length == 0)
				return true;

			// Data packets (< 128): must have payload
			if (m_header < 128 && m_length > 0)
				return true;

			// Falcon Authentication packets (207-212): carry payloads with length field
			if (is_auth_packet() && m_length > 0)
				return true;

			// Generic request packets (>= 128, < 255): no payload
			if (m_header >= 128 && m_header < 255 && m_length == 0)
				return true;

			return false;
		}

		network::Shared_payload get_bytes()
		{
			if (!is_valid())
			{
				return network::Shared_payload{};
			}

			network::Payload BYTES(1, m_header);

			/** Handle for Data Packets (header < 128) or Authentication Packets (207-212) **/
			// Both standard data packets and Falcon auth packets use the same wire format:
			// [header (1 byte)] [length (4 bytes, big-endian)] [payload data]
			if ((m_header < 128 || is_auth_packet()) && m_length > 0)
			{
				BYTES.push_back((m_length >> 24));
				BYTES.push_back((m_length >> 16));
				BYTES.push_back((m_length >> 8));
				BYTES.push_back(m_length);

				BYTES.insert(BYTES.end(), m_data->begin(), m_data->end());
			}

			return std::make_shared<network::Payload>(BYTES);
		}

		inline Packet get_packet(std::uint8_t header) const
		{
			Packet packet{ header, nullptr };
			return packet;
		}
	};

	inline Packet extract_packet_from_buffer(network::Shared_payload buffer, std::size_t& remaining_size, std::size_t start_index)
	{
		Packet packet;
		remaining_size = 0;		// buffer invalid
		if (!buffer)
		{
			return packet;
		}
		else if (buffer->empty())
		{
			return packet;
		}

		if (start_index >= buffer->size())	// invalid start_index given
		{
			return packet;
		}

		auto const buffer_start = buffer->begin() + start_index;
		auto const buffer_size = std::distance(buffer_start, buffer->end());
		if (buffer_size == 1)
		{
			packet.m_header = (*buffer)[start_index];
			packet.m_is_valid = true;
			remaining_size = 0;		// buffer has only 1 byte size left -> header
			return packet;
		}
		else if (buffer_size > 1 && buffer_size < 5)	// data paket but not even correct length field was transmitted
		{
			return packet;
		}
		else
		{
			std::uint32_t const length = ((*buffer)[start_index + 1] << 24) + ((*buffer)[start_index + 2] << 16) + ((*buffer)[start_index + 3] << 8) + ((*buffer)[start_index + 4]);

			if (length > std::distance(buffer_start + 5, buffer->end()))
			{
				return packet;
			}

			packet.m_is_valid = true;
			packet.m_header = (*buffer)[start_index];
			packet.m_length = length;
			packet.m_data = std::make_shared<network::Payload>(buffer_start + 5, buffer_start + 5 + length);

			remaining_size = buffer_size - (5 + packet.m_data->size());		// header (1 byte) + 4 byte length 
		}


		return packet;
	}

	/** Wrapper for backward compatibility - delegates to llp_logging.hpp **/
	inline const char* get_packet_header_name(std::uint8_t header)
	{
		return get_llp_header_name(header);
	}

	/** Wrapper for backward compatibility - delegates to llp_logging.hpp **/
	inline std::string format_payload_hex(network::Shared_payload const& payload, std::size_t max_bytes = 16)
	{
		return format_llp_payload_hex(payload, max_bytes);
	}

}

#endif
