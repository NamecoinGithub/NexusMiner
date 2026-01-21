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
	// Packet protocol constants
	namespace PacketConstants {
		// Invalid header marker for error conditions
		static constexpr uint16_t INVALID_HEADER = 0xFFFF;
		
		// Minimum legacy auth/session opcode (CHANNEL_ACK = 206)
		// Opcodes 206-255 are always legacy single-byte format, never stateless
		static constexpr uint8_t LEGACY_AUTH_OPCODE_MIN = 206;
		
		// Threshold for detecting POTENTIAL stateless mining protocol (uint16_t opcodes)
		// First byte >= 0xD0 MAY indicate uint16_t opcode, but we must verify by checking
		// context. Legacy opcodes 208-255 also start with 0xD0-0xFF.
		static constexpr uint8_t STATELESS_OPCODE_THRESHOLD = 0xD0;
		
		// Mirror-mapped stateless opcode range (uint16_t values)
		// Stateless opcodes are 0xD000-0xD0FF (mirror-mapped from legacy 0x00-0xFF)
		static constexpr uint16_t STATELESS_OPCODE_MIN = 0xD000;
		static constexpr uint16_t STATELESS_OPCODE_MAX = 0xD0FF;
		
		// Helper function to check if a uint16_t opcode is a stateless mining opcode
		// Returns true if opcode is in range [0xD000, 0xD0FF] (mirror-mapped range)
		inline bool is_stateless_opcode(uint16_t opcode) {
			return LLP::IsStatelessOpcode(opcode);
		}
		
		// Helper function to check if a single byte is a legacy auth/session opcode
		// These are always single-byte format (206-255), never part of uint16_t stateless opcodes
		inline bool is_legacy_auth_opcode(uint8_t opcode) {
			return (opcode >= LEGACY_AUTH_OPCODE_MIN);
		}
	}
	
	/** Class to handle sending and receiving of LLP Packets. **/
	class Packet
	{
	public:

		// Packet headers - use centralized definitions from miner_opcodes.hpp
		// These values MUST match the node implementation exactly for protocol compatibility
		// Underlying type is uint16_t to support stateless mining opcodes (0xD000+)
		enum : uint16_t
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

			/** STATELESS MINING REWARD BINDING (Phase 2 - Encrypted) **/
			MINER_SET_REWARD = LLP::MINER_SET_REWARD,
			MINER_REWARD_RESULT = LLP::MINER_REWARD_RESULT,

			/** PUSH NOTIFICATIONS (LLL-TAO PR #156) **/
			MINER_READY = LLP::MINER_READY,
			PRIME_BLOCK_AVAILABLE = LLP::PRIME_BLOCK_AVAILABLE,
			HASH_BLOCK_AVAILABLE = LLP::HASH_BLOCK_AVAILABLE,

			// LEGACY - kept for pool compatibility
			BLOCK = LLP::BLOCK,
			STALE = LLP::STALE,
			
			/** NEW STATELESS MINING PROTOCOL (uint16_t opcodes, mirror-mapped 0xD0xx) **/
			/** These require Packet(uint16_t) constructor **/
			
			// Core mining operations (mirror-mapped from legacy)
			STATELESS_SUBMIT_BLOCK = LLP::StatelessMining::SUBMIT_BLOCK,              // 0xD001
			STATELESS_SET_CHANNEL = LLP::StatelessMining::SET_CHANNEL,                // 0xD003
			STATELESS_GET_BLOCK = LLP::StatelessMining::GET_BLOCK,                    // 0xD081
			STATELESS_BLOCK_ACCEPTED = LLP::StatelessMining::BLOCK_ACCEPTED,          // 0xD0C8
			STATELESS_BLOCK_REJECTED = LLP::StatelessMining::BLOCK_REJECTED,          // 0xD0C9
			STATELESS_MINER_SET_REWARD = LLP::StatelessMining::MINER_SET_REWARD,      // 0xD0D5
			STATELESS_MINER_REWARD_RESULT = LLP::StatelessMining::MINER_REWARD_RESULT,// 0xD0D6
			STATELESS_MINER_READY = LLP::StatelessMining::MINER_READY,                // 0xD0D8
			STATELESS_PRIME_BLOCK_AVAILABLE = LLP::StatelessMining::PRIME_BLOCK_AVAILABLE,  // 0xD0D9
			STATELESS_HASH_BLOCK_AVAILABLE = LLP::StatelessMining::HASH_BLOCK_AVAILABLE,    // 0xD0DA

			/** GENERIC **/
			PING = LLP::PING,
			CLOSE = LLP::CLOSE
		};

		Packet()
			: m_header{ PacketConstants::INVALID_HEADER }
			, m_length{ 0 }
			, m_is_valid{ false }
			, m_is_uint16_opcode{ false }
		{
		}

		Packet(std::uint8_t header, network::Payload const& data)
			: m_header{ header }
			, m_is_valid{ true }
			, m_is_uint16_opcode{ false }
		{
			m_data = std::make_shared<network::Payload>(data);
			m_length = m_data->size();
		}
		
		Packet(std::uint16_t header, network::Payload const& data)
			: m_header{ header }
			, m_is_valid{ true }
			, m_is_uint16_opcode{ PacketConstants::is_stateless_opcode(header) }
		{
			m_data = std::make_shared<network::Payload>(data);
			m_length = m_data->size();
		}

		Packet(std::uint8_t header, network::Shared_payload data)
			: m_header{ header }
			, m_length{ 0 }
			, m_is_valid{ true }
			, m_is_uint16_opcode{ false }
		{
			if (data)
			{
				m_data = std::move(data);
				m_length = m_data->size();
			}
		}
		
		Packet(std::uint16_t header, network::Shared_payload data)
			: m_header{ header }
			, m_length{ 0 }
			, m_is_valid{ true }
			, m_is_uint16_opcode{ PacketConstants::is_stateless_opcode(header) }
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
			, m_is_uint16_opcode{ false }
		{
		}
		
		explicit Packet(std::uint16_t header)
			: m_header{ header }
			, m_length{ 0 }
			, m_is_valid{ true }
			, m_is_uint16_opcode{ PacketConstants::is_stateless_opcode(header) }
		{
		}

		// creates a packet from received buffer
		explicit Packet(network::Shared_payload buffer)
		{
			m_is_valid = true;
			m_is_uint16_opcode = false;
			
			if (buffer->empty())
			{
				m_header = PacketConstants::INVALID_HEADER;
				m_is_valid = false;
				m_length = 0;
				return;
			}
			
			// Detect opcode format with disambiguation logic:
			// 1. Legacy auth/session opcodes (206-255) are ALWAYS single-byte format
			// 2. Stateless opcodes (0xD000-0xD00C) are ALWAYS two-byte format
			// 3. For ambiguous cases (first_byte >= 0xD0), check if it's a known legacy opcode
			uint8_t first_byte = (*buffer)[0];
			
			// PRIORITY 1: Known legacy auth/session opcodes (206-255) - always single-byte
			if (PacketConstants::is_legacy_auth_opcode(first_byte))
			{
				// LEGACY uint8_t opcode format (1-byte header)
				// This includes MINER_AUTH_CHALLENGE (208) and all auth/session opcodes
				m_is_uint16_opcode = false;
				m_header = first_byte;
				m_length = 0;
				
				if (buffer->size() > 1 && buffer->size() < 5)
				{
					m_is_valid = false;
				}
				else if (buffer->size() >= 5)
				{
					// Parse length (4 bytes, big-endian, starts at offset 1)
					m_length = ((*buffer)[1] << 24) + ((*buffer)[2] << 16) + 
					           ((*buffer)[3] << 8) + ((*buffer)[4]);
					
					// Extract data (starts at offset 5)
					if (buffer->size() >= 5 + m_length)
					{
						m_data = std::make_shared<network::Payload>(buffer->begin() + 5, 
						                                             buffer->begin() + 5 + m_length);
					}
					else
					{
						m_is_valid = false;
						m_length = 0;
					}
				}
			}
			// PRIORITY 2: Check for stateless opcodes (requires 2 bytes)
			else if (first_byte >= PacketConstants::STATELESS_OPCODE_THRESHOLD && buffer->size() >= 2)
			{
				// Parse potential 2-byte header to check if it's a known stateless opcode
				uint16_t potential_header = (static_cast<uint16_t>(first_byte) << 8) | 
				                            static_cast<uint16_t>((*buffer)[1]);
				
				if (PacketConstants::is_stateless_opcode(potential_header))
				{
					// NEW uint16_t opcode format (2-byte header, big-endian, 0xD000-0xD00C)
					m_is_uint16_opcode = true;
					m_header = potential_header;
					
					// Check if we have length field (need at least 6 bytes total: header(2) + length(4))
					if (buffer->size() < 6)
					{
						m_is_valid = false;
						m_length = 0;
						return;
					}
					
					// Parse length (4 bytes, big-endian, starts at offset 2)
					m_length = ((*buffer)[2] << 24) + ((*buffer)[3] << 16) + 
					           ((*buffer)[4] << 8) + (*buffer)[5];
					
					// Extract data (starts at offset 6)
					if (buffer->size() >= 6 + m_length)
					{
						m_data = std::make_shared<network::Payload>(buffer->begin() + 6, 
						                                             buffer->begin() + 6 + m_length);
					}
					else
					{
						m_is_valid = false;
						m_length = 0;
					}
				}
				else
				{
					// First byte >= 0xD0 but not a known stateless opcode
					// Treat as legacy single-byte opcode
					m_is_uint16_opcode = false;
					m_header = first_byte;
					m_length = 0;
					
					if (buffer->size() > 1 && buffer->size() < 5)
					{
						m_is_valid = false;
					}
					else if (buffer->size() >= 5)
					{
						// Parse length (4 bytes, big-endian, starts at offset 1)
						m_length = ((*buffer)[1] << 24) + ((*buffer)[2] << 16) + 
						           ((*buffer)[3] << 8) + ((*buffer)[4]);
						
						// Extract data (starts at offset 5)
						if (buffer->size() >= 5 + m_length)
						{
							m_data = std::make_shared<network::Payload>(buffer->begin() + 5, 
							                                             buffer->begin() + 5 + m_length);
						}
						else
						{
							m_is_valid = false;
							m_length = 0;
						}
					}
				}
			}
			else
			{
				// LEGACY uint8_t opcode format (1-byte header)
				// Standard opcodes < 0xD0
				m_is_uint16_opcode = false;
				m_header = first_byte;
				m_length = 0;
				
				if (buffer->size() > 1 && buffer->size() < 5)
				{
					m_is_valid = false;
				}
				else if (buffer->size() >= 5)
				{
					// Parse length (4 bytes, big-endian, starts at offset 1)
					m_length = ((*buffer)[1] << 24) + ((*buffer)[2] << 16) + 
					           ((*buffer)[3] << 8) + ((*buffer)[4]);
					
					// Extract data (starts at offset 5)
					if (buffer->size() >= 5 + m_length)
					{
						m_data = std::make_shared<network::Payload>(buffer->begin() + 5, 
						                                             buffer->begin() + 5 + m_length);
					}
					else
					{
						m_is_valid = false;
						m_length = 0;
					}
				}
			}
		}

		/** Components of an LLP Packet.
			LEGACY FORMAT (uint8_t opcodes, < 0xD0):
				BYTE 0       : Header (1 byte)
				BYTE 1 - 4   : Length (4 bytes, big-endian)
				BYTE 5 - End : Data
			
			NEW FORMAT (uint16_t opcodes, >= 0xD000):
				BYTE 0 - 1   : Header (2 bytes, big-endian)
				BYTE 2 - 5   : Length (4 bytes, big-endian)
				BYTE 6 - End : Data
		**/
		std::uint16_t		m_header;  // Changed from uint8_t to support 0xD000+ opcodes
		std::uint32_t		m_length;
		network::Shared_payload m_data;
		bool m_is_valid;
		bool m_is_uint16_opcode;  // True if this packet uses uint16_t opcode (>= 0xD000)

		/**
		 * @brief Check if packet header is part of stateless mining protocol (206-214)
		 * 
		 * These packets carry payloads despite having headers >= 128:
		 * - CHANNEL_ACK (206): 1-byte channel confirmation payload
		 * - MINER_AUTH_INIT (207): pubkey data
		 * - MINER_AUTH_CHALLENGE (208): nonce data
		 * - MINER_AUTH_RESPONSE (209): signature data
		 * - MINER_AUTH_RESULT (210): status + optional session_id
		 * - SESSION_START (211), SESSION_KEEPALIVE (212): session data
		 * - MINER_SET_REWARD (213), MINER_REWARD_RESULT (214): encrypted reward data
		 * 
		 * NOTE: This function assumes CHANNEL_ACK (206) through MINER_REWARD_RESULT (214)
		 * form a contiguous range. If new packet types are added in this range, they must
		 * also follow the same payload convention. See src/LLP/miner_opcodes.hpp for the
		 * authoritative packet type definitions.
		 */
		inline bool is_auth_packet() const
		{
			// Stateless mining protocol packets (206-214) all carry payloads despite header >= 128
			// IMPORTANT: This range must remain contiguous - see miner_opcodes.hpp
			return (m_header >= CHANNEL_ACK && m_header <= MINER_REWARD_RESULT);
		}

		/**
		 * @brief Get detailed validation failure reason for diagnostics
		 * 
		 * This method provides visibility into why a packet failed validation,
		 * which is critical for debugging Falcon AUTH INT response failures.
		 * 
		 * @return Human-readable string describing the validation state
		 */
		inline std::string get_validation_state() const
		{
			if (!m_is_valid)
			{
				return "INVALID: m_is_valid flag is false (construction or parsing failure)";
			}
			
			// Special case: LOGIN message (legacy compatibility)
			if (m_header == 0 && m_length == 0)
				return "VALID: LOGIN message (legacy compatibility)";
			
			// Known header-only request packets
			bool is_header_only_request = (m_header == GET_HEIGHT || 
			                               m_header == GET_BLOCK || 
			                               m_header == PING);
			
			if (is_header_only_request && m_length == 0)
				return "VALID: Header-only request packet (GET_HEIGHT/GET_BLOCK/PING)";
			
			if (is_header_only_request && m_length > 0)
				return "INVALID: Header-only request packet has unexpected payload";
			
			// Data packets (< 128): must have payload
			if (m_header < 128 && m_length > 0)
				return "VALID: Data packet with payload";
			
			if (m_header < 128 && m_length == 0)
				return "INVALID: Data packet (header < 128) requires payload but length is 0";
			
			// Stateless mining protocol packets (206-214): carry payloads with length field
			if (is_auth_packet() && m_length > 0)
				return "VALID: Stateless mining protocol packet with payload";
			
			if (is_auth_packet() && m_length == 0)
				return "INVALID: Stateless mining protocol packet (206-214) requires payload but length is 0";
			
			// Generic request packets (>= 128, < 255): no payload
			if (m_header >= 128 && m_header < 255 && m_length == 0)
				return "VALID: Generic request packet (no payload)";
			
			if (m_header >= 128 && m_header < 255 && m_length > 0 && !is_auth_packet())
				return "INVALID: Generic request packet (>=128, not auth) should not have payload";
			
			return "INVALID: Unknown packet structure";
		}

		inline bool is_valid() const
		{
			if (!m_is_valid)
			{
				return false;
			}
			
			// NEW uint16_t opcode protocol (0xD000+)
			if (m_is_uint16_opcode)
			{
				// All uint16_t opcodes in 0xD000+ range are valid if parsing succeeded
				// Validation is done during parsing
				return true;
			}

			// LEGACY uint8_t opcodes below...
			
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

			// Stateless mining protocol packets (206-214): carry payloads with length field
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

			network::Payload BYTES;
			
			if (m_is_uint16_opcode)
			{
				// NEW uint16_t opcode format: [header(2)][length(4)][data]
				// Header (2 bytes, big-endian)
				BYTES.push_back((m_header >> 8) & 0xFF);
				BYTES.push_back(m_header & 0xFF);
				
				// Length (4 bytes, big-endian) - if payload exists
				if (m_length > 0 && m_data)
				{
					BYTES.push_back((m_length >> 24) & 0xFF);
					BYTES.push_back((m_length >> 16) & 0xFF);
					BYTES.push_back((m_length >> 8) & 0xFF);
					BYTES.push_back(m_length & 0xFF);
					
					// Data
					BYTES.insert(BYTES.end(), m_data->begin(), m_data->end());
				}
				else if (m_length > 0)
				{
					// Payload expected but missing - invalid
					return network::Shared_payload{};
				}
				// else: header-only packet, no length/data needed
			}
			else
			{
				// LEGACY uint8_t opcode format: [header(1)][length(4)][data]
				// Header (1 byte)
				BYTES.push_back(static_cast<uint8_t>(m_header));

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
		
		// Detect opcode format with disambiguation logic (same as Packet constructor):
		// 1. Legacy auth/session opcodes (206-255) are ALWAYS single-byte format
		// 2. Stateless opcodes (0xD000-0xD00C) are ALWAYS two-byte format  
		// 3. For ambiguous cases, prioritize known legacy opcodes
		uint8_t first_byte = (*buffer)[start_index];
		
		// PRIORITY 1: Known legacy auth/session opcodes (206-255) - always single-byte
		if (PacketConstants::is_legacy_auth_opcode(first_byte))
		{
			// LEGACY uint8_t opcode format (includes MINER_AUTH_CHALLENGE = 208)
			packet.m_is_uint16_opcode = false;
			packet.m_header = first_byte;
			
			if (buffer_size == 1)
			{
				packet.m_is_valid = true;
				packet.m_length = 0;
				remaining_size = 0;
				return packet;
			}
			else if (buffer_size > 1 && buffer_size < 5)
			{
				// data packet but not even correct length field was transmitted
				return packet;
			}
			else
			{
				std::uint32_t const length = ((*buffer)[start_index + 1] << 24) + 
				                              ((*buffer)[start_index + 2] << 16) + 
				                              ((*buffer)[start_index + 3] << 8) + 
				                              ((*buffer)[start_index + 4]);

				if (length > std::distance(buffer_start + 5, buffer->end()))
				{
					return packet;
				}

				packet.m_is_valid = true;
				packet.m_length = length;
				packet.m_data = std::make_shared<network::Payload>(buffer_start + 5, buffer_start + 5 + length);
				remaining_size = buffer_size - (5 + packet.m_data->size());		// header (1 byte) + 4 byte length 
			}
		}
		// PRIORITY 2: Check for stateless opcodes (requires 2 bytes)
		else if (first_byte >= PacketConstants::STATELESS_OPCODE_THRESHOLD && buffer_size >= 2)
		{
			// Parse potential 2-byte header to check if it's a known stateless opcode
			uint16_t potential_header = (static_cast<uint16_t>(first_byte) << 8) | 
			                            static_cast<uint16_t>((*buffer)[start_index + 1]);
			
			if (PacketConstants::is_stateless_opcode(potential_header))
			{
				// NEW uint16_t opcode format (2-byte header, big-endian, 0xD000-0xD00C)
				packet.m_is_uint16_opcode = true;
				packet.m_header = potential_header;
				packet.m_is_valid = true;
				
				if (buffer_size == 2)
				{
					// Header-only packet
					packet.m_length = 0;
					remaining_size = 0;
					return packet;
				}
				else if (buffer_size < 6)
				{
					// Not enough data for length field
					packet.m_is_valid = false;
					return packet;
				}
				else
				{
					// Parse length (4 bytes, big-endian, starts at offset 2)
					std::uint32_t const length = ((*buffer)[start_index + 2] << 24) + 
					                              ((*buffer)[start_index + 3] << 16) + 
					                              ((*buffer)[start_index + 4] << 8) + 
					                              (*buffer)[start_index + 5];
					
					if (length > std::distance(buffer_start + 6, buffer->end()))
					{
						// Not enough data for payload
						packet.m_is_valid = false;
						return packet;
					}
					
					packet.m_length = length;
					packet.m_data = std::make_shared<network::Payload>(buffer_start + 6, buffer_start + 6 + length);
					remaining_size = buffer_size - (6 + packet.m_data->size());		// header (2 bytes) + 4 byte length
				}
			}
			else
			{
				// First byte >= 0xD0 but not a known stateless opcode
				// Treat as legacy single-byte opcode
				packet.m_is_uint16_opcode = false;
				packet.m_header = first_byte;
				
				if (buffer_size == 1)
				{
					packet.m_is_valid = true;
					packet.m_length = 0;
					remaining_size = 0;
					return packet;
				}
				else if (buffer_size > 1 && buffer_size < 5)
				{
					// data packet but not even correct length field was transmitted
					return packet;
				}
				else
				{
					std::uint32_t const length = ((*buffer)[start_index + 1] << 24) + 
					                              ((*buffer)[start_index + 2] << 16) + 
					                              ((*buffer)[start_index + 3] << 8) + 
					                              ((*buffer)[start_index + 4]);

					if (length > std::distance(buffer_start + 5, buffer->end()))
					{
						return packet;
					}

					packet.m_is_valid = true;
					packet.m_length = length;
					packet.m_data = std::make_shared<network::Payload>(buffer_start + 5, buffer_start + 5 + length);
					remaining_size = buffer_size - (5 + packet.m_data->size());		// header (1 byte) + 4 byte length 
				}
			}
		}
		else
		{
			// LEGACY uint8_t opcode format (1-byte header)
			// Includes: first_byte < 0xD0 OR buffer has only 1 byte
			packet.m_is_uint16_opcode = false;
			
			if (buffer_size == 1)
			{
				packet.m_header = first_byte;
				packet.m_is_valid = true;
				remaining_size = 0;		// buffer has only 1 byte size left -> header
				return packet;
			}
			else if (buffer_size > 1 && buffer_size < 5)	// data packet but not even correct length field was transmitted
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
				packet.m_header = first_byte;
				packet.m_length = length;
				packet.m_data = std::make_shared<network::Payload>(buffer_start + 5, buffer_start + 5 + length);

				remaining_size = buffer_size - (5 + packet.m_data->size());		// header (1 byte) + 4 byte length 
			}
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
