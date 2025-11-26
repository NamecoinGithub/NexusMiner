#include "cpu/worker_hash.hpp"
#include "config/config.hpp"
#include "stats/stats_collector.hpp"
#include "block.hpp"
#include "hash/nexus_hash_utils.hpp"
#include <asio.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

namespace nexusminer
{
namespace cpu
{

Worker_hash::Worker_hash(std::shared_ptr<asio::io_context> io_context, Worker_config& config) 
: m_io_context{std::move(io_context)}
, m_logger{spdlog::get("logger")}
, m_config{config}
, m_stop{true}
, m_log_leader{"CPU Worker " + m_config.m_id + ": " }
, m_hash_count{0}
, m_best_leading_zeros{0}
, m_met_difficulty_count {0}
, m_pool_nbits{0}
, m_thread_id{}
, m_thread_start_time{}
, m_last_hash_count_snapshot{0}
, m_last_stats_time{}
{
	m_logger->info(m_log_leader + "Initialized (Internal ID: {})", m_config.m_internal_id);
}

Worker_hash::~Worker_hash() 
{ 
	//make sure the run thread exits the loop
	m_stop = true;  
	if (m_run_thread.joinable())
		m_run_thread.join(); 
}

void Worker_hash::set_block(LLP::CBlock block, std::uint32_t nbits, Worker::Block_found_handler result)
{
	//stop the existing mining loop if it is running
	m_stop = true;
	if (m_run_thread.joinable())
		m_run_thread.join();
	{
		std::scoped_lock<std::mutex> lck(m_mtx);
		m_found_nonce_callback = result;
		m_block = Block_data{ block };

		//set the starting nonce for each worker to something different that won't overlap with the others
		m_starting_nonce = static_cast<uint64_t>(m_config.m_internal_id) << 48;
		m_block.nNonce = m_starting_nonce;
		
		// Validate and set nBits with consistency checks
		if(nbits != 0)	// take nBits provided from pool
		{
			// Validate nbits consistency
			if (m_pool_nbits != 0 && m_pool_nbits != nbits)
			{
				m_logger->warn(m_log_leader + "m_pool_nbits changed from 0x{:08x} to 0x{:08x}", m_pool_nbits, nbits);
			}
			m_pool_nbits = nbits;
			m_logger->info(m_log_leader + "Set m_pool_nbits to 0x{:08x} (from pool)", m_pool_nbits);
		}
		else
		{
			// Use block's nBits when pool doesn't provide one
			if (m_pool_nbits != 0)
			{
				m_logger->info(m_log_leader + "Resetting m_pool_nbits (was 0x{:08x}, using block nBits 0x{:08x})", 
					m_pool_nbits, m_block.nBits);
			}
			m_pool_nbits = 0;
		}

		std::vector<unsigned char> headerB = m_block.GetHeaderBytes();
		
		// Validate header payload before processing
		if (headerB.empty())
		{
			m_logger->error(m_log_leader + "GetHeaderBytes() returned empty payload!");
			throw std::runtime_error("Empty header payload");
		}
		
		m_logger->debug(m_log_leader + "Header payload size: {} bytes (expected: 216 for hash, 208 for prime)", 
			headerB.size());
		
		//calculate midstate
		m_skein.setMessage(headerB);
		
		// Log midstate calculation for debugging
		log_midstate_calculation();
		
		// Reset statistics for new block
		reset_statistics();
	}
	//restart the mining loop
	m_stop = false;
	m_logger->info(m_log_leader + "Starting hashing loop (Starting nonce: 0x{:016x}, nBits: 0x{:08x})", 
		m_starting_nonce, m_pool_nbits != 0 ? m_pool_nbits : m_block.nBits);
	m_run_thread = std::thread(&Worker_hash::run, this);
}

void Worker_hash::run()
{
	// Log thread initialization diagnostics
	log_thread_initialization();
	
	m_logger->info(m_log_leader + "Hashing thread started");
	uint64_t last_log_hash_count = 0;
	constexpr uint64_t log_interval = 1000000;  // Log every 1M hashes
	constexpr int max_retries = 3;
	uint64_t payload_validation_failures = 0;
	uint64_t hash_mismatches = 0;
	
	// Periodic thread diagnostics interval (every 60 seconds)
	auto last_diagnostics_time = std::chrono::steady_clock::now();
	constexpr auto diagnostics_interval = std::chrono::seconds(60);
	
	while (!m_stop)
	{
		// Periodically log thread diagnostics
		auto current_time = std::chrono::steady_clock::now();
		if (current_time - last_diagnostics_time >= diagnostics_interval) {
			log_thread_diagnostics();
			last_diagnostics_time = current_time;
		}
		
		uint64_t nonce;
		bool hash_calculated = false;
		int retry_count = 0;
		
		// Retry mechanism for hash calculation
		while (!hash_calculated && retry_count < max_retries && !m_stop)
		{
			try
			{
				std::scoped_lock<std::mutex> lck(m_mtx);
				
				// Calculate the remainder of the skein hash starting from the midstate
				m_skein.calculateHash();
				
				// Validate Skein output before passing to Keccak
				NexusSkein::stateType skeinHash = m_skein.getHash();
				if (!validate_skein_output(skeinHash))
				{
					++payload_validation_failures;
					m_logger->warn(m_log_leader + "Skein payload validation failed for nonce 0x{:016x}", m_skein.getNonce());
					throw std::runtime_error("Invalid Skein output payload");
				}
				
				// Log Skein output for debugging (periodically)
				if (m_hash_count % (log_interval * 10) == 0)
				{
					log_skein_state(skeinHash, m_skein.getNonce());
				}
				
				// Run keccak on the result from skein
				NexusKeccak keccak(skeinHash);
				keccak.calculateHash();
				uint64_t keccakHash = keccak.getResult();
				
				// Validate Keccak output
				if (!validate_keccak_output(keccakHash))
				{
					++payload_validation_failures;
					m_logger->warn(m_log_leader + "Keccak payload validation failed for nonce 0x{:016x}", m_skein.getNonce());
					throw std::runtime_error("Invalid Keccak output payload");
				}
				
				// Cross-validate periodically (every 100000 hashes) to minimize performance impact
				// Also validate when we find a candidate nonce
				bool should_cross_validate = (m_hash_count % 100000 == 0) || ((keccakHash & leading_zero_mask()) == 0);
				
				if (should_cross_validate && !cross_validate_hashes(skeinHash, keccakHash))
				{
					++hash_mismatches;
					m_logger->error(m_log_leader + "Hash cross-validation failed for nonce 0x{:016x} - skipping nonce", m_skein.getNonce());
					// Log detailed mismatch info for debugging
					log_hash_mismatch(skeinHash, keccakHash, m_skein.getNonce());
					
					// Skip this nonce due to validation failure and move to next
					throw std::runtime_error("Hash cross-validation failed");
				}
				
				nonce = m_skein.getNonce();
				
				// Check the result for leading zeros
				if ((keccakHash & leading_zero_mask()) == 0)
				{
					m_logger->info(m_log_leader + "Found a nonce candidate {}", nonce);
					m_skein.setNonce(nonce);
					// Verify the difficulty
					if (difficulty_check())
					{
						++m_met_difficulty_count;
						// Update the block with the nonce and call the callback function
						m_block.nNonce = nonce;
						{
							if (m_found_nonce_callback)
							{
								::asio::post([self = shared_from_this()]()
								{
									self->m_found_nonce_callback(self->m_config.m_internal_id, std::make_unique<Block_data>(self->m_block));
								});
							}
							else
							{
								m_logger->debug(m_log_leader + "Miner callback function not set.");
							}
						}
					}
				}
				m_skein.setNonce(++nonce);	
				++m_hash_count;
				hash_calculated = true;
				
				// Log progress periodically with enhanced diagnostics
				if (m_hash_count - last_log_hash_count >= log_interval)
				{
					m_logger->debug(m_log_leader + "Hashing progress: {} hashes computed, current nonce: 0x{:016x}", 
						m_hash_count, nonce);
					if (payload_validation_failures > 0 || hash_mismatches > 0)
					{
						m_logger->info(m_log_leader + "Diagnostics: {} payload validation failures, {} hash mismatches", 
							payload_validation_failures, hash_mismatches);
					}
					last_log_hash_count = m_hash_count;
				}
			}
			catch (const std::exception& e)
			{
				++retry_count;
				if (retry_count < max_retries)
				{
					m_logger->warn(m_log_leader + "Hash calculation failed (attempt {}/{}): {}. Retrying...", 
						retry_count, max_retries, e.what());
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				else
				{
					m_logger->error(m_log_leader + "Hash calculation failed after {} retries: {}. Skipping nonce.", 
						max_retries, e.what());
					// Skip this nonce and continue
					std::scoped_lock<std::mutex> lck(m_mtx);
					nonce = m_skein.getNonce();
					m_skein.setNonce(++nonce);
				}
			}
		}
	}
	m_logger->info(m_log_leader + "Hashing thread stopped. Total hashes: {}, Payload failures: {}, Hash mismatches: {}", 
		m_hash_count, payload_validation_failures, hash_mismatches);
}

void Worker_hash::update_statistics(stats::Collector& stats_collector)
{
	std::scoped_lock<std::mutex> lck(m_mtx);

	auto hash_stats = std::get<stats::Hash>(stats_collector.get_worker_stats(m_config.m_internal_id));
	hash_stats.m_hash_count = m_hash_count;
	hash_stats.m_best_leading_zeros = m_best_leading_zeros;
	hash_stats.m_met_difficulty_count = m_met_difficulty_count;

	stats_collector.update_worker_stats(m_config.m_internal_id, hash_stats);

}


bool Worker_hash::difficulty_check()
{
	//perform additional difficulty filtering prior to submitting the nonce 
	
	// Validate m_pool_nbits consistency
	uint32_t nbits_to_use = m_pool_nbits != 0 ? m_pool_nbits : m_block.nBits;
	
	if (m_pool_nbits != 0 && m_block.nBits != 0 && m_pool_nbits != m_block.nBits)
	{
		m_logger->debug(m_log_leader + "Using pool nBits 0x{:08x} (block nBits: 0x{:08x})", 
			m_pool_nbits, m_block.nBits);
	}

	//leading zeros in bits required of the hash for it to pass the current difficulty.
	int leadingZerosRequired;
	uint64_t difficultyTest64;
	decodeBits(nbits_to_use, leadingZerosRequired, difficultyTest64);
	
	// Recalculate and validate hash outputs
	m_skein.calculateHash();
	NexusSkein::stateType skeinHash = m_skein.getHash();
	
	// Validate Skein output in difficulty check
	if (!validate_skein_output(skeinHash))
	{
		m_logger->error(m_log_leader + "Skein validation failed in difficulty_check");
		return false;
	}
	
	//run keccak on the result from skein
	NexusKeccak keccak(skeinHash);
	keccak.calculateHash();
	uint64_t keccakHash = keccak.getResult();
	
	// Validate Keccak output in difficulty check
	if (!validate_keccak_output(keccakHash))
	{
		m_logger->error(m_log_leader + "Keccak validation failed in difficulty_check");
		return false;
	}
	
	int hashActualLeadingZeros = 63 - findMSB(keccakHash);
	m_logger->info(m_log_leader + "Difficulty check: Leading Zeros Found/Required {}/{}, nBits: 0x{:08x}", 
		hashActualLeadingZeros, leadingZerosRequired, nbits_to_use);
	
	if (hashActualLeadingZeros > m_best_leading_zeros)
	{
		m_best_leading_zeros = hashActualLeadingZeros;
		m_logger->info(m_log_leader + "New best leading zeros: {}", m_best_leading_zeros);
	}
	
	//check the hash result is less than the difficulty.  We truncate to just use the upper 64 bits for easier calculation.
	if (keccakHash <= difficultyTest64)
	{
		m_logger->info(m_log_leader + "Nonce passes difficulty check (hash: 0x{:016x} <= difficulty: 0x{:016x})", 
			keccakHash, difficultyTest64);
		
		// Log detailed payload information for successful nonce
		log_skein_state(skeinHash, m_skein.getNonce());
		
		return true;
	}
	else
	{
		m_logger->debug(m_log_leader + "Nonce fails difficulty check (hash: 0x{:016x} > difficulty: 0x{:016x})", 
			keccakHash, difficultyTest64);
		return false;
	}
}

uint64_t Worker_hash::leading_zero_mask()
{
	return ((1ull << leading_zeros_required) - 1) << (64 - leading_zeros_required);
}

void Worker_hash::reset_statistics()
{
	m_hash_count = 0;
	m_best_leading_zeros = 0;
	m_met_difficulty_count = 0;
}

bool Worker_hash::validate_skein_output(const NexusSkein::stateType& skeinHash) const
{
	// Validate that Skein output is not all zeros (invalid state)
	bool all_zeros = true;
	bool all_same = true;
	uint64_t first_val = skeinHash[0];
	
	for (size_t i = 0; i < skeinHash.size(); ++i)
	{
		if (skeinHash[i] != 0)
		{
			all_zeros = false;
		}
		if (i > 0 && skeinHash[i] != first_val)
		{
			all_same = false;
		}
	}
	
	if (all_zeros)
	{
		m_logger->error(m_log_leader + "Skein output is all zeros (invalid state)");
		return false;
	}
	
	// Additional validation: check for obviously invalid patterns
	// (all same value, which would indicate a calculation error)
	if (all_same && first_val != 0)
	{
		m_logger->warn(m_log_leader + "Skein output has suspicious pattern (all values = 0x{:016x})", first_val);
		// Don't reject, but log for debugging
	}
	
	return true;
}

bool Worker_hash::validate_keccak_output(uint64_t keccakHash) const
{
	// Keccak output validation
	// All 64-bit values are theoretically valid for Keccak hash results
	// We primarily rely on cross-validation for comprehensive checking
	return true;
}

bool Worker_hash::cross_validate_hashes(const NexusSkein::stateType& skeinHash, uint64_t keccakHash) const
{
	// Cross-validation: Verify that the Keccak hash was derived from the Skein hash
	// Note: This performs an additional Keccak calculation which has a performance cost
	// This is only done periodically based on hash_count to minimize overhead
	
	// Skip cross-validation for most hashes to maintain performance
	// Only validate every 100000th hash or when we find a candidate
	// The caller should control when to invoke this expensive check
	
	// Recalculate Keccak to verify
	NexusKeccak keccak_verify(skeinHash);
	keccak_verify.calculateHash();
	uint64_t keccak_verify_result = keccak_verify.getResult();
	
	if (keccak_verify_result != keccakHash)
	{
		m_logger->error(m_log_leader + "Cross-validation failed: Keccak hash mismatch (expected: 0x{:016x}, got: 0x{:016x})",
			keccak_verify_result, keccakHash);
		return false;
	}
	
	return true;
}

void Worker_hash::log_skein_state(const NexusSkein::stateType& skeinHash, uint64_t nonce) const
{
	static constexpr size_t SKEIN_LOG_WORDS = 4;  // Number of words to log from Skein output
	
	m_logger->debug(m_log_leader + "Skein output for nonce 0x{:016x}:", nonce);
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (size_t i = 0; i < std::min(SKEIN_LOG_WORDS, skeinHash.size()); ++i)
	{
		ss << "0x" << std::setw(16) << skeinHash[i] << " ";
	}
	m_logger->debug(m_log_leader + "  First {} words: {}", SKEIN_LOG_WORDS, ss.str());
}

void Worker_hash::log_hash_mismatch(const NexusSkein::stateType& skeinHash, uint64_t keccakHash, uint64_t nonce) const
{
	static constexpr size_t SKEIN_LOG_WORDS = 4;  // Number of words to log from Skein output
	
	m_logger->error(m_log_leader + "Hash mismatch detected for nonce 0x{:016x}", nonce);
	
	// Log Skein output
	std::stringstream ss_skein;
	ss_skein << std::hex << std::setfill('0');
	for (size_t i = 0; i < std::min(SKEIN_LOG_WORDS, skeinHash.size()); ++i)
	{
		ss_skein << "0x" << std::setw(16) << skeinHash[i] << " ";
	}
	m_logger->error(m_log_leader + "  Skein output (first {} words): {}", SKEIN_LOG_WORDS, ss_skein.str());
	
	// Log Keccak result
	m_logger->error(m_log_leader + "  Keccak result: 0x{:016x}", keccakHash);
	
	// Log current m_pool_nbits for context
	m_logger->error(m_log_leader + "  Current m_pool_nbits: 0x{:08x}", m_pool_nbits);
}

void Worker_hash::log_midstate_calculation()
{
	static constexpr size_t SKEIN_LOG_WORDS = 4;  // Number of words to log from midstate
	
	// Log midstate information for debugging
	auto key2 = m_skein.getKey2();
	auto msg2 = m_skein.getMessage2();
	
	m_logger->debug(m_log_leader + "Midstate calculated:");
	
	// Log first few words of key2
	std::stringstream ss_key;
	ss_key << std::hex << std::setfill('0');
	for (size_t i = 0; i < std::min(SKEIN_LOG_WORDS, key2.size()); ++i)
	{
		ss_key << "0x" << std::setw(16) << key2[i] << " ";
	}
	m_logger->debug(m_log_leader + "  Key2 (first {} words): {}", SKEIN_LOG_WORDS, ss_key.str());
	
	// Log first few words of message2
	std::stringstream ss_msg;
	ss_msg << std::hex << std::setfill('0');
	for (size_t i = 0; i < std::min(SKEIN_LOG_WORDS, msg2.size()); ++i)
	{
		ss_msg << "0x" << std::setw(16) << msg2[i] << " ";
	}
	m_logger->debug(m_log_leader + "  Message2 (first {} words): {}", SKEIN_LOG_WORDS, ss_msg.str());
}

void Worker_hash::log_thread_initialization()
{
	m_thread_id = std::this_thread::get_id();
	m_thread_start_time = std::chrono::steady_clock::now();
	m_last_stats_time = m_thread_start_time;
	m_last_hash_count_snapshot = 0;
	
	// Convert thread ID to string for logging
	std::ostringstream ss;
	ss << m_thread_id;
	
	m_logger->info(m_log_leader + "Thread initialization diagnostics:");
	m_logger->info(m_log_leader + "  Thread ID: {}", ss.str());
	m_logger->info(m_log_leader + "  Worker Internal ID: {}", m_config.m_internal_id);
	m_logger->info(m_log_leader + "  Starting nonce: 0x{:016x}", m_starting_nonce);
	
#ifdef __linux__
	// Log CPU affinity on Linux
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	int result = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
	if (result == 0) {
		std::vector<int> cpu_cores;
		for (int j = 0; j < CPU_SETSIZE; j++) {
			if (CPU_ISSET(j, &cpuset)) {
				cpu_cores.push_back(j);
			}
		}
		if (!cpu_cores.empty()) {
			std::stringstream affinity_ss;
			for (size_t i = 0; i < cpu_cores.size(); ++i) {
				if (i > 0) affinity_ss << ", ";
				affinity_ss << cpu_cores[i];
			}
			m_logger->info(m_log_leader + "  CPU affinity: cores [{}]", affinity_ss.str());
		} else {
			m_logger->info(m_log_leader + "  CPU affinity: unrestricted (can run on any core)");
		}
	} else {
		m_logger->warn(m_log_leader + "  CPU affinity: unable to query (error {})", result);
	}
#else
	m_logger->info(m_log_leader + "  CPU affinity: not available on this platform");
#endif
}

void Worker_hash::log_thread_diagnostics()
{
	auto current_time = std::chrono::steady_clock::now();
	auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - m_thread_start_time).count();
	auto interval_time = std::chrono::duration_cast<std::chrono::seconds>(current_time - m_last_stats_time).count();
	
	if (interval_time > 0) {
		uint64_t interval_hashes = m_hash_count - m_last_hash_count_snapshot;
		double interval_hashrate = static_cast<double>(interval_hashes) / interval_time;
		double average_hashrate = elapsed_time > 0 ? static_cast<double>(m_hash_count) / elapsed_time : 0.0;
		
		// Convert thread ID to string for logging
		std::ostringstream ss;
		ss << m_thread_id;
		
		m_logger->info(m_log_leader + "Thread diagnostics:");
		m_logger->info(m_log_leader + "  Thread ID: {}", ss.str());
		m_logger->info(m_log_leader + "  Running time: {} seconds", elapsed_time);
		m_logger->info(m_log_leader + "  Total hashes: {}", m_hash_count);
		m_logger->info(m_log_leader + "  Interval hashrate: {:.2f} H/s", interval_hashrate);
		m_logger->info(m_log_leader + "  Average hashrate: {:.2f} H/s", average_hashrate);
		m_logger->info(m_log_leader + "  Current nonce: 0x{:016x}", m_skein.getNonce());
		
		// Update snapshots for next interval
		m_last_stats_time = current_time;
		m_last_hash_count_snapshot = m_hash_count;
	}
}

}
}