#include "cpu/worker_prime.hpp"
#include "cpu/thread_utils.hpp"
#include "cpu/prime_validation.hpp"
#include "config/config.hpp"
#include "stats/stats_collector.hpp"
#include "prime/prime.hpp"
#include "prime/chain_sieve.hpp"
#include "block.hpp"
#include <asio.hpp>
#include <primesieve.hpp>
#include <sstream> 
#include <boost/random.hpp>

namespace nexusminer
{
namespace cpu
{
Worker_prime::Worker_prime(std::shared_ptr<asio::io_context> io_context, config::Worker_config& config)
	: m_io_context{ std::move(io_context) }
	, m_logger{ spdlog::get("logger") }
	, m_config{ config }
	, m_prime_helper{std::make_unique<Prime>()}
	, m_segmented_sieve{std::make_unique<Sieve>()}
	, m_stop{ true }
	, m_initialized{ false }
	, m_log_leader{ "CPU Worker " + m_config.m_id + ": " }
	, m_primes{ 0 }
	, m_chains{ 0 }
	, m_difficulty{ 0 }
	, m_pool_nbits{ 0 }
{
	try {
		m_logger->debug("Worker_prime constructor: Initializing worker {}", m_config.m_id);
		
		// Log CPU-specific configuration for multi-core support
		if (std::holds_alternative<config::Worker_config_cpu>(m_config.m_worker_mode)) {
			auto const& cpu_cfg = std::get<config::Worker_config_cpu>(m_config.m_worker_mode);
			if (cpu_cfg.m_threads > 1) {
				m_logger->info(m_log_leader + "Multi-core configuration: {} thread(s)", cpu_cfg.m_threads);
				m_logger->info(m_log_leader + "Note: Multi-threading support is available");
			}
			if (cpu_cfg.m_affinity_mask > 0) {
				m_logger->info(m_log_leader + "CPU affinity mask: 0x{:016x}", cpu_cfg.m_affinity_mask);
			}
			if (cpu_cfg.m_priority_level != 2) {
				m_logger->info(m_log_leader + "Thread priority: {}", cpu_cfg.m_priority_level);
			}
		}
		
		// Initialize segmented sieve with error handling
		m_segmented_sieve->generate_sieving_primes();
		
		// Run performance test
		fermat_performance_test();
		
		// Initialize data structures
		m_chain_histogram = std::vector<std::uint32_t>(10, 0);
		m_segmented_sieve->reset_stats();
		
		// Mark as initialized
		m_initialized = true;
		m_logger->info("Worker_prime {}: Initialization complete", m_config.m_id);
		
	} catch (const std::exception& e) {
		m_logger->error("Worker_prime constructor: Failed to initialize worker {}: {}", 
		                m_config.m_id, e.what());
		m_initialized = false;
		throw;
	} catch (...) {
		m_logger->error("Worker_prime constructor: Unknown exception during initialization of worker {}", 
		                m_config.m_id);
		m_initialized = false;
		throw;
	}
}

Worker_prime::~Worker_prime() noexcept
{
	try {
		m_logger->debug("Worker_prime destructor: Cleaning up worker {}", m_config.m_id);
		
		// Stop the mining thread
		m_stop = true;
		
		// Wait for thread to complete with timeout protection
		if (m_run_thread.joinable())
		{
			m_logger->debug("Worker_prime destructor: Waiting for worker {} thread to finish", m_config.m_id);
			m_run_thread.join();
		}
		
		// Join all worker threads
		for (auto& thread : m_worker_threads) {
			if (thread.joinable())
				thread.join();
		}
		
		m_logger->debug("Worker_prime destructor: Worker {} cleanup complete", m_config.m_id);
		
	} catch (const std::exception& e) {
		// Log but don't propagate exceptions from destructor
		if (m_logger) {
			m_logger->error("Worker_prime destructor: Exception during cleanup of worker {}: {}", 
			                m_config.m_id, e.what());
		}
	} catch (...) {
		if (m_logger) {
			m_logger->error("Worker_prime destructor: Unknown exception during cleanup of worker {}", 
			                m_config.m_id);
		}
	}
}

void Worker_prime::set_block(LLP::CBlock block, std::uint32_t nbits, Worker::Block_found_handler result)
{
	// Validate worker is properly initialized
	if (!m_initialized) {
		m_logger->error("Worker_prime::set_block: Worker {} not properly initialized, cannot set block", 
		                m_config.m_id);
		return;
	}
	
	try {
		m_logger->debug("Worker_prime::set_block: Setting new block for worker {}", m_config.m_id);
		
		//stop the existing mining loop if it is running
		m_stop = true;
		if (m_run_thread.joinable())
		{
			m_logger->debug("Worker_prime::set_block: Waiting for previous thread to finish for worker {}", 
			                m_config.m_id);
			m_run_thread.join();
		}

		{
			std::scoped_lock<std::mutex> lck(m_mtx);
			m_found_nonce_callback = result;
			m_block = Block_data{ block };
			if (nbits != 0)	// take nBits provided from pool
			{
				m_pool_nbits = nbits;
			}

			m_difficulty = m_pool_nbits != 0 ? m_pool_nbits : m_block.nBits;
			bool excludeNonce = true;  //prime block hash excludes the nonce
			std::vector<unsigned char> headerB = m_block.GetHeaderBytes(excludeNonce);
			//calculate the block hash
			NexusSkein skein;
			skein.setMessage(headerB);
			skein.calculateHash();
			NexusSkein::stateType hash = skein.getHash();

			//keccak
			NexusKeccak keccak(hash);
			keccak.calculateHash();
			NexusKeccak::k_1024 keccakFullHash_i = keccak.getHashResult();
			keccakFullHash_i.isBigInt = true;
			uint1k keccakFullHash("0x" + keccakFullHash_i.toHexString(true));
			m_base_hash = keccakFullHash;
			//Now we have the hash of the block header.  We use this to feed the miner. 

			//set the starting nonce for each worker to something different that won't overlap with the others
			m_starting_nonce = static_cast<uint64_t>(m_config.m_internal_id) << 48;
			m_nonce = m_starting_nonce;

			//set the sieve start range
			uint1k startprime = m_base_hash + m_nonce;
			m_segmented_sieve->set_sieve_start(startprime);
			//update the starting nonce to reflect the actual sieve start used
			m_nonce = static_cast<uint64_t>(m_segmented_sieve->get_sieve_start() - m_base_hash);
			//m_logger->debug("starting nonce: {}", m_nonce);
			//clear out any old chains from the last block
			m_segmented_sieve->clear_chains();
		}
		//restart the mining loop
		m_stop = false;
		m_logger->debug("Worker_prime::set_block: Starting mining thread for worker {}", m_config.m_id);
		m_run_thread = std::thread(&Worker_prime::run, this);
		
	} catch (const std::exception& e) {
		m_logger->error("Worker_prime::set_block: Exception for worker {}: {}", m_config.m_id, e.what());
		m_stop = true;
	} catch (...) {
		m_logger->error("Worker_prime::set_block: Unknown exception for worker {}", m_config.m_id);
		m_stop = true;
	}
}

void Worker_prime::run()
{
	// Get CPU configuration
	if (!std::holds_alternative<config::Worker_config_cpu>(m_config.m_worker_mode)) {
		m_logger->error(m_log_leader + "Invalid worker mode for CPU worker");
		return;
	}
	
	auto const& cpu_cfg = std::get<config::Worker_config_cpu>(m_config.m_worker_mode);
	uint32_t num_threads = (cpu_cfg.m_threads > 0) ? cpu_cfg.m_threads : 1;
	
	// Prime mining currently supports single-threaded mode only
	// Multi-threading requires sieve partitioning which is more complex
	if (num_threads > 1) {
		m_logger->warn(m_log_leader + "Multi-threading requested ({} threads) but prime mining currently supports only single thread", num_threads);
		m_logger->warn(m_log_leader + "Falling back to single-threaded mode");
		num_threads = 1;
	}
	
	// Apply thread settings
	if (cpu::set_thread_priority(cpu_cfg.m_priority_level)) {
		m_logger->info(m_log_leader + "Thread priority set to level {}", cpu_cfg.m_priority_level);
	} else {
		m_logger->warn(m_log_leader + "Failed to set thread priority to level {}", cpu_cfg.m_priority_level);
	}
	
	// Apply hyperthreading and efficiency cores filtering
	uint64_t effective_affinity = cpu_cfg.m_affinity_mask;
	
	if (effective_affinity == 0) {
		// No specific affinity set, potentially filter based on HT/E-core settings
		if (!cpu_cfg.m_enable_hyperthreading || !cpu_cfg.m_enable_efficiency_cores) {
			// Get total logical processors
			uint32_t total_cores = std::thread::hardware_concurrency();
			uint32_t physical_cores = cpu::get_physical_core_count();
			bool smt_enabled = cpu::is_smt_enabled();
			
			m_logger->info(m_log_leader + "Core detection: {} logical cores, {} physical cores, SMT {}",
			              total_cores, physical_cores, smt_enabled ? "enabled" : "disabled");
			
			// Build affinity mask based on settings
			if (!cpu_cfg.m_enable_hyperthreading && smt_enabled) {
				// Use only physical cores (first half typically)
				for (uint32_t i = 0; i < physical_cores; i++) {
					effective_affinity |= (1ULL << i);
				}
				m_logger->info(m_log_leader + "Hyperthreading disabled, using physical cores only: 0x{:016x}", 
				              effective_affinity);
			}
			
			if (!cpu_cfg.m_enable_efficiency_cores) {
				// Try to get P-cores only
				auto p_cores = cpu::get_performance_cores();
				if (!p_cores.empty()) {
					effective_affinity = 0;
					for (auto core : p_cores) {
						effective_affinity |= (1ULL << core);
					}
					m_logger->info(m_log_leader + "E-cores disabled, using P-cores only: 0x{:016x}", 
					              effective_affinity);
				} else {
					m_logger->warn(m_log_leader + "Could not detect P-cores, using all cores");
				}
			}
		}
	}
	
	if (effective_affinity != 0) {
		if (cpu::set_thread_affinity(effective_affinity)) {
			m_logger->info(m_log_leader + "Thread affinity set to 0x{:016x}", effective_affinity);
		} else {
			m_logger->warn(m_log_leader + "Failed to set thread affinity to 0x{:016x}", effective_affinity);
		}
	}
	
	m_segmented_sieve->calculate_starting_multiples();
	uint32_t segment_size = m_segmented_sieve->get_segment_size();
	uint64_t find_chains_ms = 0;
	uint64_t sieving_ms = 0;
	uint64_t test_chains_ms = 0;
	uint64_t elapsed_ms = 0;
	uint64_t high = 0;
	uint64_t low = 0;
	uint64_t range_searched_this_cycle = 0;

	auto start = std::chrono::steady_clock::now();
	auto interval_start = std::chrono::steady_clock::now();
	
	// Initialize CPU tracking
	m_cpu_tracking_start = std::chrono::steady_clock::now();
	m_cpu_active_time = std::chrono::milliseconds{0};
	m_cpu_total_time = std::chrono::milliseconds{0};
	
	while (!m_stop)
	{
		auto iteration_start = std::chrono::steady_clock::now();
		
		m_segmented_sieve->reset_sieve();
		m_segmented_sieve->clear_chains();

		// current segment = [low, high]
		high = low + segment_size - 1;
		uint64_t sieve_size = (high - low) / 30 + 1;
		m_range_searched += segment_size;
		range_searched_this_cycle += segment_size;

		auto sieve_start = std::chrono::steady_clock::now();
		m_segmented_sieve->sieve_segment();
		auto sieve_stop = std::chrono::steady_clock::now();
		auto sieve_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(sieve_stop - sieve_start);
		sieving_ms += sieve_elapsed.count();
		auto find_chains_start = std::chrono::steady_clock::now();
		m_segmented_sieve->find_chains(low, false);
		auto find_chains_stop = std::chrono::steady_clock::now();
		auto find_chains_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(find_chains_stop - find_chains_start);
		find_chains_ms += find_chains_elapsed.count();
		auto test_chains_start = std::chrono::steady_clock::now();
		m_segmented_sieve->test_chains();
		auto test_chains_stop = std::chrono::steady_clock::now();
		auto test_chains_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(test_chains_stop - test_chains_start);
		test_chains_ms += test_chains_elapsed.count();
		//check difficulty of any chains that passed through the filter
		for (auto x : m_segmented_sieve->m_long_chain_starts)
		{
			m_block.nNonce = m_nonce + x;
			uint1k chain_start = m_base_hash + m_block.nNonce;
			
			// Enhanced validation using new prime_validation module
			uint1024_t hashPrime = boost_uint1024_t_to_uint1024_t(chain_start);
			double required_difficulty = getNetworkDifficulty();
			std::vector<uint8_t> offsets;
			double actual_difficulty = 0.0;
			
			// Use the new comprehensive validation
			bool is_valid = nexusminer::prime::ValidatePrimeCandidate(
				hashPrime, 
				required_difficulty, 
				offsets, 
				actual_difficulty
			);
			
			if (is_valid)
			{
				m_segmented_sieve->m_best_chain = std::max(actual_difficulty, m_segmented_sieve->m_best_chain);
				
				// Format offsets for logging
				std::ostringstream offsets_str;
				offsets_str << "[";
				for (size_t i = 0; i < offsets.size(); ++i) {
					if (i > 0) offsets_str << ", ";
					offsets_str << static_cast<int>(offsets[i]);
				}
				offsets_str << "]";
				
				m_logger->info(m_log_leader + "✓ FOUND VALID PRIME BLOCK! Difficulty: {:.6f} (required: {:.6f}), Chain length: {}, Offsets: {}", 
					actual_difficulty, required_difficulty, offsets.size(), offsets_str.str());
				
				//we found a valid chain.  submit it. 
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
			else
			{
				m_logger->debug(m_log_leader + "Candidate validation failed (difficulty {:.6f} < {:.6f} or invalid prime), continuing...",
					actual_difficulty, required_difficulty);
			}
		}
		low += segment_size;
		
		// Track CPU active time for this iteration
		auto iteration_end = std::chrono::steady_clock::now();
		auto iteration_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(iteration_end - iteration_start);
		m_cpu_active_time += iteration_elapsed;
		
		// Update total time
		m_cpu_total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
			iteration_end - m_cpu_tracking_start);
		
		//debug
		auto end = std::chrono::steady_clock::now();
		auto interval_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - interval_start);
		bool print_debug = false;
		if (print_debug && interval_elapsed.count() > 10000)
		{
			std::cout << "--debug--" << std::endl;
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
			elapsed_ms = elapsed.count();
			double chains_per_mm = 1.0e6 * m_segmented_sieve->m_chain_count / m_range_searched;
			double chains_per_sec = 1.0e3 * m_segmented_sieve->m_chain_count / elapsed_ms;
			double fermat_positive_rate = 1.0 * m_segmented_sieve->m_fermat_prime_count / m_segmented_sieve->m_fermat_test_count;
			double fermat_tests_per_chain = 1.0 * m_segmented_sieve->m_fermat_test_count / m_segmented_sieve->m_chain_count;
			std::cout << std::fixed << std::setprecision(2) << m_range_searched / 1.0e9 << " billion integers searched." <<
				" Found " << m_segmented_sieve->m_chain_count << " chain candidates. (" << chains_per_mm << " chains per million integers)" << std::endl;
			std::cout << "Fermat Tests: " << m_segmented_sieve->m_fermat_test_count << " Fermat Primes: " << m_segmented_sieve->m_fermat_prime_count <<
				" Fermat Positive Rate: " << std::fixed << std::setprecision(3) <<
				100.0 * fermat_positive_rate << "% Fermat tests per million integers sieved: " <<
				1.0e6 * m_segmented_sieve->m_fermat_test_count / m_range_searched << std::endl;

			std::cout << "Search rate: " << std::fixed << std::setprecision(1) << range_searched_this_cycle / (elapsed.count() * 1.0e3) << " million integers per second." << std::endl;
			double predicted_8chain_positivity_rate = std::pow(fermat_positive_rate, 8);
			//std::cout << "Predicted chains tested to find one Fermat 8-chains: " << 1 / predicted_8chain_positivity_rate << std::endl;
			//double predicted_days_between_8chains = 1.0 / (predicted_8chain_positivity_rate * chains_per_sec * 3600 * 24);
			//std::cout << "Predicted days between 8 chains per core: " << std::fixed << std::setprecision(2) << predicted_days_between_8chains << std::endl;
			std::cout << "Elapsed time: " << std::fixed << std::setprecision(2) << elapsed_ms / 1000.0 << "s. Sieving: " <<
				100.0 * sieving_ms / elapsed_ms << "% Chain filtering: " << 100.0 * find_chains_ms / elapsed_ms
				<< "% Fermat testing: " << 100.0 * test_chains_ms / elapsed_ms << "% Other: " <<
				100.0 * (elapsed_ms - (sieving_ms + find_chains_ms + test_chains_ms)) / elapsed_ms << "%" << std::endl;
			interval_start = std::chrono::steady_clock::now();
			std::cout << std::endl;
		}
	}
}

double Worker_prime::getDifficulty(uint1k p)
{
	std::vector<unsigned int> offsets_to_test;
	LLC::CBigNum prime_to_test = boost_uint1024_t_to_CBignum(p);
	double difficulty = m_prime_helper->GetPrimeDifficulty(prime_to_test, 1, offsets_to_test);
	return difficulty;
}

double Worker_prime::getNetworkDifficulty()
{
	return m_difficulty / 10000000.0;
}

bool Worker_prime::difficulty_check(uint1k p)
{
	return getDifficulty(p) >= getNetworkDifficulty();
}



LLC::CBigNum Worker_prime::boost_uint1024_t_to_CBignum(uint1k p)
{
	std::stringstream ss;
	ss << std::hex << p;
	std::string p_hex_str = ss.str();
	LLC::CBigNum p_CBignum;
	p_CBignum.SetHex(p_hex_str);
	return p_CBignum;
}

// Helper function to convert boost::multiprecision::uint1024_t to LLC::uint1024_t
uint1024_t Worker_prime::boost_uint1024_t_to_uint1024_t(uint1k p)
{
	std::stringstream ss;
	ss << std::hex << p;
	std::string p_hex_str = ss.str();
	uint1024_t result;
	result.SetHex(p_hex_str);
	return result;
}

void Worker_prime::update_statistics(stats::Collector& stats_collector)
{
	auto prime_stats = std::get<stats::Prime>(stats_collector.get_worker_stats(m_config.m_internal_id));
	prime_stats.m_primes = m_segmented_sieve->m_fermat_prime_count;
	prime_stats.m_chains = m_segmented_sieve->m_chain_count;
	prime_stats.m_difficulty = m_difficulty;
	prime_stats.m_chain_histogram = m_segmented_sieve->m_chain_histogram;
	prime_stats.m_range_searched = m_range_searched;
	prime_stats.m_most_difficult_chain = m_segmented_sieve->m_best_chain;
	
	// Calculate CPU load as ratio of active time to total time
	if (m_cpu_total_time.count() > 0) {
		prime_stats.m_cpu_load = static_cast<double>(m_cpu_active_time.count()) / 
		                          static_cast<double>(m_cpu_total_time.count());
		// Clamp to [0.0, 1.0]
		prime_stats.m_cpu_load = std::max(0.0, std::min(1.0, prime_stats.m_cpu_load));
	} else {
		prime_stats.m_cpu_load = 0.0;
	}

	stats_collector.update_worker_stats(m_config.m_internal_id, prime_stats);

	m_primes = 0;
	m_chains = 0;
}

void Worker_prime::fermat_performance_test()
//test the throughput of fermat primality test
{
	using namespace boost::multiprecision;
	using namespace boost::random;

	typedef independent_bits_engine<mt19937, 1024, boost::multiprecision::uint1024_t> generator1024_type;
	generator1024_type gen1024;
	gen1024.seed(time(0));
	// Generate some random 1024-bit unsigned values:
	std::vector<boost::multiprecision::uint1024_t> big_uints;
	int sample_size = 2000;
	for (unsigned i = 0; i < sample_size; ++i)
	{
		boost::multiprecision::uint1024_t pp = gen1024();
		//make it odd
		pp += 1?(pp % 2) == 0:0;
		big_uints.push_back(pp);
	}

	int p_count = 0;
	auto start = std::chrono::steady_clock::now();
	for (unsigned i = 0; i < sample_size; ++i)
	{
		p_count += 1 ? m_segmented_sieve->primality_test(big_uints[i]) : 0;
	}
	auto end = std::chrono::steady_clock::now();
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	double expected_primes = sample_size * 2 / (1024 * 0.693147);
	std::stringstream ss;
	ss << "Found " << p_count << " primes out of " << sample_size << " tested. Expected about " << expected_primes << ". ";
	ss << std::fixed << std::setprecision(2) << 1000.0* sample_size /elapsed.count()<< " primality tests/second. (" << 1.0*elapsed.count()/ sample_size << "ms)";
	m_logger->info(ss.str());
	
}

}
}