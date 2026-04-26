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
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <sstream> 
#include <boost/random.hpp>

namespace nexusminer
{
namespace cpu
{
namespace
{
constexpr std::size_t kPrimeOffsetFractionBytes = sizeof(std::uint32_t);
constexpr std::size_t kMaxSerializedPrimeOffsets = 10;
constexpr std::size_t kBoostUint1kLimbBytes = sizeof(boost::multiprecision::limb_type);

bool has_expected_prime_offsets(const std::vector<uint8_t>& offsets)
{
	return offsets.size() == kMaxSerializedPrimeOffsets;
}
}

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

		// Start persistent thread
		m_shutdown = false;
		m_run_thread = std::thread(&Worker_prime::run, this);
		m_logger->info(m_log_leader + "Persistent worker thread started");

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

		m_stop = true;  // Interrupt mining loops before competing for m_mtx during shutdown

		// Signal shutdown and wake up the worker thread
		{
			std::scoped_lock<std::mutex> lck(m_mtx);
			m_shutdown = true;
			m_running = false;
		}
		m_cv.notify_all();

		// Wait for main thread to complete with timeout protection
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
		Block_data block_data{ block };
		const auto base_hash = block_data.GetPrimeBaseHash();
		set_block_impl(std::move(block_data), nbits, base_hash, std::move(result));

	} catch (const std::exception& e) {
		m_logger->error("Worker_prime::set_block: Exception for worker {}: {}", m_config.m_id, e.what());
	} catch (...) {
		m_logger->error("Worker_prime::set_block: Unknown exception for worker {}", m_config.m_id);
	}
}

void Worker_prime::set_block(std::shared_ptr<WorkPackage> work_package, Worker::Block_found_handler result)
{
	// Validate worker is properly initialized
	if (!m_initialized) {
		m_logger->error("Worker_prime::set_block: Worker {} not properly initialized, cannot set block",
		                m_config.m_id);
		return;
	}

	try {
		m_logger->debug("Worker_prime::set_block: Setting new block for worker {} (optimized)", m_config.m_id);
		const auto& block = work_package->get_block();
		Block_data block_data{ block };
		const auto& precomputed_hash = work_package->get_prime_base_hash();
		if (precomputed_hash.has_value()) {
			m_logger->debug("Worker_prime::set_block: Using precomputed base hash from WorkPackage");
			set_block_impl(std::move(block_data), work_package->get_nbits(), precomputed_hash.value(), std::move(result));
		} else {
			m_logger->debug("Worker_prime::set_block: Computing base hash locally (no precomputed hash)");
			const auto base_hash = block_data.GetPrimeBaseHash();
			set_block_impl(std::move(block_data), work_package->get_nbits(), base_hash, std::move(result));
		}

	} catch (const std::exception& e) {
		m_logger->error("Worker_prime::set_block: Exception for worker {}: {}", m_config.m_id, e.what());
	} catch (...) {
		m_logger->error("Worker_prime::set_block: Unknown exception for worker {}", m_config.m_id);
	}
}

void Worker_prime::set_block_impl(Block_data block_data,
                                  std::uint32_t nbits,
                                  const uint1k& base_hash,
                                  Worker::Block_found_handler result)
{
	bool notify_worker = false;

	{
		std::scoped_lock<std::mutex> lck(m_mtx);
		m_found_nonce_callback = std::move(result);

		if (nbits != 0)	// take nBits provided from pool
		{
			m_pool_nbits = nbits;
		}

		const auto new_difficulty = m_pool_nbits != 0 ? m_pool_nbits : block_data.nBits;
		// same_active_search: the worker is already mining this exact proof-hash space,
		// so restarting would only throw away current sieve/segment progress.
		const bool same_active_search = !m_new_work && m_has_active_cycle && base_hash == m_active_base_hash;
		// same_queued_work: an identical template is already pending for the worker
		// thread, so avoid stacking another redundant restart request on top of it.
		const bool same_queued_work = m_new_work && base_hash == m_base_hash;

		// Preserve current search progress when the incoming template maps to the
		// exact same prime proof-hash space. Restarting would only throw away work.
		if (same_active_search || same_queued_work) {
			m_block = std::move(block_data);
			m_difficulty = new_difficulty;
			m_base_hash = base_hash;
			m_logger->debug("Worker_prime::set_block: Preserving current search for worker {} (duplicate prime proof-hash work)",
			                m_config.m_id);
			return;
		}

		m_block = std::move(block_data);
		m_difficulty = new_difficulty;
		m_base_hash = base_hash;

		// set the starting nonce for each worker to something different that won't overlap with the others
		m_starting_nonce = static_cast<uint64_t>(m_config.m_internal_id) << 48;
		m_nonce = m_starting_nonce;

		// NOTE: Sieve initialization (set_sieve_start, clear_chains,
		// calculate_starting_multiples) is intentionally NOT done here.
		// It runs on the worker thread in run() to eliminate the race condition
		// where set_block() could mutate the sieve while run() is using it.

		// Signal new work is available
		m_stop = true;
		m_new_work = true;
		m_running = true;
		notify_worker = true;
	}

	if (notify_worker) {
		m_cv.notify_one();
		m_logger->debug("Worker_prime::set_block: New work signaled for worker {}", m_config.m_id);
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
	uint32_t num_threads = (cpu_cfg.m_threads > 1) ? cpu_cfg.m_threads : 1;

	// Prime mining currently supports single-threaded mode only
	// Multi-threading requires sieve partitioning which is more complex
	if (num_threads > 1) {
		m_logger->warn(m_log_leader + "Multi-threading requested ({} threads) but prime mining currently supports only single thread", num_threads);
		m_logger->warn(m_log_leader + "Falling back to single-threaded mode");
		num_threads = 1;
	}

	m_logger->info(m_log_leader + "Persistent worker thread ready, waiting for work...");

	// Persistent thread loop - runs until shutdown
	while (true) {
		// Wait for new work or shutdown signal
		{
			std::unique_lock<std::mutex> lock(m_mtx);
			m_cv.wait(lock, [this] { return m_new_work || m_shutdown; });

			// Check for shutdown
			if (m_shutdown) {
				m_logger->info(m_log_leader + "Worker thread shutting down");
				break;
			}

			// Clear new work flag
			m_new_work = false;
			// Reset stop flag so the inner mining loop can run
			m_stop = false;
		}

		// Apply thread settings for mining
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

		// Make local copies of block data to avoid race conditions
		// These copies are made once per work unit and remain stable during mining
		Block_data local_block;
		uint1k local_base_hash;
		uint64_t local_nonce;
		{
			std::scoped_lock<std::mutex> lck(m_mtx);
			local_block = m_block;
			local_base_hash = m_base_hash;
			local_nonce = m_nonce;
			m_active_base_hash = local_base_hash;
			m_has_active_cycle = true;
		}
		// Initialize the sieve on the worker thread only — set_block() no longer mutates
		// m_segmented_sieve, so all sieve operations are exclusively on this thread,
		// eliminating the race condition that caused the segfault at template transitions.
		{
			uint1k startprime = local_base_hash + local_nonce;
			m_segmented_sieve->set_sieve_start(startprime);
			// Update local_nonce to reflect the actual sieve start position chosen by the sieve.
			// We do NOT write back to m_nonce here: set_block() always resets m_nonce to
			// m_starting_nonce before run() reads it, so the adjusted value is only needed
			// locally within this mining cycle.
			local_nonce = static_cast<uint64_t>(m_segmented_sieve->get_sieve_start() - local_base_hash);
			m_segmented_sieve->clear_chains();
			m_segmented_sieve->calculate_starting_multiples();
		}
		publish_statistics_snapshot();
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

	// Initialize CPU tracking (protected by mutex to prevent races with update_statistics)
	{
		std::scoped_lock<std::mutex> lck(m_mtx);
		m_cpu_tracking_start = std::chrono::steady_clock::now();
		m_cpu_active_time = std::chrono::milliseconds{0};
		m_cpu_total_time = std::chrono::milliseconds{0};
	}

	while (!m_stop)
	{
		// Check for new work at the top of the loop
		{
			std::unique_lock<std::mutex> lck(m_mtx);
			if (m_new_work)
			{
				break;
			}
		}

		auto iteration_start = std::chrono::steady_clock::now();

		m_segmented_sieve->reset_sieve();
		if (m_stop) break;  // Check if new work arrived during reset_sieve()
		m_segmented_sieve->clear_chains();
		if (m_stop) break;  // Check if new work arrived during clear_chains()

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
		const double required_difficulty = getNetworkDifficulty();
		//check difficulty of any chains that passed through the filter
		for (auto x : m_segmented_sieve->m_long_chain_starts)
		{
			local_block.nNonce = local_nonce + x;
			uint1k chain_start = local_base_hash + local_block.nNonce;

			// Enhanced validation using new prime_validation module
			uint1024_t hashPrime = boost_uint1024_t_to_uint1024_t(chain_start);
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
				assert(has_expected_prime_offsets(offsets) &&
					"Expected 10 total bytes (6 prime-gap bytes + 4-byte LE fraction)");
				if (!has_expected_prime_offsets(offsets))
				{
					m_logger->error(m_log_leader + "Rejecting prime candidate with malformed serialized offsets ({} bytes, expected {} total bytes = {} prime-gap bytes + {}-byte LE fraction)",
						offsets.size(),
						kMaxSerializedPrimeOffsets,
						kMaxSerializedPrimeOffsets - kPrimeOffsetFractionBytes,
						kPrimeOffsetFractionBytes);
					continue;
				}

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
						m_logger->info(m_log_leader + "💎 Block found! Posting to main io_context...");
						// Capture block and offsets by value to avoid dangling references
						auto block_copy = local_block;
						auto captured_offsets = std::move(offsets);
						::asio::post(*m_io_context, [self = shared_from_this(), block_copy, captured_offsets = std::move(captured_offsets)]()
						{
							auto bd = std::make_unique<Block_data>(block_copy);
							bd->vOffsets = captured_offsets; // Prime chain offsets for submission
							self->m_found_nonce_callback(self->m_config.m_internal_id,
								std::move(bd));
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
		publish_statistics_snapshot();
		low += segment_size;

		// Track CPU active time for this iteration (protected by mutex to prevent races with update_statistics)
		auto iteration_end = std::chrono::steady_clock::now();
		auto iteration_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(iteration_end - iteration_start);
		{
			std::scoped_lock<std::mutex> lck(m_mtx);
			m_cpu_active_time += iteration_elapsed;

			// Update total time
			m_cpu_total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
				iteration_end - m_cpu_tracking_start);
		}
		
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

		{
			std::scoped_lock<std::mutex> lck(m_mtx);
			// Clear the active-cycle marker once the loop yields so a later duplicate
			// template is compared against the next live search, not stale prior state.
			m_has_active_cycle = false;
		}

		m_logger->info(m_log_leader + "Mining stopped, waiting for new work...");
	}  // End of persistent thread loop
}

double Worker_prime::getDifficulty(const uint1k& p)
{
	std::vector<uint8_t> offsets_to_test;
	double difficulty = 0.0;
	// Pass a zero threshold when we only need the canonical LLL-TAO difficulty
	// calculation and serialized offsets, not submission gating.
	nexusminer::prime::ValidatePrimeCandidate(
		boost_uint1024_t_to_uint1024_t(p),
		0.0,
		offsets_to_test,
		difficulty);
	return difficulty;
}

double Worker_prime::getNetworkDifficulty()
{
	return m_difficulty / 10000000.0;
}

bool Worker_prime::difficulty_check(const uint1k& p)
{
	return getDifficulty(p) >= getNetworkDifficulty();
}



LLC::CBigNum Worker_prime::boost_uint1024_t_to_CBignum(const uint1k& p)
{
	std::stringstream ss;
	ss << std::hex << p;
	std::string p_hex_str = ss.str();
	LLC::CBigNum p_CBignum;
	p_CBignum.SetHex(p_hex_str);
	return p_CBignum;
}

// Helper function to convert boost::multiprecision::uint1024_t to LLC::uint1024_t
uint1024_t Worker_prime::boost_uint1024_t_to_uint1024_t(const uint1k& p)
{
	uint1024_t result{};
	const auto limb_bytes = p.backend().size() * kBoostUint1kLimbBytes;
	if (limb_bytes > sizeof(result))
	{
		throw std::runtime_error("Boost uint1024 limb storage exceeds LLC uint1024_t size");
	}

	// Both boost::uint1024_t and LLC::uint1024_t store little-endian limbs in the
	// active numeric payload. prime_validation_test verifies this limb copy matches
	// the legacy hex round-trip used previously.
	std::memcpy(&result, p.backend().limbs(), limb_bytes);
	return result;
}

void Worker_prime::update_statistics(stats::Collector& stats_collector)
{
	auto prime_stats = *m_published_stats.load();

	// Keep CPU-load reporting interval-based while leaving histogram/best-chain stats
	// on the immutable worker snapshot path.
	{
		std::scoped_lock<std::mutex> lck(m_mtx);
		if (m_cpu_total_time.count() > 0) {
			prime_stats.m_cpu_load = static_cast<double>(m_cpu_active_time.count()) /
			                          static_cast<double>(m_cpu_total_time.count());
			prime_stats.m_cpu_load = std::max(0.0, std::min(1.0, prime_stats.m_cpu_load));
		} else {
			prime_stats.m_cpu_load = 0.0;
		}

		m_cpu_active_time = {};
		m_cpu_total_time  = {};
		m_cpu_tracking_start = std::chrono::steady_clock::now();
	}

	stats_collector.update_worker_stats(m_config.m_internal_id, prime_stats);

	// [Sieve Diag] log — emitted on stats thread only, reads atomics with relaxed order
	{
		auto sieve_calls = m_segmented_sieve->m_diag_sieve_calls.load(std::memory_order_relaxed);
		auto inner_hits  = m_segmented_sieve->m_diag_inner_hits.load(std::memory_order_relaxed);
		auto sort_us     = m_segmented_sieve->m_diag_sort_us.load(std::memory_order_relaxed);
		auto prime_count = m_segmented_sieve->m_diag_prime_count.load(std::memory_order_relaxed);

		if (sieve_calls > 0) {
			m_logger->debug("[Sieve Diag] calls={} hits={} hits/call={:.1f} sort={:.2f}ms primes={}",
				sieve_calls, inner_hits,
				static_cast<double>(inner_hits) / sieve_calls,
				sort_us / 1000.0,
			prime_count);
		}
	}
}

void Worker_prime::publish_statistics_snapshot()
{
	stats::Prime prime_stats;
	prime_stats.m_primes = stats::saturating_prime_stat(m_segmented_sieve->m_fermat_prime_count);
	prime_stats.m_chains = stats::saturating_prime_stat(m_segmented_sieve->m_chain_count);
	prime_stats.m_chain_histogram = stats::copy_prime_histogram(m_segmented_sieve->m_chain_histogram);
	prime_stats.m_range_searched = m_range_searched.load(std::memory_order_relaxed);
	prime_stats.m_most_difficult_chain = m_segmented_sieve->m_best_chain;

	{
		std::scoped_lock<std::mutex> lck(m_mtx);
		prime_stats.m_difficulty = m_difficulty;
		if (m_cpu_total_time.count() > 0) {
			prime_stats.m_cpu_load = static_cast<double>(m_cpu_active_time.count()) /
			                          static_cast<double>(m_cpu_total_time.count());
			prime_stats.m_cpu_load = std::max(0.0, std::min(1.0, prime_stats.m_cpu_load));
		} else {
			prime_stats.m_cpu_load = 0.0;
		}
	}

	m_published_stats.store(std::move(prime_stats));
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
