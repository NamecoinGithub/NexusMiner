#ifndef CHAIN_SIEVE_HPP
#define CHAIN_SIEVE_HPP

#include <vector>
#include <atomic>
#include <algorithm>
#include <numeric>
#include <spdlog/spdlog.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/gmp.hpp>
#include "sieve_utils.hpp"
#include "mining/mining_constants.hpp"

namespace nexusminer {
	namespace cpu
	{
		enum class Fermat_test_status {
			untested,
			fail,
			pass
		};

		static constexpr int maxGap = 12;  //the largest allowable prime gap.

		//a candidate for a dense prime cluster.  A chain consists of a base integer plus a list of offsets. 
		class Chain
		{
		public:
			enum class Chain_state {
				open, //immature chain empty or in process of being built
				closed, //chain is complete and available for fermat testing
				in_process, //fermat testing is in process. 
				complete  //fermat testing is complete. 
			};

			class Chain_offset {
			public:
				int m_offset = 0;  //offset from the base offset
				Fermat_test_status m_fermat_test_status = Fermat_test_status::untested;
				Chain_offset(int offset) :m_offset{ offset }, m_fermat_test_status{ Fermat_test_status::untested }{};
			};

			Chain();
			Chain(uint64_t base_offset);
			void open(uint64_t base_offset);
			void close();
			int length() { return m_offsets.size(); }
			void get_best_fermat_chain(uint64_t& base_offset, int& offset, int& length);
			bool is_there_still_hope();  //is it possible this chain can result in a valid fermat chain
			bool get_next_fermat_candidate(uint64_t& base_offset, int& offset);
			bool update_fermat_status(bool is_prime);
			void push_back(int offset);
			const std::string str();

			int m_min_chain_length = 8;
			int m_min_chain_report_length = 4;
			Chain_state m_chain_state = Chain_state::open;
			uint64_t m_base_offset = 0;
			std::vector<Chain_offset> m_offsets; //offsets including 0
			int m_gap_in_process = 0;
			int m_next_fermat_test_offset_index = 0;
			int m_prime_count = 0;
			int m_untested_count = 0;

		private:

		};

		class Sieve
		{
		public:
			Sieve();

			// Stone 1: kept for backward compatibility — first call resolves the
			// process-shared sieving prime table and sizes the per-worker mutable
			// wheel state (m_prime_state) accordingly.  Subsequent calls are
			// cheap (no re-generation, no extra allocation).
			void generate_sieving_primes();

			// Stone 2: prefer prepare(sieve_start).  set_sieve_start() still
			// rounds the start to a multiple of 30 and stores it as a fallback
			// for legacy callers that go on to invoke the no-arg overloads.
			void set_sieve_start(boost::multiprecision::uint1024_t);
			boost::multiprecision::uint1024_t get_sieve_start();

			// Stone 2: parameterised entry points.  These never read m_sieve_start;
			// the caller threads the base hash explicitly.  The no-arg overloads
			// below remain for legacy callers and forward to the cached value.
			//
			// prepare() bundles set_sieve_start + clear_chains +
			// calculate_starting_multiples and returns the rounded start that the
			// sieve actually uses (callers compare against the requested start to
			// adjust their nonce bookkeeping).
			boost::multiprecision::uint1024_t prepare(boost::multiprecision::uint1024_t sieve_start);
			void calculate_starting_multiples(const boost::multiprecision::uint1024_t& sieve_start);
			void calculate_starting_multiples();
			void test_chains(const boost::multiprecision::uint1024_t& sieve_start);
			void test_chains();

			void sieve_segment();
			void sieve_batch(uint64_t low);
			void sieve_batch_cpu(uint64_t low);
			std::uint32_t get_segment_size();
			std::uint32_t get_segment_batch_size();
			void reset_sieve();
			void reset_sieve_batch(uint64_t low);
			void clear_chains();
			void reset_stats();
			void find_chains(uint64_t low, bool batch_sieve_mode);
			uint64_t count_fermat_primes(uint64_t sieve_size, uint64_t low);
			bool primality_test(boost::multiprecision::uint1024_t p);
			void primality_batch_test();
			void primality_batch_test_cpu();
			void clean_chains();
			uint64_t get_current_chain_list_length();
			int get_fermat_test_batch_size() { return m_fermat_test_batch_size; }
			std::vector<std::uint64_t> m_long_chain_starts;
			uint64_t m_sieve_batch_start_offset;

			//stats
			std::vector<std::uint32_t> m_chain_histogram;
			uint64_t m_fermat_test_count = 0;
			uint64_t m_fermat_prime_count = 0;
			uint64_t m_chain_count = 0;
			int m_chain_candidate_max_length = 0;
			uint64_t m_chain_candidate_total_length = 0;
			double m_best_chain = 0;

			// ── Diagnostic counters: written ONLY by mining thread, read ONLY by stats thread ──
			// std::atomic so the stats collector thread can safely read without a mutex lock.
			// The mining thread does only fetch_add (relaxed); the stats thread does
			// .load(std::memory_order_relaxed) — no synchronisation needed beyond atomicity.
			std::atomic<uint64_t> m_diag_sieve_calls{0};   // total sieve_segment() calls since last reset
			std::atomic<uint64_t> m_diag_inner_hits{0};    // total inner-loop sieve-write hits since last reset
			std::atomic<uint64_t> m_diag_starting_multiples_us{0};  // µs spent in calculate_starting_multiples (no sort since Stone 1)
			std::atomic<uint32_t> m_diag_prime_count{0};   // count of sieving primes in m_primes_aos

		private:
			class Fermat_test_candidate {
			public:
				uint64_t base_offset = 0;
				int offset = 0;
				Fermat_test_status fermat_test_status = Fermat_test_status::untested;
				uint64_t get_offset() { return base_offset + offset; }
			};

			std::shared_ptr<spdlog::logger> m_logger;

			static constexpr uint8_t sieve30 = 0xFF;  //compressed sieve for primorial 2*3*5 = 30.  Each bit represents a possible prime location in the wheel {1,7,11,13,17,19,23,29} 
			static constexpr int sieve30_offsets[]{ 1,7,11,13,17,19,23,29 };  // each bit in the sieve30 represets an offset from the base mod 30
			static constexpr int sieve30_gaps[]{ 6,4,2,4,2,4,6,2 };
			static constexpr int sieve30_index[]{ -1,0,-1,-1,-1,-1,-1, 1, -1, -1, -1, 2, -1, 3, -1, -1, -1, 4, -1, 5, -1, -1, -1, 6, -1, -1, -1, -1, -1, 7 };  //reverse lookup table (offset mod 30 to index)
			static constexpr int L1_CACHE_SIZE = mining::L1_CACHE_BYTES;
			static constexpr int L2_CACHE_SIZE = mining::L2_CACHE_BYTES;
			//upper limit of the sieving range
			//static constexpr uint64_t sieve_range = 3e9;//3e9;
			//upper limit of the sieving primes. 
			static constexpr uint32_t sieving_prime_limit = mining::CPU_SIEVING_PRIME_LIMIT;
			static constexpr uint32_t sieve_size = L2_CACHE_SIZE * 16;
			//each segment byte covers a range of 30 sieving primes 
			static constexpr uint32_t m_segment_size = sieve_size * 30;
			//number of segments needed to cover the sieving range
			//static constexpr int segments = sieve_range / m_segment_size + (sieve_range % m_segment_size != 0);
			//we start sieving at 7
			static constexpr int sieving_start_prime = mining::SIEVING_START_PRIME;
			static constexpr int m_min_chain_length = mining::MIN_CHAIN_LENGTH;

			/// Bitmasks used to unset bits
			static constexpr uint8_t unset_bit_mask[30] =
			{
				(uint8_t)~(1 << 0), (uint8_t)~(1 << 0),
				(uint8_t)~(1 << 1), (uint8_t)~(1 << 1), (uint8_t)~(1 << 1), (uint8_t)~(1 << 1), (uint8_t)~(1 << 1), (uint8_t)~(1 << 1),
				(uint8_t)~(1 << 2), (uint8_t)~(1 << 2), (uint8_t)~(1 << 2), (uint8_t)~(1 << 2),
				(uint8_t)~(1 << 3), (uint8_t)~(1 << 3),
				(uint8_t)~(1 << 4), (uint8_t)~(1 << 4), (uint8_t)~(1 << 4), (uint8_t)~(1 << 4),
				(uint8_t)~(1 << 5), (uint8_t)~(1 << 5),
				(uint8_t)~(1 << 6), (uint8_t)~(1 << 6), (uint8_t)~(1 << 6), (uint8_t)~(1 << 6),
				(uint8_t)~(1 << 7), (uint8_t)~(1 << 7), (uint8_t)~(1 << 7), (uint8_t)~(1 << 7), (uint8_t)~(1 << 7), (uint8_t)~(1 << 7)
			};

			//how many bits are set in a byte
			static constexpr int popcnt[256] =
			{
			  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
			  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			  1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			  2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
			  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			  3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
			  4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
			};

			/// Stone 1: per-worker mutable wheel state for one sieving prime.
			/// The prime *value* lives in the process-shared
			/// Sieving_prime_table — only the per-worker (multiple, wheel_index)
			/// pair is duplicated across workers.  Order matches
			/// Sieving_prime_table::primes() (large-prime-first).
			struct SievePrimeState {
				uint32_t multiple;     ///< current multiple (updated each segment)
				int32_t  wheel_index;  ///< index into sieve30_offsets[] / unset_bit_mask[]
			};

			/// Per-wheel-position step sizes precomputed once per sieving prime.
			/// byte_delta   = (k * gap) / 30  — whole sieve-bytes to advance
			/// offset_delta = (k * gap) % 30  — sub-byte remainder
			struct WheelStep {
				uint32_t byte_delta;
				uint8_t  offset_delta;
			};

			//the sieve.  each bit that is set represents a possible prime.
			std::vector<uint8_t> m_sieve;
			// Stone 1: per-worker mutable wheel state, indexed parallel to
			// Sieving_prime_table::instance().primes().  The prime values
			// themselves are not duplicated here.
			std::vector<SievePrimeState> m_prime_state;
			std::vector<Chain> m_chain;
			std::vector<uint8_t> m_sieve_results;  //accumulated results of sieving
			boost::multiprecision::uint1024_t m_sieve_start;  //starting integer for the sieve.  This must be a multiple of 30.
			bool m_chain_in_process = false;
			Chain m_current_chain;
			static constexpr int m_fermat_test_batch_size = 100;
			static constexpr int m_segment_batch_size = 1; //number of segments to batch process
			static constexpr int m_sieve_batch_buffer_size = sieve_size * m_segment_batch_size;
			void close_chain();
			void open_chain(uint64_t base_offset);
		};
	}
}

#endif