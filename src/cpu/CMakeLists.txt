add_library(cpu STATIC src/cpu/worker_hash.cpp src/cpu/thread_utils.cpp)

if(WITH_PRIME)
    target_sources(cpu PRIVATE src/cpu/worker_prime.cpp src/cpu/prime/prime.cpp src/cpu/prime/chain_sieve.cpp src/cpu/prime_validation.cpp)
endif()
                    
target_include_directories(cpu
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE src
)

# TODO reduce dependencies
target_link_libraries(cpu hash worker LLP LLC stats config spdlog::spdlog)

add_executable(worker_hash_shutdown_test worker_hash_shutdown_test.cpp)
target_link_libraries(worker_hash_shutdown_test PRIVATE cpu spdlog::spdlog GTest::gtest_main)
target_include_directories(worker_hash_shutdown_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/config/inc
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(worker_hash_shutdown_test)

if(WITH_PRIME)
    target_link_libraries(cpu libprimesieve-static)
    if(WIN32)
        target_link_libraries(cpu mpir) # OpenSSL::Crypto OpenSSL::applink)
    else()
       target_link_libraries(cpu gmp) # OpenSSL::Crypto OpenSSL::applink)
    endif()

    add_executable(prime_validation_test prime_validation_test.cpp)
    target_link_libraries(prime_validation_test PRIVATE cpu LLC spdlog::spdlog GTest::gtest_main)
    gtest_discover_tests(prime_validation_test)
endif()
