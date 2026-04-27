add_library(cpu STATIC src/cpu/worker_hash.cpp src/cpu/thread_utils.cpp)

if(WITH_PRIME)
    target_sources(cpu PRIVATE src/cpu/worker_prime.cpp src/cpu/prime/prime.cpp src/cpu/prime/chain_sieve.cpp src/cpu/prime/sieving_prime_table.cpp src/cpu/prime/segment_allocator.cpp src/cpu/prime/prime_mining_engine.cpp src/cpu/prime_validation.cpp)
endif()
                    
target_include_directories(cpu
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE src
)

# TODO reduce dependencies
target_link_libraries(cpu hash worker LLP LLC stats config spdlog::spdlog)

add_nexusminer_test(
    NAME        worker_hash_shutdown_test
    SOURCES     worker_hash_shutdown_test.cpp
    LINK_LIBS   cpu spdlog::spdlog
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/inc
                 ${CMAKE_SOURCE_DIR}/src/config/inc
)

if(WITH_PRIME)
    target_link_libraries(cpu libprimesieve-static)
    if(WIN32)
        target_link_libraries(cpu mpir) # OpenSSL::Crypto OpenSSL::applink)
    else()
       target_link_libraries(cpu gmp) # OpenSSL::Crypto OpenSSL::applink)
    endif()

    add_nexusminer_test(
        NAME        prime_validation_test
        SOURCES     prime_validation_test.cpp
        LINK_LIBS   cpu LLC spdlog::spdlog
    )

    add_nexusminer_test(
        NAME        sieving_prime_table_test
        SOURCES     sieving_prime_table_test.cpp
        LINK_LIBS   cpu spdlog::spdlog
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    add_nexusminer_test(
        NAME        segment_allocator_test
        SOURCES     segment_allocator_test.cpp
        LINK_LIBS   cpu spdlog::spdlog
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    add_nexusminer_test(
        NAME        chain_sieve_test
        SOURCES     chain_sieve_test.cpp
        LINK_LIBS   cpu spdlog::spdlog
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    add_nexusminer_test(
        NAME        prime_mining_engine_test
        SOURCES     prime_mining_engine_test.cpp
        LINK_LIBS   cpu spdlog::spdlog
        INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
endif()
