cmake_minimum_required(VERSION 3.19)

add_library(protocol STATIC src/protocol/solo.cpp
                            src/protocol/pool_base.cpp
                            src/protocol/falcon_wrapper.cpp
                            src/protocol/chacha20_wrapper.cpp
                            src/protocol/session_manager.cpp
                            src/protocol/mining_template_interface.cpp
                            src/protocol/push_notification_handler.cpp
                            src/protocol/height_tracker.cpp
                            src/protocol/packet_builder.cpp
                            ${CMAKE_SOURCE_DIR}/src/LLP/colin_ping_handler.cpp
                            ${CMAKE_SOURCE_DIR}/src/LLP/stateless_block_utility.cpp)
                    
target_include_directories(protocol
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/Util/include
        ${CMAKE_SOURCE_DIR}/src/LLP/include
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(protocol PRIVATE network LLP stats config spdlog nlohmann_json::nlohmann_json ${OPENSSL_LIBRARIES})

# Mining Template Validation Unit Test
add_executable(mining_template_validation_test mining_template_validation_test.cpp)
target_link_libraries(mining_template_validation_test PRIVATE protocol LLP TAO spdlog)
target_include_directories(mining_template_validation_test PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/TAO/inc
)

# ChaCha20-Poly1305 AEAD Unit Test
add_executable(chacha20_test chacha20_test.cpp)
target_link_libraries(chacha20_test PRIVATE protocol spdlog ${OPENSSL_LIBRARIES})
target_include_directories(chacha20_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# Genesis Utils and Serialization Helpers Unit Test
add_executable(genesis_serialization_utils_test genesis_serialization_utils_test.cpp)
target_link_libraries(genesis_serialization_utils_test PRIVATE protocol)
target_include_directories(genesis_serialization_utils_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# HeightTracker Unit Test
add_executable(height_tracker_test height_tracker_test.cpp)
target_link_libraries(height_tracker_test PRIVATE protocol)
target_include_directories(height_tracker_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
)

# PacketBuilder Unit Test
add_executable(packet_builder_test packet_builder_test.cpp)
target_link_libraries(packet_builder_test PRIVATE protocol LLP spdlog)
target_include_directories(packet_builder_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# Phase 2B: unified height-state update regression tests
add_executable(phase2b_update_height_test phase2b_update_height_test.cpp)
target_link_libraries(phase2b_update_height_test PRIVATE protocol LLP spdlog)
target_include_directories(phase2b_update_height_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# KEEPALIVE v2 miner-side unit tests
add_executable(keepalive_v2_test keepalive_v2_test.cpp)
target_link_libraries(keepalive_v2_test PRIVATE protocol LLP spdlog)
target_include_directories(keepalive_v2_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# Push notification lane detection unit tests
add_executable(push_notification_lane_test push_notification_lane_test.cpp)
target_link_libraries(push_notification_lane_test PRIVATE LLP LLC)
target_include_directories(push_notification_lane_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# SESSION_STATUS / SESSION_STATUS_ACK wire-protocol unit tests
add_executable(session_status_wire_test session_status_wire_test.cpp)
target_link_libraries(session_status_wire_test PRIVATE LLP)
target_include_directories(session_status_wire_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# StatelessBlockUtility encode/decode unit tests
add_executable(stateless_block_utility_test
    stateless_block_utility_test.cpp
    ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp)
target_link_libraries(stateless_block_utility_test PRIVATE protocol LLP spdlog)
target_include_directories(stateless_block_utility_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src/LLP/include
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
    ${CMAKE_SOURCE_DIR}/src
)

# End-to-End Block Submission Test (encode_submit → ChaCha20 → SUBMIT_BLOCK)
add_executable(e2e_block_submission_test
    e2e_block_submission_test.cpp
    ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp)
target_link_libraries(e2e_block_submission_test PRIVATE protocol LLP spdlog ${OPENSSL_LIBRARIES})
target_include_directories(e2e_block_submission_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src/LLP/include
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
    ${CMAKE_SOURCE_DIR}/src
)

# MinedBlockCache + worker-feed dedup guard unit tests
add_executable(mined_block_cache_dedup_test
    ${CMAKE_SOURCE_DIR}/src/stats/mined_block_cache_test.cpp)
target_link_libraries(mined_block_cache_dedup_test PRIVATE protocol LLP stats spdlog)
target_include_directories(mined_block_cache_dedup_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src/stats/inc
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
    ${CMAKE_SOURCE_DIR}/src
)

# NODE_SHUTDOWN (0xD0FF) wire protocol unit tests
add_executable(node_shutdown_wire_test node_shutdown_wire_test.cpp)
target_link_libraries(node_shutdown_wire_test PRIVATE protocol LLP spdlog)
target_include_directories(node_shutdown_wire_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)

# GET_BLOCK deduplication and recovery unit tests
add_executable(get_block_dedup_recovery_test get_block_dedup_recovery_test.cpp)
target_link_libraries(get_block_dedup_recovery_test PRIVATE protocol LLP spdlog)
target_include_directories(get_block_dedup_recovery_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)
