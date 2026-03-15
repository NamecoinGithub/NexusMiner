add_library(protocol STATIC src/protocol/solo.cpp
                            src/protocol/pool_base.cpp
                            src/protocol/falcon_wrapper.cpp
                            src/protocol/chacha20_wrapper.cpp
                            src/protocol/chacha20_evp_manager.cpp
                            src/protocol/session_manager.cpp
                            src/protocol/node_session_context.cpp
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
add_test(NAME mining_template_validation_test COMMAND $<TARGET_FILE:mining_template_validation_test>)

# ChaCha20-Poly1305 AEAD Unit Test
add_executable(chacha20_test chacha20_test.cpp)
target_link_libraries(chacha20_test PRIVATE protocol spdlog ${OPENSSL_LIBRARIES})
target_include_directories(chacha20_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# Falcon Quantum Tunnel Vector parity + benchmark test
add_executable(falcon_qtv_parity_test falcon_qtv_parity_test.cpp)
target_link_libraries(falcon_qtv_parity_test PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(falcon_qtv_parity_test PRIVATE
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

# Deterministic first-block acceptance harness
add_executable(first_block_acceptance_test
    first_block_acceptance_test.cpp
    ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp)
target_link_libraries(first_block_acceptance_test PRIVATE protocol network LLP asio spdlog ${OPENSSL_LIBRARIES})
target_include_directories(first_block_acceptance_test PRIVATE
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

# Solo auth/session resync regression tests
add_executable(solo_auth_resync_test solo_auth_resync_test.cpp)
target_link_libraries(solo_auth_resync_test PRIVATE protocol spdlog)
target_include_directories(solo_auth_resync_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src
)

# Register all test executables with CTest
add_test(NAME chacha20_test COMMAND $<TARGET_FILE:chacha20_test>)
add_test(NAME falcon_qtv_parity_test COMMAND $<TARGET_FILE:falcon_qtv_parity_test>)
add_test(NAME genesis_serialization_utils_test COMMAND $<TARGET_FILE:genesis_serialization_utils_test>)
add_test(NAME height_tracker_test COMMAND $<TARGET_FILE:height_tracker_test>)
add_test(NAME packet_builder_test COMMAND $<TARGET_FILE:packet_builder_test>)
add_test(NAME phase2b_update_height_test COMMAND $<TARGET_FILE:phase2b_update_height_test>)
add_test(NAME keepalive_v2_test COMMAND $<TARGET_FILE:keepalive_v2_test>)
add_test(NAME push_notification_lane_test COMMAND $<TARGET_FILE:push_notification_lane_test>)
add_test(NAME session_status_wire_test COMMAND $<TARGET_FILE:session_status_wire_test>)
add_test(NAME stateless_block_utility_test COMMAND $<TARGET_FILE:stateless_block_utility_test>)
add_test(NAME e2e_block_submission_test COMMAND $<TARGET_FILE:e2e_block_submission_test>)
add_test(NAME first_block_acceptance_test COMMAND $<TARGET_FILE:first_block_acceptance_test>)
add_test(NAME mined_block_cache_dedup_test COMMAND $<TARGET_FILE:mined_block_cache_dedup_test>)
add_test(NAME node_shutdown_wire_test COMMAND $<TARGET_FILE:node_shutdown_wire_test>)
add_test(NAME get_block_dedup_recovery_test COMMAND $<TARGET_FILE:get_block_dedup_recovery_test>)
add_test(NAME solo_auth_resync_test COMMAND $<TARGET_FILE:solo_auth_resync_test>)
# SESSION_START packet parser unit tests
add_executable(session_start_parser_test session_start_parser_test.cpp)
target_link_libraries(session_start_parser_test PRIVATE protocol)
target_include_directories(session_start_parser_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src
)

# NodeSessionContext unit tests
add_executable(node_session_context_test node_session_context_test.cpp)
target_link_libraries(node_session_context_test PRIVATE protocol network asio spdlog)
target_include_directories(node_session_context_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME node_session_context_test COMMAND $<TARGET_FILE:node_session_context_test>)
