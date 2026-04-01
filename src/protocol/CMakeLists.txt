add_library(protocol STATIC src/protocol/solo.cpp
                            src/protocol/pool_base.cpp
                            src/protocol/falcon_wrapper.cpp
                            src/protocol/chacha20_wrapper.cpp
                            src/protocol/session_manager.cpp
                            src/protocol/node_session_context.cpp
                            src/protocol/mining_template_interface.cpp
                            src/protocol/push_notification_handler.cpp
                            src/protocol/height_tracker.cpp
                            src/protocol/packet_builder.cpp
                            src/protocol/epoch_coordinator.cpp
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

# ============================================================================
# Common include-path sets for protocol tests
# ============================================================================
set(PROTOCOL_TEST_INCLUDES_MINIMAL
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src
)
set(PROTOCOL_TEST_INCLUDES_LLP
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src
)
set(PROTOCOL_TEST_INCLUDES_FULL
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src/LLP/include
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
    ${CMAKE_SOURCE_DIR}/src
)

# ============================================================================
# Protocol test executables
# ============================================================================

add_nexusminer_test(
    NAME     mining_template_validation_test
    SOURCES  mining_template_validation_test.cpp
    LIBS     protocol LLP TAO spdlog
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
             ${CMAKE_SOURCE_DIR}/src/LLP/inc
             ${CMAKE_SOURCE_DIR}/src/TAO/inc
)

add_nexusminer_test(
    NAME     chacha20_test
    SOURCES  chacha20_test.cpp
    LIBS     protocol spdlog ${OPENSSL_LIBRARIES}
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

add_nexusminer_test(
    NAME     falcon_qtv_parity_test
    SOURCES  falcon_qtv_parity_test.cpp
    LIBS     ${OPENSSL_LIBRARIES}
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

add_nexusminer_test(
    NAME     genesis_serialization_utils_test
    SOURCES  genesis_serialization_utils_test.cpp
    LIBS     protocol
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

add_nexusminer_test(
    NAME     height_tracker_test
    SOURCES  height_tracker_test.cpp
    LIBS     protocol
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
             ${CMAKE_SOURCE_DIR}/src/LLC/inc
)

add_nexusminer_test(
    NAME     packet_builder_test
    SOURCES  packet_builder_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     phase2b_update_height_test
    SOURCES  phase2b_update_height_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     keepalive_v2_test
    SOURCES  keepalive_v2_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     push_notification_lane_test
    SOURCES  push_notification_lane_test.cpp ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp
    LIBS     protocol LLP LLC spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     session_status_wire_test
    SOURCES  session_status_wire_test.cpp
    LIBS     LLP
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     stateless_block_utility_test
    SOURCES  stateless_block_utility_test.cpp ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_FULL}
)

add_nexusminer_test(
    NAME     e2e_block_submission_test
    SOURCES  e2e_block_submission_test.cpp ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp
    LIBS     protocol LLP spdlog ${OPENSSL_LIBRARIES}
    INCLUDES ${PROTOCOL_TEST_INCLUDES_FULL}
)

add_nexusminer_test(
    NAME     first_block_acceptance_test
    SOURCES  first_block_acceptance_test.cpp ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp
    LIBS     protocol network LLP asio spdlog ${OPENSSL_LIBRARIES}
    INCLUDES ${PROTOCOL_TEST_INCLUDES_FULL}
)

add_nexusminer_test(
    NAME     mined_block_cache_dedup_test
    SOURCES  ${CMAKE_SOURCE_DIR}/src/stats/mined_block_cache_test.cpp
    LIBS     protocol LLP stats spdlog
    INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/inc
             ${CMAKE_SOURCE_DIR}/src/LLP/inc
             ${CMAKE_SOURCE_DIR}/src/LLP
             ${CMAKE_SOURCE_DIR}/src/stats/inc
             ${CMAKE_SOURCE_DIR}/src/LLC/inc
             ${CMAKE_SOURCE_DIR}/src
)

add_nexusminer_test(
    NAME     node_shutdown_wire_test
    SOURCES  node_shutdown_wire_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     get_block_dedup_recovery_test
    SOURCES  get_block_dedup_recovery_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     degraded_recovery_test
    SOURCES  degraded_recovery_test.cpp
    LIBS     protocol LLP spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)

add_nexusminer_test(
    NAME     solo_auth_resync_test
    SOURCES  solo_auth_resync_test.cpp
    LIBS     protocol spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_MINIMAL}
)

add_nexusminer_test(
    NAME     packet_ingress_preflight_test
    SOURCES  packet_ingress_preflight_test.cpp
    LIBS     protocol network asio spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_MINIMAL}
)

add_nexusminer_test(
    NAME     session_start_parser_test
    SOURCES  session_start_parser_test.cpp
    LIBS     protocol
    INCLUDES ${PROTOCOL_TEST_INCLUDES_MINIMAL}
)

add_nexusminer_test(
    NAME     node_session_context_test
    SOURCES  node_session_context_test.cpp
    LIBS     protocol network asio spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_MINIMAL}
)

add_nexusminer_test(
    NAME     epoch_coordinator_test
    SOURCES  epoch_coordinator_test.cpp
    LIBS     protocol network asio spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_MINIMAL}
)

add_nexusminer_test(
    NAME     fork_vs_tip_change_test
    SOURCES  fork_vs_tip_change_test.cpp
    LIBS     protocol LLP LLC spdlog
    INCLUDES ${PROTOCOL_TEST_INCLUDES_LLP}
)
