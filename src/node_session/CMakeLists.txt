add_library(node_session STATIC src/node_session/node_session.cpp)

target_include_directories(node_session
    PUBLIC
        $<INSTALL_INTERFACE:inc>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/LLP/include
        ${CMAKE_SOURCE_DIR}/src/LLP
)

target_link_libraries(node_session
    PUBLIC
        network
        protocol
    PRIVATE
        config
        LLP
        spdlog
)

# Unit tests for NodeSession
add_executable(node_session_test node_session_test.cpp
    ${CMAKE_SOURCE_DIR}/src/miner_keys.cpp)
target_link_libraries(node_session_test PRIVATE node_session protocol network config stats spdlog LLC)
target_include_directories(node_session_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/src/LLP
    ${CMAKE_SOURCE_DIR}/src/LLP/include
    ${CMAKE_SOURCE_DIR}/src/protocol/inc
    ${CMAKE_SOURCE_DIR}/src/network/inc
    ${CMAKE_SOURCE_DIR}/src/config/inc
    ${CMAKE_SOURCE_DIR}/src/stats/inc
    ${CMAKE_SOURCE_DIR}/src/LLC/inc
    ${CMAKE_SOURCE_DIR}/src
)

# Register test with CTest
add_test(NAME node_session_test COMMAND $<TARGET_FILE:node_session_test>)
