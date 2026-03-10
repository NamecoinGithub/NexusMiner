add_library(LLP INTERFACE)
target_include_directories(LLP INTERFACE .)

target_link_libraries(LLP INTERFACE network LLC)

# Unit tests for LLP packet framing and protocol-lane wire behavior
add_executable(packet_framing_test packet_framing_test.cpp)
target_link_libraries(packet_framing_test PRIVATE LLP)
target_include_directories(packet_framing_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME packet_framing_test COMMAND $<TARGET_FILE:packet_framing_test>)

add_executable(protocol_lane_header_test protocol_lane_header_test.cpp)
target_link_libraries(protocol_lane_header_test PRIVATE LLP)
target_include_directories(protocol_lane_header_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
add_test(NAME protocol_lane_header_test COMMAND $<TARGET_FILE:protocol_lane_header_test>)
