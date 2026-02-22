cmake_minimum_required(VERSION 3.19)

add_library(protocol STATIC src/protocol/solo.cpp
                            src/protocol/pool_base.cpp
                            src/protocol/falcon_wrapper.cpp
                            src/protocol/chacha20_wrapper.cpp
                            src/protocol/session_manager.cpp
                            src/protocol/mining_template_interface.cpp
                            src/protocol/push_notification_handler.cpp
                            src/protocol/height_tracker.cpp)
                    
target_include_directories(protocol
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/Util/include
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

# HeightTracker Unit Test
add_executable(height_tracker_test height_tracker_test.cpp)
target_link_libraries(height_tracker_test PRIVATE protocol)
target_include_directories(height_tracker_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)