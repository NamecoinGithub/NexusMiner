add_library(config STATIC "src/config/config.cpp"
                          "src/config/validator.cpp"
                          "src/config/toml_config.cpp"
                          "src/config/miner_config.cpp")
                    
target_include_directories(config
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(config spdlog nlohmann_json::nlohmann_json LLC)