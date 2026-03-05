add_library(LLP INTERFACE)
target_include_directories(LLP INTERFACE .)

target_link_libraries(LLP INTERFACE network LLC)