add_library(worker INTERFACE)
target_include_directories(worker INTERFACE .)

target_link_libraries(worker INTERFACE LLP LLC hash)