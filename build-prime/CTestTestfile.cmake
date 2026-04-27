# CMake generated Testfile for 
# Source directory: /home/runner/work/NexusMiner/NexusMiner
# Build directory: /home/runner/work/NexusMiner/NexusMiner/build-prime
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[dual_connection_manager_test]=] "/home/runner/work/NexusMiner/NexusMiner/build-prime/dual_connection_manager_test")
set_tests_properties([=[dual_connection_manager_test]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/NexusMiner/NexusMiner/cmake/AddTest.cmake;51;add_test;/home/runner/work/NexusMiner/NexusMiner/CMakeLists.txt;251;add_nexusminer_test;/home/runner/work/NexusMiner/NexusMiner/CMakeLists.txt;0;")
subdirs("_deps/spdlog-build")
subdirs("_deps/nlohmann_json-build")
subdirs("_deps/primesieve-build")
subdirs("src/chrono")
subdirs("src/network")
subdirs("src/LLP")
subdirs("src/LLC")
subdirs("src/hash")
subdirs("src/worker")
subdirs("src/config")
subdirs("src/stats")
subdirs("src/protocol")
subdirs("src/node_session")
subdirs("src/cpu")
subdirs("src/fpga")
subdirs("src/TAO")
subdirs("src/tools")
