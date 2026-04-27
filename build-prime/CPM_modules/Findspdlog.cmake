include("/home/runner/work/NexusMiner/NexusMiner/cmake/CPM.cmake")
CPMAddPackage("NAME;spdlog;GITHUB_REPOSITORY;gabime/spdlog;VERSION;1.13.0;OPTIONS;SPDLOG_BUILD_SHARED OFF")
set(spdlog_FOUND TRUE)