# cmake/AddTest.cmake — DRY helper for NexusMiner test executables
#
# Usage:
#   add_nexusminer_test(
#       NAME          my_test
#       SOURCES       my_test.cpp [extra.cpp ...]
#       LIBS          protocol LLP spdlog
#       [INCLUDES     ${CMAKE_SOURCE_DIR}/src/LLP/inc ...]
#   )
#
# Automatically adds:
#   - add_executable / target_link_libraries / target_include_directories / add_test

function(add_nexusminer_test)
    cmake_parse_arguments(
        TEST                        # prefix
        ""                          # options (flags)
        "NAME"                      # single-value keywords
        "SOURCES;LIBS;INCLUDES"     # multi-value keywords
        ${ARGN}
    )

    if(NOT TEST_NAME)
        message(FATAL_ERROR "add_nexusminer_test: NAME is required")
    endif()
    if(NOT TEST_SOURCES)
        message(FATAL_ERROR "add_nexusminer_test(${TEST_NAME}): SOURCES is required")
    endif()

    add_executable(${TEST_NAME} ${TEST_SOURCES})

    if(TEST_LIBS)
        target_link_libraries(${TEST_NAME} PRIVATE ${TEST_LIBS})
    endif()

    if(TEST_INCLUDES)
        target_include_directories(${TEST_NAME} PRIVATE ${TEST_INCLUDES})
    endif()

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)
endfunction()
