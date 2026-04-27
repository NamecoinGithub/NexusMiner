#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "primesieve::libprimesieve" for configuration "Release"
set_property(TARGET primesieve::libprimesieve APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(primesieve::libprimesieve PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libprimesieve.so.12.14"
  IMPORTED_SONAME_RELEASE "libprimesieve.so.12"
  )

list(APPEND _cmake_import_check_targets primesieve::libprimesieve )
list(APPEND _cmake_import_check_files_for_primesieve::libprimesieve "${_IMPORT_PREFIX}/lib/libprimesieve.so.12.14" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
