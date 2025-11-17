cmake_minimum_required(VERSION 3.19)

# Falcon library C sources
set(FALCON_SOURCES
    falcon/codec.c
    falcon/common.c
    falcon/falcon.c
    falcon/fft.c
    falcon/fpr.c
    falcon/keygen.c
    falcon/rng.c
    falcon/shake.c
    falcon/sign.c
    falcon/vrfy.c
)

# Set language for Falcon C files
set_source_files_properties(${FALCON_SOURCES} PROPERTIES LANGUAGE C)

add_library(LLC STATIC  src/LLC/hash/SK/skein.cpp
                        src/LLC/hash/SK/KeccakSponge.cpp
                        src/LLC/hash/SK/KeccakHash.cpp 
                        src/LLC/hash/SK/skein_block.cpp 
                        src/LLC/types/base_uint.cpp 
                        src/LLC/hash/SK/Keccak-compact64.cpp
                        src/LLC/types/bignum.cpp
                        src/LLC/flkey.cpp
                        ${FALCON_SOURCES})
                    
target_include_directories(LLC
    PUBLIC 
        $<INSTALL_INTERFACE:inc>    
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../>
    PRIVATE src
    PRIVATE falcon
)

target_link_libraries(LLC OpenSSL::Crypto OpenSSL::applink)
if(WIN32 AND STATIC_OPENSSL)
    target_link_libraries(LLC crypt32.lib)
endif()
