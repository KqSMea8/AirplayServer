cmake_minimum_required(VERSION 3.4.1)

add_subdirectory(src/main/cpp/lib/crypto)
add_subdirectory(src/main/cpp/lib/curve25519)
add_subdirectory(src/main/cpp/lib/ed25519)
add_subdirectory(src/main/cpp/lib/playfair)
add_subdirectory(src/main/cpp/lib/plist)
add_subdirectory(src/main/cpp/lib/fdk-aac)
add_subdirectory(src/main/cpp/lib)

include_directories(lib
        lib/fdk-aac/libAACdec/include
        lib/fdk-aac/libAACenc/include
        lib/fdk-aac/libFDK/include
        lib/fdk-aac/libMpegTPDec/include
        lib/fdk-aac/libMpegTPEnc/include
        lib/fdk-aac/libPCMutils/include
        lib/fdk-aac/libSBRdec/include
        lib/fdk-aac/libSBRenc/include
        lib/fdk-aac/libSYS/include

        lib/fdk-aac/libArithCoding/include
        lib/fdk-aac/libDRCdec/include
        lib/fdk-aac/libSACdec/include
        lib/fdk-aac/libSACenc/include)
add_library( raop_server
        SHARED
        src/main/cpp/jni_raop_server.cpp )
add_subdirectory(src/main/cpp/mDNSResponder)
find_library( log-lib
              log )

target_link_libraries( raop_server
                       ${log-lib}
        play-lib
        jdns_sd
        ed25519
        fdk-aac)