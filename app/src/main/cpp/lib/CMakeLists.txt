cmake_minimum_required(VERSION 3.4.1)
include_directories(crypto curve25519 ed25519 playfair plist/plist
        fdk-aac/libAACdec/include
        fdk-aac/libAACenc/include
        fdk-aac/libFDK/include
        fdk-aac/libMpegTPDec/include
        fdk-aac/libMpegTPEnc/include
        fdk-aac/libPCMutils/include
        fdk-aac/libSBRdec/include
        fdk-aac/libSBRenc/include
        fdk-aac/libSYS/include
        #fdk-aac/libArithCoding/include
        #fdk-aac/libDRCdec/include
        #fdk-aac/libSACdec/include
        #fdk-aac/libSACenc/include
        )


aux_source_directory(. play_src)
set(DIR_SRCS ${play_src})

add_library( play-lib
        SHARED
        ${DIR_SRCS}
        )
find_library( log-lib
        log )
target_link_libraries( play-lib
        crypto
        curve25519
        ed25519
        playfair
        plist
        fdk-aac
        ${log-lib})