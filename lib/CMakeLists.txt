cmake_minimum_required(VERSION 3.4.1)
include_directories( curve25519 ed25519 playfair plist/plist )


aux_source_directory(. play_src)
set(DIR_SRCS ${play_src})

add_library( play-lib
        SHARED
        ${DIR_SRCS}
        )

find_package(OpenSSL REQUIRED)

target_link_libraries( play-lib
        OpenSSL::Crypto
	    pthread
        curve25519
        ed25519
        playfair
        plist )

if( UNIX AND NOT APPLE )
target_link_libraries( play-lib
		dns_sd )
endif()
        