cmake_minimum_required(VERSION 3.4.1)
aux_source_directory(. crypto_src)
set(DIR_SRCS ${crypto_src})
add_library( crypto
        STATIC
        ${DIR_SRCS})