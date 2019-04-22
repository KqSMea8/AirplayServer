cmake_minimum_required(VERSION 3.4.1)


include_directories( /opt/vc/include/ 
	/opt/vc/include/interface/vcos/pthreads 
	/opt/vc/include/interface/vmcs_host/linux 
	/opt/vc/src/hello_pi/libs/ilclient )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSTANDALONE -D__STDC_CONSTANT_MACROS -D__STDC_LIMIT_MACROS -DTARGET_POSIX -D_LINUX -fPIC -DPIC -D_REENTRANT -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -Wall -g -DHAVE_LIBOPENMAX=2 -DOMX -DOMX_SKIP64BIT -ftree-vectorize -pipe -DUSE_EXTERNAL_OMX -DHAVE_LIBBCM_HOST -DUSE_EXTERNAL_LIBBCM_HOST -DUSE_VCHIQ_ARM -Wno-psabi")

aux_source_directory(/opt/vc/src/hello_pi/libs/ilclient/ ilclient_src)
set(DIR_SRCS ${ilclient_src})
add_library( ilclient
        STATIC
        ${DIR_SRCS})
target_link_libraries( ilclient brcmGLESv2 brcmEGL openmaxil bcm_host vcos vchiq_arm pthread rt m ) 

aux_source_directory(. renderers_src)
set(DIR_SRCS ${renderers_src})
add_library( renderers
        STATIC
        ${DIR_SRCS})
target_link_libraries ( renderers ilclient )