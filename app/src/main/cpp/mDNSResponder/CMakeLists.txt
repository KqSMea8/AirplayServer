cmake_minimum_required(VERSION 3.4.1)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -D_GNU_SOURCE -DHAVE_IPV6 -DHAVE_LINUX -DNOT_HAVE_SA_LEN -DPLATFORM_NO_RLIMIT -DTARGET_OS_LINUX -DUSES_NETLINK -DMDNS_DEBUGMSGS=0 -W -Wall -Wextra -Wno-array-bounds -Wno-pointer-sign -Wno-unused -Wno-unused-parameter -Werror=implicit-function-declaration -DANDROID_TOOLCHAIN=clang")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g  -fno-strict-aliasing  -D_GNU_SOURCE  -DHAVE_IPV6  -DHAVE_LINUX  -DNOT_HAVE_SA_LEN  -DPLATFORM_NO_RLIMIT  -DTARGET_OS_LINUX  -DUSES_NETLINK  -DMDNS_DEBUGMSGS=0 -W  -Wall  -Wextra  -Wno-array-bounds  -Wno-pointer-sign  -Wno-unused  -Wno-unused-parameter  -Werror=implicit-function-declaration")
#-DMDNS_UDS_SERVERPATH=\"/dev/socket/mdnsd\"  -DMDNS_USERNAME=\"mdnsr\"
add_definitions(-DMDNS_UDS_SERVERPATH="/dev/socket/mdnsd" )
add_definitions(-DMDNS_USERNAME="mdnsr" )

include_directories(mDNSPosix mDNSCore mDNSShared)
add_library( jdns_sd
        SHARED
        mDNSShared/dnssd_clientlib.c
        mDNSShared/dnssd_clientstub.c
        mDNSShared/dnssd_ipc.c
        JNISupport.c)


