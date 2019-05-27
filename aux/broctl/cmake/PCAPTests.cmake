include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckIncludeFiles)

set(CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})

cmake_policy(PUSH)

if ( POLICY CMP0075 )
    # It's fine that check_include_files links against CMAKE_REQUIRED_LIBRARIES
    cmake_policy(SET CMP0075 NEW)
endif ()

check_include_files(pcap-int.h HAVE_PCAP_INT_H)

cmake_policy(POP)

check_function_exists(pcap_freecode HAVE_LIBPCAP_PCAP_FREECODE)
if (NOT HAVE_LIBPCAP_PCAP_FREECODE)
    set(DONT_HAVE_LIBPCAP_PCAP_FREECODE true)
    message(STATUS "No implementation for pcap_freecode()")
endif ()

check_c_source_compiles("
#include <pcap.h>
int main () {
    int snaplen;
    int linktype;
    struct bpf_program fp;
    int optimize;
    bpf_u_int32 netmask;
    char str[10];
    char error[1024];
    snaplen = 50;
    linktype = DLT_EN10MB;
    optimize = 1;
    netmask = 0L;
    str[0] = 'i'; str[1] = 'p'; str[2] = '\\\\0';
    (void)pcap_compile_nopcap(
        snaplen, linktype, &fp, str, optimize, netmask, &error);
    return 0;
}
" LIBPCAP_PCAP_COMPILE_NOPCAP_HAS_ERROR_PARAMETER)
if (NOT LIBPCAP_PCAP_COMPILE_NOPCAP_HAS_ERROR_PARAMETER)
    # double check
    check_c_source_compiles("
#include <pcap.h>
int main () {
    int snaplen;
    int linktype;
    struct bpf_program fp;
    int optimize;
    bpf_u_int32 netmask;
    char str[10];
    snaplen = 50;
    linktype = DLT_EN10MB;
    optimize = 1;
    netmask = 0L;
    str[0] = 'i'; str[1] = 'p'; str[2] = '\\\\0';
    (void)pcap_compile_nopcap(snaplen, linktype, &fp, str, optimize, netmask);
    return 0;
}
" LIBPCAP_PCAP_COMPILE_NOPCAP_NO_ERROR_PARAMETER)
    if (NOT LIBPCAP_PCAP_COMPILE_NOPCAP_NO_ERROR_PARAMETER)
        message(FATAL_ERROR
            "Can't determine if pcap_compile_nopcap takes an error parameter")
    endif ()
endif ()

check_symbol_exists(DLT_PPP_SERIAL pcap.h HAVE_DLT_PPP_SERIAL)
if (NOT HAVE_DLT_PPP_SERIAL)
    set(DLT_PPP_SERIAL 50)
endif ()

set(CMAKE_REQUIRED_INCLUDES)
set(CMAKE_REQUIRED_LIBRARIES)
