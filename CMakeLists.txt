cmake_minimum_required(VERSION 3.12)
project(libsocks2c)

OPTION(ENABLE_UOUT "whether build with UDP Over UTCP feature" OFF)
IF (ENABLE_UOUT)
    add_definitions(-DUDP_OVER_UTCP)
ENDIF()

add_definitions(-DPROTOCOL_CHACHA20)
#add_definitions(-DDISABLE_DEBUG_LOG)
add_definitions(-DLOG_DEBUG_DETAIL)
add_definitions(-DUDP_DEBUG_DETAIL)
#add_definitions(-DTCP_DEBUG_DETAIL)
add_definitions(-DMULTITHREAD_IO)
add_definitions(-DSINGLETON_RAW_POINTER)
add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
set(CMAKE_CXX_STANDARD 14)

#include headers
IF (WIN32)
  add_definitions(-D_WIN32_WINNT=0x0A00)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-DSODIUM_STATIC)
  add_definitions(-DBUILD_DLL)
  IF (ENABLE_UOUT)
      include_directories("C:/WpdPack/Include")
      include_directories("C:/WinDivert-1.4.3-A/include")
  ENDIF()
  include_directories("C:/include")
ELSE()
    IF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
        #all in include_directories("/usr/local/include")
    ELSEIF(CMAKE_SYSTEM_NAME MATCHES "Linux")
        include_directories("/root/spdlog-1.3.1/include")
    ENDIF()
    include_directories("/usr/local/include")
ENDIF()

SET(CORE_FILES
        main.cpp
        lib/libsocks2c.cpp
        lib/libsocks2c.h
        src/protocol/socks5_protocol.h
        src/protocol/socks5_protocol_helper.cpp
        src/protocol/socks5_protocol_helper.h
        src/netio/basic_network_io.h
        src/netio/basic_network_io_mt.h
        src/netio/basic_network_io_mt.cpp
        src/net/tcp/client/client_tcp_proxy.h
        src/net/tcp/client/client_tcp_proxy_session.h

        src/net/udp/client/client_udp_proxy.h
        src/net/udp/client/client_udp_proxy_session.h

        src/utils/logger.cpp
        src/utils/logger.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf.h
        src/protocol/iproxy_protocol.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf_helper.h
        src/protocol/client_proxy_protocol.h src/utils/randomNumberGenerator.cpp
        src/utils/randomNumberGenerator.h src/protocol/server_proxy_protocol.h

        src/net/tcp/server/server_tcp_proxy.h
        src/net/tcp/server/server_tcp_proxy_session.h
        src/net/tcp/server/server_tcp_proxy_mt.h

        src/net/udp/server/server_udp_proxy.h
        src/net/udp/server/server_udp_proxy_session.h
        src/protocol/protocol_def.h

        src/protocol/custom/chacha20/chacha20.h
        src/protocol/custom/chacha20/chacha20_helper.h
        src/utils/trafficcounter.cpp
		src/utils/cacheline_helper.c

        lib/proxymap.h
        src/utils/singleton.h
        lib/version.h
		src/net/udp/bufferqueue.h
        src/utils/macro_def.h
        )



IF (ENABLE_UOUT)
LIST(APPEND CORE_FILES
        src/net/raw/server/server_udp_raw_proxy.h
        src/net/raw/raw_socket.h
        src/net/raw/client/client_udp_raw_proxy.h
        src/net/udp/client/client_udp_proxy_withraw.h
        src/net/raw/server/server_udp_raw_proxy_session.h
        src/net/raw/raw_proxy_helper/interface_helper.h
        src/net/raw/raw_proxy_helper/interface_helper.cpp
        src/net/raw/raw_proxy_helper/firewall_helper.h
        src/net/raw/raw_proxy_helper/firewall_helper.cpp
        src/utils/system/system_exec.h
        src/net/raw/sniffer_def.h
        src/net/raw/client/basic_client_udp_raw_proxy.h
        src/net/raw/raw_proxy_helper/tcp_checksum_helper.h
        src/net/raw/raw_proxy_helper/tcp_checksum_helper.cpp)
    IF(WIN32)
        LIST(APPEND CORE_FILES src/net/raw/client/client_udp_raw_proxy_win32.h)
    ENDIF()
ENDIF()

add_executable(libsocks2c ${CORE_FILES})
set_target_properties(libsocks2c PROPERTIES PREFIX "")

#link libs and platform specific source file
IF (WIN32)
    IF (ENABLE_UOUT)
        #target_link_libraries(libsocks2c "C:/WpdPack/Lib/x64/Packet.lib")
        target_link_libraries(libsocks2c "C:/WpdPack/Lib/x64/wpcap.lib")
        target_link_libraries(libsocks2c "C:/lib/tins.lib")
        target_link_libraries(libsocks2c "C:/WinDivert-1.4.3-A/x86_64/WinDivert.lib")
    ENDIF()
        target_link_libraries(libsocks2c "C:/lib/libsodium.lib")
ELSE()
    target_link_libraries(libsocks2c pthread)
    target_link_libraries(libsocks2c "/usr/local/lib/libsodium.a")
    IF (ENABLE_UOUT)
        IF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
            target_link_libraries(libsocks2c "/usr/local/lib/libtins.dylib")
            target_link_libraries(libsocks2c "/usr/local/lib/libpcap.dylib")
        ELSEIF(CMAKE_SYSTEM_NAME MATCHES "Linux")
            target_link_libraries(libsocks2c "/usr/local/lib/libtins.so")
            target_link_libraries(libsocks2c "/usr/local/lib/libpcap.so")
        ENDIF()
    ENDIF()
ENDIF()

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.68.0 REQUIRED system filesystem coroutine context regex thread)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(libsocks2c ${Boost_LIBRARIES})
endif ()



