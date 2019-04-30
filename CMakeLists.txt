cmake_minimum_required(VERSION 3.12)
project(libsocks2c)

OPTION(BUILD_SERVER_LIB "" OFF)
OPTION(BUILD_CLIENT_LIB "" OFF)
OPTION(BUILD_NETUNNEL_SERVER "netunnel" OFF)
OPTION(ENABLE_UOUT "whether build with UDP Over UTCP feature" OFF)
OPTION(BUILD_IOS_LIB "build ios lib" OFF)

IF (ENABLE_UOUT)
    add_definitions(-DUDP_OVER_UTCP)
ENDIF()

add_definitions(-DPROTOCOL_AES256GCM)

add_definitions(-DDISABLE_DEBUG_LOG)
#add_definitions(-DLOG_DEBUG_DETAIL)
#add_definitions(-DUDP_DEBUG_DETAIL)
#add_definitions(-DTCP_DEBUG_DETAIL)
add_definitions(-DMULTITHREAD_IO)
add_definitions(-DSINGLETON_RAW_POINTER)
add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
set(CMAKE_CXX_STANDARD 17)

#include headers
IF (WIN32)
  add_definitions(-DTINS_STATIC)
  add_definitions(-D_WIN32_WINNT=0x0A00)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
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
        #include_directories("/root/spdlog-1.3.1/include")
    ENDIF()
    include_directories("/usr/local/include")
ENDIF()

SET(CORE_FILES
        lib/libsocks2c.cpp
        lib/libsocks2c.h
        src/protocol/socks5/socks5_protocol.h
        src/protocol/socks5/socks5_protocol_helper.cpp
        src/protocol/socks5/socks5_protocol_helper.h
        src/netio/basic_network_io_mt.h
        src/netio/basic_network_io_mt.cpp

		src/state/globalstate.h

        src/utils/logger.cpp
        src/utils/logger.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf.h
        src/protocol/basic_protocol/iproxy_protocol.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf_helper.h
        src/protocol/basic_protocol/client_proxy_protocol.h
        src/utils/randomNumberGenerator.cpp
        src/utils/randomNumberGenerator.h
        src/protocol/basic_protocol/server_proxy_protocol.h

        src/protocol/basic_protocol/protocol_def.h

        src/protocol/custom/chacha20/chacha20.h
        src/protocol/custom/chacha20/chacha20_helper.h
        src/utils/trafficcounter.cpp

        lib/server_proxymap.h
        src/utils/singleton.h
		src/net/udp/bufferqueue.h
        src/utils/macro_def.h
        src/protocol/custom/netunnel-aes256gcmwithobf/netunnel_protocol.h
        src/protocol/custom/netunnel-aes256gcmwithobf/netunnel_protocol_helper.h
        src/utils/sqlhost.h
        src/factory/client_factory.h
        src/factory/server_factory.h
        lib/client_proxymap.h
        src/net/raw/server/buffersize_def.h
        )

IF(BUILD_CLIENT_LIB)
message("Build Client")
add_definitions(-DBUILD_CLIENT_LIB)
LIST(APPEND CORE_FIELS
        src/net/tcp/client/client_tcp_proxy.h
        src/net/tcp/client/client_tcp_proxy_session.h

        src/net/udp/client/client_udp_proxy.h
        src/net/udp/client/client_udp_proxy_session.h)
ENDIF()


IF(BUILD_NETUNNEL_SERVER)
    message("configure Netunnel server")
    IF (NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
        MESSAGE(FATAL_ERROR "Netunnel server can only build on linux")
    ENDIF()
    add_definitions(-DBUILD_SERVER_LIB)

    LIST(APPEND CORE_FILES
        src/protocol/custom/netunnel-aes256gcmwithobf/userstatistic/statistic_helper.cpp
        src/protocol/custom/netunnel-aes256gcmwithobf/userstatistic/statistic_helper.h
        src/protocol/custom/netunnel-aes256gcmwithobf/user_info.h)
ENDIF()

IF(BUILD_SERVER_LIB)
    message("Build server")
    add_definitions(-DBUILD_SERVER_LIB)
    LIST(APPEND CORE_FILES
            src/net/tcp/server/server_tcp_proxy.h
            src/net/tcp/server/server_tcp_proxy_session.h
            src/net/tcp/server/server_tcp_proxy_mt.h

            src/net/udp/server/server_udp_proxy.h
            src/net/udp/server/server_udp_proxy_session.h)
ENDIF()


IF (ENABLE_UOUT)
    message("Build uout")

    LIST(APPEND CORE_FILES
        src/net/raw/raw_proxy_helper/interface_helper.h
        src/net/raw/raw_proxy_helper/interface_helper.cpp
        src/net/raw/server/raw_udp_session.h
        src/net/raw/server/server_udp_raw_proxy.h
        src/net/raw/raw_socket.h
        src/net/raw/client/client_udp_raw_proxy.h
        src/net/udp/client/client_udp_proxy_withraw.h
        src/net/raw/server/server_udp_raw_proxy_session.h
        src/net/raw/raw_proxy_helper/firewall_helper.h
        src/net/raw/raw_proxy_helper/firewall_helper.cpp
        src/utils/system/system_exec.h
        src/net/raw/sniffer_def.h
        src/net/raw/client/basic_client_udp_raw_proxy.h
        src/net/raw/raw_proxy_helper/tcp_checksum_helper.h
        src/net/raw/raw_proxy_helper/tcp_checksum_helper.cpp
		src/net/raw/raw_proxy_helper/port_usable_checker.h
        src/net/raw/raw_proxy_helper/port_usable_checker.cpp)
    IF(WIN32)
        LIST(APPEND CORE_FILES src/net/raw/client/client_udp_raw_proxy_win32.h)
    ENDIF()
ENDIF()

#add_library(libsocks2c ${CORE_FILES})
LIST(APPEND CORE_FILES main.cpp)
add_executable(libsocks2c ${CORE_FILES})
set_target_properties(libsocks2c PROPERTIES PREFIX "")

#link libs and platform specific source file
IF (WIN32)
    IF (ENABLE_UOUT)
        #target_link_libraries(libsocks2c "C:/WpdPack/Lib/x64/Packet.lib")
        target_link_libraries(libsocks2c "C:/WpdPack/Lib/x64/wpcap.lib")
        target_link_libraries(libsocks2c "C:/lib/debug/tins.lib")
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

IF(NOT BUILD_IOS_LIBRARY)
#    set(Boost_USE_STATIC_LIBS ON)
#    set(Boost_USE_MULTITHREADED ON)
#    set(Boost_USE_STATIC_RUNTIME OFF)
#    find_package(Boost 1.70.0 REQUIRED system filesystem coroutine context regex thread)
#
#    if (Boost_FOUND)
#        include_directories(${Boost_INCLUDE_DIRS})
#        target_link_libraries(libsocks2c ${Boost_LIBRARIES})
#    endif ()

	IF(WIN32)
		include_directories("C:/Boost/include/boost-1_70")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_regex-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_context-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_coroutine-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_context-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_date_time-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_thread-vc142-mt-x64-1_70.lib")
#		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_chrono-vc142-mt-x64-1_70.lib")
		
		
		
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_regex-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_context-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_coroutine-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_context-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_date_time-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_thread-vc142-mt-gd-x64-1_70.lib")
		target_link_libraries(libsocks2c "C:/Boost/lib/libboost_chrono-vc142-mt-gd-x64-1_70.lib")
	ELSE()
	    target_link_libraries(libsocks2c "/usr/local/lib/libboost_thread.a")
		target_link_libraries(libsocks2c "/usr/local/lib/libboost_regex.a")
		target_link_libraries(libsocks2c "/usr/local/lib/libboost_coroutine.a")
        target_link_libraries(libsocks2c "/usr/local/lib/libboost_context.a")
        target_link_libraries(libsocks2c "/usr/local/lib/libboost_filesystem.a")
	ENDIF()
ENDIF()


IF(BUILD_NETUNNEL_SERVER)
    message("Build netunnelserver, removing client definition")
    remove_definitions(-DBUILD_CLIENT_LIB)
    add_definitions(-DBUILD_NETUNNEL_SERVER)
    add_definitions(-DBOOST_HANA_CONFIG_ENABLE_STRING_UDL)
    include_directories(/home/mariolau/Desktop/ozo-master/include)
    include_directories(/usr/include/postgresql)
    target_link_libraries(libsocks2c pq)
ENDIF()

if (BUILD_IOS_LIB)
    set(ENABLE_UOUT, OFF)
    remove_definitions(-DUDP_OVER_UTCP)
    remove_definitions(-DBUILD_SERVER_LIB)
    remove_definitions(-DMULTITHREAD_IO)
endif()


IF(BUILD_TESTING)
	add_subdirectory(test/socks5protocolhelper)
	enable_testing()
	add_test(NAME Socks5ProtocolHelper COMMAND Test)
ENDIF()


