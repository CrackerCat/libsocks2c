cmake_minimum_required(VERSION 3.10)
project(socks2c_core)

add_definitions(-DPROTOCOL_CHACHA20)
add_definitions(-DLOG_DEBUG_DETAIL)
add_definitions(-DMULTITHREAD_IO)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS '-fPIC')
set(CMAKE_C_FLAGS '-fPIC')

include_directories("/usr/local/include")
IF (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    include_directories("/Users/mario/Documents/spdlog-1.2.1/include")
ELSEIF(CMAKE_SYSTEM_NAME MATCHES "Linux")
    include_directories("/root/spdlog-1.2.1/include")
ENDIF()


add_executable(socks2c_core
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

        src/utils/Singleton.h src/utils/logger.cpp
        src/utils/logger.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf.h
        src/protocol/iproxy_protocol.h
        src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf_helper.h
        src/protocol/client_proxy_protocol.h src/utils/randomNumberGenerator.cpp
        src/utils/randomNumberGenerator.h src/protocol/server_proxy_protocol.h
        src/net/tcp/client/client_tcp_proxy_mt.h
        include/socks2c.h

        src/net/tcp/server/server_tcp_proxy.h
        src/net/tcp/server/server_tcp_proxy_session.h
        src/net/tcp/server/server_tcp_proxy_mt.h

        src/net/udp/server/server_udp_proxy.h
        src/net/udp/server/server_udp_proxy_session.h

        src/protocol/custom/chacha20/chacha20.h
        src/protocol/custom/chacha20/chacha20_helper.h
        src/utils/trafficcounter.cpp src/net/udp/fec.cpp src/net/udp/fec.h test/multiservertest.h test/multiservertestwithmultiio.h test/runclient.h)


target_link_libraries(socks2c_core pthread)

target_link_libraries(socks2c_core "/usr/local/lib/libsodium.a")

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.68.0 REQUIRED system coroutine regex thread)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(socks2c_core ${Boost_LIBRARIES})
endif ()



