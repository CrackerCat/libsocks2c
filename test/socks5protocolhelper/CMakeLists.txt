cmake_minimum_required (VERSION 3.12)
project (Test)

add_executable(Test
        test.cpp
        ../../src/protocol/socks5/socks5_protocol.h
        ../../src/protocol/socks5/socks5_protocol_helper.h
        ../../src/protocol/socks5/socks5_protocol_helper.cpp
        )

target_link_libraries(Test "/usr/local/lib/libboost_thread.a")
target_link_libraries(Test "/usr/local/lib/libboost_regex.a")
