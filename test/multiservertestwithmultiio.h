#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/bind.hpp>
#include <thread>

#include "../lib/libsocks2c.h"

// all proxyserver or session timeout in 5s
const int timeout = 5;

void AsyncRun(boost::asio::io_context server_io[4])
{
    for (int i = 0; i < 4; ++i) {
        std::thread t(boost::bind(&boost::asio::io_context::run, &server_io[i]));
        t.detach();
    }

}


void test()
{

    {

        boost::asio::io_context io[4];

        for (int i = 0; i < 100; ++i) {
            unsigned int port = 1000 + i;
            LibSocks2c::RunServerWithExternContext(io[i % 4], "12345678", "0.0.0.0", port, timeout);
        }

        AsyncRun(io);

        sleep(2);
        for (int i = 10; i < 1001; ++i) {
            unsigned int port = 1000 + i;
            LibSocks2c::RunServerWithExternContext(io[i % 4], "12345678", "0.0.0.0", port, timeout);
        }

        sleep(25);

    }



}