#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/bind.hpp>
#include <thread>

#include "../lib/libsocks2c.h"

// all proxyserver or session timeout in 5s
const int timeout = 500;

void AsyncRun(boost::asio::io_context* server_io)
{
    std::thread t1(boost::bind(&boost::asio::io_context::run, server_io));
    t1.detach();
}


void test()
{

    {

        auto io = new boost::asio::io_context(1);

        for (int i = 0; i < 100; ++i) {
            unsigned int port = 1000 + i;
            LibSocks2c::RunServerWithExternContext(*io, "12345678", "0.0.0.0", port, timeout);
        }

        AsyncRun(io);

        sleep(2);
        for (int i = 10; i < 200; ++i) {
            unsigned int port = 1000 + i;
            LibSocks2c::RunServerWithExternContext(*io, "12345678", "0.0.0.0", port, timeout);
        }
        sleep(200);

        io->stop();

        delete io;
        sleep(2);


        printf("stopped");


    }



}