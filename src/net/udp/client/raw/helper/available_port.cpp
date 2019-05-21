#include "available_port.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/unordered_set.hpp>
#include <random>

boost::unordered_set<uint16_t> port_set;


bool port_in_use(unsigned short port) {
    using namespace boost::asio;
    using ip::tcp;

    io_context io;
    tcp::acceptor a(io);

    boost::system::error_code ec;
    a.open(tcp::v4(), ec) || a.bind({ tcp::v4(), port }, ec);

    return ec == error::address_in_use;
}


bool port_in_set(unsigned short port) {
    return port_set.find(port) != port_set.end();
}


unsigned short GetPort()
{
    // we need to check if that port is available
    std::random_device rd;
    std::mt19937 eng(rd());
    std::uniform_int_distribution<unsigned short> distr(10000, 65535);

    for (int i = 0; i < 10; ++i)
    {
        auto selected_port = distr(eng);
        if (!port_in_use(selected_port) && !port_in_set(selected_port))
        {
            port_set.insert(selected_port);
            return selected_port;
        }
    }

    return 0;
}


void ReleasePort(unsigned short port)
{
    port_set.erase(port);
}


