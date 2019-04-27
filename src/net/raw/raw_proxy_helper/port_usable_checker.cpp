#include "port_usable_checker.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

bool port_in_use(unsigned short port) {
	using namespace boost::asio;
	using ip::tcp;

	io_context io;
	tcp::acceptor a(io);

	boost::system::error_code ec;
	a.open(tcp::v4(), ec) || a.bind({ tcp::v4(), port }, ec);

	return ec == error::address_in_use;
}