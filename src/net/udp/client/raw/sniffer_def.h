#pragma once

#ifdef _WIN32
#include <boost/asio/windows/object_handle.hpp>
typedef boost::asio::windows::object_handle SnifferSocket;
typedef boost::asio::windows::object_handle SendSocket;
#else
#include <boost/asio/posix/stream_descriptor.hpp>
typedef boost::asio::posix::stream_descriptor SnifferSocket;
#endif