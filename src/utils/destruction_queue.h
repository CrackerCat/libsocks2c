#pragma once

// for udp session only
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include "singleton.h"

class DestructionQueue : public Singleton<DestructionQueue>
{

public:

	DestructionQueue() : worker_(boost::asio::make_work_guard(io_context_))
	{

		boost::thread t1(boost::bind(&boost::asio::io_context::run, &io_context_));
		t1.detach();

	}

	auto& GetQueueIO()
	{
		return this->io_context_;
	}

private:

	boost::asio::io_context io_context_;
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> worker_;
		





};