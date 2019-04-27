#pragma once


#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/thread.hpp>
#include "../utils/logger.h"

class BasicNetworkIO_MT {

    using IO_CONTEXT = boost::asio::io_context;
    using PIO_CONTEXT = IO_CONTEXT*;
    using VIO_CONTEXT = std::vector<IO_CONTEXT>;
    using VPIO_CONTEXT = std::vector<PIO_CONTEXT>;

    using THREAD_GROUP = boost::thread_group;

    using WORK_GUARD = boost::asio::executor_work_guard<boost::asio::io_context::executor_type>;
    using VWORK_GUARD = std::vector<WORK_GUARD>;


public:

	BasicNetworkIO_MT();

    ~BasicNetworkIO_MT();

    /*
     *  you can pass a specific context if you don't want to use the build in context
     *  all io operation will attach on that context
     */
	void SetIOContext(IO_CONTEXT* io_context);

	void Join();

protected:

	void RunIO();

	IO_CONTEXT& GetIOContext();

	IO_CONTEXT& GetIOContextAt(unsigned int pos);

	IO_CONTEXT& GetRandomIOContext();

	uint64_t GetVIOContextSize();

	static VWORK_GUARD vwork_guard_;
    static VPIO_CONTEXT vpio_context_;
	THREAD_GROUP thread_group_;

private:

	static bool isRunning;
	static bool use_buildin_context;

	uint8_t ioNum;

	inline uint8_t randomNum(int a, int b);

};


