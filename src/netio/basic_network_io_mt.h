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

    BasicNetworkIO_MT(){

#ifdef MULTITHREAD_IO
		ioNum = boost::thread::physical_concurrency();
#else
		ioNum = 1;
#endif
		//return if vio was created previously
		if (vpio_context_.size() != 0) return;

        for (unsigned int i = 0; i < ioNum; i++)
        {
            vpio_context_.emplace_back(new IO_CONTEXT());
            vwork_guard_.emplace_back(boost::asio::make_work_guard(*vpio_context_[i]));
        }
    }

    ~BasicNetworkIO_MT();

    /*
     *  you can pass a specific context if you don't want to use the build in one
     *  all io operation will attach on that context
     */
    void SetIOContext(IO_CONTEXT* io_context)
    {
		if (!use_buildin_context) return;
        use_buildin_context = false;

		vwork_guard_.clear();
        vpio_context_.clear();

		vpio_context_.push_back(io_context);
    }


	void Join()
	{
		thread_group_.join_all();
	}


	void StopIO()
	{
		for (unsigned int i = 0; i < ioNum; i++)
		{
			vpio_context_[i]->stop();
		}

		this->thread_group_.join_all();

		isRunning = false;
	}



protected:

    void RunIO()
    {
        if (!use_buildin_context) return;
		if (isRunning) return;

		if (!firstRun)
		{
			for (unsigned int i = 0; i < ioNum; ++i)
			{
				LOG_DEBUG("restarting io {}", i);
				vpio_context_[i]->restart();
			}
		}

        for(unsigned int i = 0; i < ioNum; ++i)
        {
			LOG_DEBUG("running thread {}", i);
            thread_group_.create_thread(boost::bind(&boost::asio::io_context::run, vpio_context_[i]));
        }

		isRunning = true;
		firstRun = false;
    }


    IO_CONTEXT& GetIOContext()
    {
        return *vpio_context_[0];
    }

    IO_CONTEXT& GetIOContextAt(unsigned int pos)
    {
        return *vpio_context_[pos];
    }

	IO_CONTEXT& GetRandomIOContext()
	{
		if (use_buildin_context)
		{
			return *vpio_context_[randomNum(0, ioNum - 1)];
		}
		return *vpio_context_[0];
	}

    uint64_t GetVIOContextSize()
    {
        return vpio_context_.size();
    }

	static VWORK_GUARD vwork_guard_;
	static VPIO_CONTEXT vpio_context_;
	THREAD_GROUP thread_group_;

private:

	static bool firstRun;

	static bool isRunning;
	static bool use_buildin_context;

	uint32_t ioNum = 0;

	inline int randomNum(int a, int b)
	{
		//printf("randing %d -- %d\n",a,b);
		if (a > b) return 0;
		return rand() % (b - a + 1) + a;
	}

};


