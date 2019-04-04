#include "basic_network_io_mt.h"

std::vector<boost::asio::io_context*> BasicNetworkIO_MT::vpio_context_;
std::vector<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> BasicNetworkIO_MT::vwork_guard_;

bool BasicNetworkIO_MT::isRunning = false;
bool BasicNetworkIO_MT::use_buildin_context = true;

BasicNetworkIO_MT::~BasicNetworkIO_MT()
{
    LOG_DEBUG("BasicNetworkIO_MT die")
}

BasicNetworkIO_MT::BasicNetworkIO_MT()
{

#ifdef MULTITHREAD_IO
	ioNum = boost::thread::physical_concurrency();
#else
	ioNum = 1;
#endif
	//return if vio was created previously
	if (vpio_context_.size() != 0) return;

	for (unsigned int i = 0; i < ioNum; i++)
	{
		//vpio_context_.emplace_back(new IO_CONTEXT(BOOST_ASIO_CONCURRENCY_HINT_SAFE));
		vpio_context_.emplace_back(new IO_CONTEXT());
		vwork_guard_.emplace_back(boost::asio::make_work_guard(*vpio_context_[i]));
	}
}


/*
*  you can pass a specific context if you don't want to use the build in one
*  all io operation will attach on that context
*/
void BasicNetworkIO_MT::SetIOContext(IO_CONTEXT* io_context)
{
	if (!use_buildin_context) return;
	use_buildin_context = false;

	vwork_guard_.clear();
	vpio_context_.clear();

	vpio_context_.push_back(io_context);
}

void BasicNetworkIO_MT::Join()
{
	thread_group_.join_all();
}


void BasicNetworkIO_MT::RunIO()
{
	if (!use_buildin_context) return;
	if (isRunning) return;

	for (unsigned int i = 0; i < ioNum; ++i)
	{
		LOG_DEBUG("running thread {}", i);
		thread_group_.create_thread(boost::bind(&boost::asio::io_context::run, vpio_context_[i]));
	}

	isRunning = true;
}

boost::asio::io_context& BasicNetworkIO_MT::GetIOContext()
{
	return *vpio_context_[0];
}

boost::asio::io_context& BasicNetworkIO_MT::GetIOContextAt(unsigned int pos)
{
	return *vpio_context_[pos];
}

boost::asio::io_context& BasicNetworkIO_MT::GetRandomIOContext()
{
	if (use_buildin_context)
	{
		return *vpio_context_[randomNum(0, ioNum - 1)];
	}
	return *vpio_context_[0];
}

uint64_t BasicNetworkIO_MT::GetVIOContextSize()
{
	return ioNum;
}

inline uint8_t BasicNetworkIO_MT::randomNum(int a, int b)
{
	if (a > b) return 0;
	return rand() % (b - a + 1) + a;
}

