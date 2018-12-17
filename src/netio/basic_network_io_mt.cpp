#include "basic_network_io_mt.h"

std::vector<boost::asio::io_context*> BasicNetworkIO_MT::vpio_context_;
std::vector<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> BasicNetworkIO_MT::vwork_guard_;

bool BasicNetworkIO_MT::isRunning = false;
bool BasicNetworkIO_MT::firstRun = true;
bool BasicNetworkIO_MT::use_buildin_context = true;

BasicNetworkIO_MT::~BasicNetworkIO_MT()
{

}