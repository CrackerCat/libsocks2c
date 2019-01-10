//
// Created by Mario Lau on 2018-12-19.
//

#include "proxymanager.h"


ProxyManager::ProxyManager() : worker(boost::asio::make_work_guard(io)), timer(io)
{

}

void ProxyManager::TakeManage(int id)
{
    if (!running) asyncRun();

    std::lock_guard<std::mutex> lg(mutex);

    managed_proxy_set.insert(id);

}


void ProxyManager::onTimeUp(const boost::system::error_code &ec)
{
    if (ec)
    {
        LOG_ERROR("onTimeUp err --> {}", ec.message().c_str())
        return;
    }

    std::lock_guard<std::mutex> lg(mutex);

    auto proxy_map = ProxyMap<Protocol>::GetInstance();
    for (auto it = managed_proxy_set.begin(); it != managed_proxy_set.end(); )
    {

        if(proxy_map->ClearProxy(*it)) {
            fflush(stdout);
            it = managed_proxy_set.erase(it);
        }
        else {
            it++;
        }

    }


    timer.expires_from_now(boost::posix_time::seconds(check_time));
    timer.async_wait(boost::bind(&ProxyManager::onTimeUp, this, boost::asio::placeholders::error));

}

void ProxyManager::asyncRun()
{

    timer.expires_from_now(boost::posix_time::seconds(check_time));
    timer.async_wait(boost::bind(&ProxyManager::onTimeUp, this, boost::asio::placeholders::error));

    boost::thread t(boost::bind(&boost::asio::io_context::run, &io));

    running = true;
}