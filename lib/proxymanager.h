#pragma once

#include "../src/utils/Singleton.h"
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <set>
#include "proxymap.h"
#include <mutex>


class ProxyManager : public Singleton<ProxyManager> {


    const int check_time = 30;

public:

    ProxyManager() : worker(boost::asio::make_work_guard(io_context), timer(io)
    {

    }

    void AsyncRun()
    {

        timer.expires_from_now(boost::posix_time::seconds(check_time));
        timer.async_wait(boost::bind(&ServerTcpProxy::onTimeExpire, this, boost::asio::placeholders::error));

        boost::thread t(boost::bind(&boost::asio::io_context::run, &io));
    }


    void TakeManage(int id)
    {
        std::lock_guard<std::mutex> lg(mutex);

        managed_proxy_set.insert(id);

    }


private:
    boost::asio::io_context io;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> worker;
    boost::asio::deadline_timer timer;

    std::mutex mutex;

    std::set<int> managed_proxy_set;

    void onTimeUp(const boost::system::error_code &ec)
    {
        if (ec)
        {
            LOG_ERROR("onTimeUp err --> {}", ec.message().c_str())
            return;
        }

        LOG_DEBUG("[{}] onTimeUp", (void*)this)

        auto proxy_map = ProxyMap::GetInstance();
        for (int i = 0; i < managed_proxy_set.size(); i++)
        {

        }


        timer.expires_from_now(boost::posix_time::seconds(check_time));
        timer.async_wait(boost::bind(&ProxyManager::onTimeUp, this, boost::asio::placeholders::error));

    }

};


