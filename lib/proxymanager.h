#pragma once

#include "../src/utils/Singleton.h"
#include "../src/protocol/protocol_def.h"
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <unordered_set>
#include "proxymap.h"
#include <mutex>


class ProxyManager : public Singleton<ProxyManager> {


    const int check_time = 10;

public:

    ProxyManager() : worker(boost::asio::make_work_guard(io)), timer(io)
    {

    }




    void TakeManage(int id)
    {
        if (!running) asyncRun();

        std::lock_guard<std::mutex> lg(mutex);
        printf("take manage: %d\n", id);
        fflush(stdout);

        managed_proxy_set.insert(id);

    }


private:
    boost::asio::io_context io;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> worker;
    boost::asio::deadline_timer timer;

    bool running = false;

    std::mutex mutex;

    std::unordered_set<int> managed_proxy_set;

    void onTimeUp(const boost::system::error_code &ec)
    {
        if (ec)
        {
            LOG_ERROR("onTimeUp err --> {}", ec.message().c_str())
            return;
        }

        LOG_DEBUG("[{}] onTimeUp", (void*)this)

        std::lock_guard<std::mutex> lg(mutex);

        auto proxy_map = ProxyMap<Protocol>::GetInstance();
        for (auto it = managed_proxy_set.begin(); it != managed_proxy_set.end(); ) {

            printf("get: %d\n",*it);
            fflush(stdout);
            if(proxy_map->ClearProxy(*it)) {
                printf("erase: %d\n",*it);
                fflush(stdout);
                it = managed_proxy_set.erase(it);
            }
            else {
                printf("not erase: %d\n",*it);
                fflush(stdout);
                it++;
            }

        }


        timer.expires_from_now(boost::posix_time::seconds(check_time));
        timer.async_wait(boost::bind(&ProxyManager::onTimeUp, this, boost::asio::placeholders::error));

    }

    void asyncRun()
    {

        timer.expires_from_now(boost::posix_time::seconds(check_time));
        timer.async_wait(boost::bind(&ProxyManager::onTimeUp, this, boost::asio::placeholders::error));

        boost::thread t(boost::bind(&boost::asio::io_context::run, &io));

        running = true;
    }
};


