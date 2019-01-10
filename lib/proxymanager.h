#pragma once

#include "../src/utils/Singleton.h"
#include "../src/protocol/protocol_def.h"
#include "proxymap.h"

#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <unordered_set>
#include <mutex>


class ProxyManager : public Singleton<ProxyManager> {

    const int check_time = 30;

public:

    ProxyManager();

    void TakeManage(int id);

private:

    boost::asio::io_context io;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> worker;
    boost::asio::deadline_timer timer;

    bool running = false;

    std::mutex mutex;

    std::unordered_set<int> managed_proxy_set;

    void onTimeUp(const boost::system::error_code &ec);

    void asyncRun();
};


