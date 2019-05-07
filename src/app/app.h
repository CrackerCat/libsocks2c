#pragma once
#include "../utils/singleton.h"
#include <sodium.h>
#include "../utils/logger.h"

#include <mutex>

static bool isLogInited(false);
static std::mutex log_mutex;


class App : public Singleton<App>
{

public:

    static void Init(bool logtofile)
    {
        int res = sodium_init();

        std::lock_guard<std::mutex> lg(log_mutex);

        if (!isLogInited)
        {
            Logger::GetInstance()->InitLog(logtofile);
#ifndef LOG_DEBUG_DETAIL
            Logger::GetInstance()->GetConsole()->set_level(spdlog::level::info);
#else
            Logger::GetInstance()->GetConsole()->set_level(spdlog::level::debug);
#endif
            isLogInited = true;

#ifndef MULTITHREAD_IO
            LOG_INFO("This build without MULTITHREAD_IO")
#endif
        }
    }


};