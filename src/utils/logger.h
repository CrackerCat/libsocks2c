#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include "Singleton.h"

class Logger : public Singleton<Logger>
{
public:
    void InitLog();

    std::shared_ptr<spdlog::logger> GetConsole(){return console;}
    void SetLevel(spdlog::level::level_enum log_level)
    {
        Logger::GetInstance()->GetConsole()->set_level(log_level);
    }

private:

    static std::shared_ptr<spdlog::logger> console;

};

#ifdef LOG_DEBUG_DETAIL
#define LOG_DETAIL(x) x
#else
#define LOG_DETAIL(x)
#endif

#ifdef DISABLE_ALL_LOG

#define LOG_INFO(f_, ...)

#define LOG_DEBUG(f_, ...)

#define LOG_ERROR(f_, ...)

#define LOG_CONSOLE

#elif defined(DISABLE_DEBUG_LOG)

#define LOG_INFO(f_, ...) Logger::GetInstance()->GetConsole()->info((f_), ##__VA_ARGS__);

#define LOG_DEBUG(f_, ...)

#define LOG_ERROR(f_, ...)  Logger::GetInstance()->GetConsole()->error((f_), ##__VA_ARGS__);

#define LOG_CONSOLE

#else

#define LOG_INFO(f_, ...) Logger::GetInstance()->GetConsole()->info((f_), ##__VA_ARGS__);

#define LOG_DEBUG(f_, ...)  Logger::GetInstance()->GetConsole()->debug((f_), ##__VA_ARGS__);

#define LOG_ERROR(f_, ...)  Logger::GetInstance()->GetConsole()->error((f_), ##__VA_ARGS__);

#define LOG_CONSOLE Logger::GetInstance()->GetConsole()

#endif



