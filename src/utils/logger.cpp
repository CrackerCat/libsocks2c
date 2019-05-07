#include "logger.h"
#include "spdlog/sinks/basic_file_sink.h"

#include <boost/lexical_cast.hpp>

std::shared_ptr<spdlog::logger> Logger::console = nullptr;

void Logger::InitLog(bool logtofile)
{
    if (logtofile)
    {
        auto current_time = boost::lexical_cast<std::string>(time(nullptr));
        console = spdlog::basic_logger_mt("console", current_time);
        spdlog::flush_every(std::chrono::seconds(5));

    }else
        console = spdlog::stdout_color_mt("console");
}