#include "logger.h"

#include <sodium.h>
std::shared_ptr<spdlog::logger> Logger::console = nullptr;

void Logger::InitLog()
{
    console = spdlog::stdout_color_mt("console");
    int res = sodium_init();
}