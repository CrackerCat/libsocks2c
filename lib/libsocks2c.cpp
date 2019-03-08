#include "libsocks2c.h"

#include "proxymap.h"

#include "../src/utils/logger.h"
#include "../src/factory/socks2c_factory.h"
#include "../src/protocol/protocol_def.h"

#include <mutex>
#include <boost/asio/io_context.hpp>

static bool isLogInited(false);
static std::mutex log_mutex;

void initLog()
{
    std::lock_guard<std::mutex> lg(log_mutex);

    if (!isLogInited)
    {
        Logger::GetInstance()->InitLog();
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

int LibSocks2c::StartProxy(Config config)
{

    initLog();

    if (config.isServer)
    {
        if (ProxyMap<Protocol>::GetInstance()->IsProxyExist(config.server_port)) return 0;

        auto handle = Socks2cFactory::CreateServerProxy<Protocol>(
                config.proxyKey,
                config.server_ip,
                config.server_port,
                config.timeout);

        auto res = ProxyMap<Protocol>::GetInstance()->Insert(config.server_port, handle);

        if (!res) return -1;

        return config.server_port;
    }

    if (ProxyMap<Protocol>::GetInstance()->IsProxyExist(config.socks5_port)) return 0;

    auto handle = Socks2cFactory::CreateClientProxy<Protocol>(
            config.proxyKey,
            config.socks5_ip,
            config.socks5_port,
            config.server_ip,
            config.server_port,
            config.resolve_dns,
            config.timeout);

    auto res = ProxyMap<Protocol>::GetInstance()->Insert(config.socks5_port, handle);

    if (res) return -1;

    return config.socks5_port;

}


bool LibSocks2c::StopProxy(int id)
{
    if (!ProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;

    return ProxyMap<Protocol>::GetInstance()->StopProxy(id);
}


void LibSocks2c::StartProxyWithContext(Config config, boost::asio::io_context &io_context)
{
    initLog();

    {
        //Socks2cFactory::CreateServerProxyWithContext<Protocol>(&io_context, proxyKey, server_ip, server_port, timeout);
    }
    //Socks2cFactory::CreateClientProxyWithContext<Protocol>(&io_context, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);


}

#include "version.h"
std::string LibSocks2c::GetVersion()
{
    return Libsocks2cVersion;
}

