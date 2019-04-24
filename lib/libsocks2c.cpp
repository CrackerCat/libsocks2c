#include "libsocks2c.h"


#include "../src/utils/logger.h"

#ifdef BUILD_SERVER_LIB
#include "../src/factory/server_factory.h"
#include "server_proxymap.h"
#endif

#if BUILD_CLIENT_LIB
#include "../src/factory/client_factory.h"
#include "client_proxymap.h"
#endif

#include "../src/protocol/basic_protocol/protocol_def.h"

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
#ifdef BUILD_SERVER_LIB
    //run server
    if (config.isServer)
    {
        if (ServerProxyMap<Protocol>::GetInstance()->IsProxyExist(config.server_port)) return 0;

        auto handle = ServerFactory::CreateServerProxy<Protocol>(
                config.proxyKey,
                config.server_ip,
                config.server_port,
                config.server_uout_port,
                config.udp_over_utcp,
                config.timeout,
                config.uid);

        auto res = ServerProxyMap<Protocol>::GetInstance()->Insert(config.server_port, handle);

        if (!res) return -1;

        return config.server_port;
    }
#endif

    #ifdef BUILD_CLIENT_LIB
    //run client
    if (ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(config.socks5_port) || config.isServer) return 0;
    auto handle = ClientFactory::CreateClientProxy<Protocol>(
            config.proxyKey,
            config.socks5_ip,
            config.socks5_port,
            config.server_ip,
            config.server_port,
			config.server_uout_port,
		    config.udp_over_utcp,
			config.local_uout_ip,
			config.local_uout_port,
            config.resolve_dns,
            config.timeout,
            config.uid);

    auto res = ClientProxyMap<Protocol>::GetInstance()->Insert(config.socks5_port, handle);

    if (res) return -1;

    return config.socks5_port;
#endif
    return -1;
}


bool LibSocks2c::StopProxy(int id, bool isServer)
{
#ifdef BUILD_SERVER
    if (isServer)
    {
        if (!ServerProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;
        return ServerProxyMap<Protocol>::GetInstance()->StopProxy(id);
    }else
    {
#elif BUILD_CLIENT
        if (!ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;
        return ClientProxyMap<Protocol>::GetInstance()->StopProxy(id);
    }
#endif
    return false;
}

void LibSocks2c::StartProxyWithContext(Config config, boost::asio::io_context &io_context)
{
    initLog();

    {
        //Socks2cFactory::CreateServerProxyWithContext<Protocol>(&io_context, proxyKey, server_ip, server_port, timeout);
    }
    //Socks2cFactory::CreateClientProxyWithContext<Protocol>(&io_context, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);

}

#include "../src/utils/sqlhost.h"

void LibSocks2c::SetSqlHost(std::string host)
{
    sql_host = host;
}

#include "../src/info/version.h"
#include "../src/info/encryption_info.h"
std::string LibSocks2c::Version()
{
	return version + " [" + ENCRYPTION_METHOD + "]";
}

