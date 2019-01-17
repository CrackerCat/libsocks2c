#include "libsocks2c.h"

#include "proxymap.h"
#include "proxymanager.h"

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

int LibSocks2c::AsyncRunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();
    if (ProxyMap<Protocol>::GetInstance()->IsProxyExist(socks5_port)) return 0;

	auto handle = Socks2cFactory::CreateClientProxy<Protocol>(proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);

    auto res = ProxyMap<Protocol>::GetInstance()->Insert(socks5_port, handle);

	if (res)
	{
		ProxyManager::GetInstance()->TakeManage(socks5_port);
		return socks5_port;
	}
    return 0;
}

bool LibSocks2c::PauseClient(int id)
{
	if (!ProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;

	return ProxyMap<Protocol>::GetInstance()->PauseClient(id);

}
bool LibSocks2c::RestartClient(int id)
{
	if (!ProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;

	return ProxyMap<Protocol>::GetInstance()->RestartClient(id);

}

bool LibSocks2c::RetargetProxyServer(int id, std::string ip, uint16_t port)
{
	if (!ProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;

	return ProxyMap<Protocol>::GetInstance()->RetargetServer(id, ip, port);

}



bool LibSocks2c::StopProxy(int id)
{
    if (!ProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;

    return ProxyMap<Protocol>::GetInstance()->StopProxy(id);
}


int LibSocks2c::AsyncRunServer(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();

    if (ProxyMap<Protocol>::GetInstance()->IsProxyExist(server_port)) return 0;

    auto handle = Socks2cFactory::CreateServerProxy<Protocol>(proxyKey, server_ip, server_port, timeout);

    auto res = ProxyMap<Protocol>::GetInstance()->Insert(server_port, handle);

	if (res)
	{
		ProxyManager::GetInstance()->TakeManage(server_port);
		return server_port;
	}
    return 0;
}


void LibSocks2c::RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();

    {
        Socks2cFactory::CreateServerProxyWithContext<Protocol>(&io_context, proxyKey, server_ip, server_port, timeout);
    }

}
void LibSocks2c::RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout)
{
    initLog();

    {
        Socks2cFactory::CreateClientProxyWithContext<Protocol>(&io_context, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);
    }

}

#include "version.h"
std::string LibSocks2c::GetLibVersion()
{
    return Libsocks2cVersion;
}

