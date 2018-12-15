#include "libsocks2c.h"
#include "../src/utils/logger.h"
#include "../src/factory/socks2c_factory.h"
#include <boost/asio/io_context.hpp>
#include <mutex>

#ifdef PROTOCOL_AES256GCM
#include "../src/protocol/custom/aes256gcmwithobf/aes256gcmwithobf.h"
#elif  PROTOCOL_CHACHA20POLY1305
#include "../src/protocol/custom/chacha20poly1305withobf/chacha20poly1305withobf.h"
#define aes256gcmwithobf_Protocol chacha20poly1305withobf_Protocol
#elif  PROTOCOL_CHACHA20
#include "../src/protocol/custom/chacha20/chacha20.h"
#define aes256gcmwithobf_Protocol chacha20_Protocol
#endif

static boost::asio::io_context* pio_context_ = nullptr;
static bool isLogInited(false);
static std::mutex log_mutex;
static std::mutex io_mutex;

void initLog()
{
    std::lock_guard<std::mutex> lg(log_mutex);

    if (!isLogInited)
    {
        Logger::GetInstance()->InitLog();
        Logger::GetInstance()->GetConsole()->set_level(spdlog::level::debug);
        isLogInited = true;
#ifndef MULTITHREAD_IO
        LOG_INFO("This build without MULTITHREAD_IO definition, running in single thread mode")
#endif
    }

}

void LibSocks2c::RunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();
    pio_context_ = new boost::asio::io_context();

    {
        Socks2cFactory::CreateClientProxyWithContext<aes256gcmwithobf_Protocol>(pio_context_, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);
    }

    pio_context_->run();
}
void LibSocks2c::RunClientMt(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout) {
    initLog();
    pio_context_ = new boost::asio::io_context();

    {
        Socks2cFactory::CreateClientProxyWithContext<aes256gcmwithobf_Protocol>(pio_context_, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);
    }
    pio_context_->run();

}



void LibSocks2c::RunServer(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();
    pio_context_ = new boost::asio::io_context();

    {
        Socks2cFactory::CreateServerProxyWithContext<aes256gcmwithobf_Protocol>(pio_context_, proxyKey, server_ip, server_port, timeout);
    }

    pio_context_->run();
}

void LibSocks2c::RunServerMt(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout)
{
	initLog();

#ifndef __linux__
	LOG_INFO("Proxy Server running on win32 or mac is only for testing")
    RunServer(proxyKey, server_ip, server_port, timeout);
#else
    auto proxytuple = Socks2cFactory::CreateServerProxyMt<aes256gcmwithobf_Protocol>(proxyKey, server_ip, server_port, timeout);
#endif

}

void LibSocks2c::RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout) {

    initLog();

    {
        Socks2cFactory::CreateServerProxyWithContext<aes256gcmwithobf_Protocol>(&io_context, proxyKey, server_ip, server_port, timeout);
    }

}
void LibSocks2c::RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout)
{
    initLog();

    {
        Socks2cFactory::CreateClientProxyWithContext<aes256gcmwithobf_Protocol>(&io_context, proxyKey, socks5_ip, socks5_port, server_ip, server_port, timeout);
    }

}

void LibSocks2c::Stop() {
	std::lock_guard<std::mutex> lg(io_mutex);

	if (!pio_context_)
	{
		printf("iocontext already stop\n");
		return;
	}
	pio_context_->stop();
	delete pio_context_;
	pio_context_ = nullptr;
}


uint64_t LibSocks2c::GetUpstreamTraffic()
{
	return TrafficCounter::GetInstance()->GetUpstreamBytes();
}

uint64_t LibSocks2c::GetDownstreamTraffic()
{
	return TrafficCounter::GetInstance()->GetDownstreamBytes();
}

