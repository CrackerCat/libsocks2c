#pragma once

#include "../net/udp/client/client_udp_proxy.h"
#include "../net/tcp/client/client_tcp_proxy.h"

#include "../net/udp/server/server_udp_proxy.h"
#include "../net/tcp/server/server_tcp_proxy.h"

#ifdef __linux__
#include "../net/tcp/server/server_tcp_proxy_mt.h"
//#include "../net/tcp/client/client_tcp_proxy_mt.h"
#endif

#define ServerProxy std::tuple<boost::shared_ptr<ServerTcpProxy<Protocol>>, boost::shared_ptr<ServerUdpProxy<Protocol>>>
#define ClientProxy std::tuple<boost::shared_ptr<ClientTcpProxy<Protocol>>, boost::shared_ptr<ClientUdpProxy<Protocol>>>

class Socks2cFactory {

public:

	// if defined MULTITHREAD_IO, then ServerTcpProxy would be multithread version
	// only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac 
	// call Join() after getting the proxy pair
	// use CreateServerProxyMt() instead on linux which provide better performance
    template<class Protocol>
    static ServerProxy CreateServerProxy(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ServerTcpProxy<Protocol>>();
        tcps->SetProxyKey(proxyKey);
        tcps->SetExpireTime(timeout);
        tcps->StartProxy(server_ip, server_port);

        auto udps = boost::make_shared<ServerUdpProxy<Protocol>>();
        udps->SetProxyKey(proxyKey);
        udps->SetExpireTime(timeout);
        udps->StartProxy(server_ip, server_port);

        return ServerProxy(tcps, udps);
    }

	// if defined MULTITHREAD_IO, then ClientTcpProxy would be multithread version
	// only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac 
	// call Join() after getting the proxy pair
    template<class Protocol>
    static ClientProxy CreateClientProxy(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ClientTcpProxy<Protocol>>();
        tcps->SetProxyKey(proxyKey);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->SetExpireTime(timeout);
        tcps->StartProxy(socks5_ip, socks5_port);

        auto udps = boost::make_shared<ClientUdpProxy<Protocol>>();
        udps->SetProxyKey(proxyKey);
        udps->SetProxyInfo(server_ip, server_port);
        udps->SetExpireTime(timeout);
        udps->StartProxy(socks5_ip, socks5_port);

        return ClientProxy(tcps, udps);
    }

#ifdef __linux__
	//multithread server with SO_REUSEPORT feature is only support on linux
    template<class Protocol>
    static auto CreateServerProxyMt(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ServerTcpProxy_MT<Protocol>>();
        tcps->SetProxyKey(proxyKey);
        tcps->SetExpireTime(timeout);
        tcps->StartProxy(server_ip, server_port);

        auto udps = boost::make_shared<ServerUdpProxy<Protocol>>();
        udps->SetProxyKey(proxyKey);
        udps->SetExpireTime(timeout);
        udps->StartProxy(server_ip, server_port);

        return std::tuple<boost::shared_ptr<ServerTcpProxy_MT<Protocol>>, boost::shared_ptr<ServerUdpProxy<Protocol>>> (tcps, udps);
    }
#endif

	/*
		Two Proxy function below are single threaded, you need to manage the io_context but don't run it on different thread
	*/
    template<class Protocol>
    static ServerProxy CreateServerProxyWithContext(boost::asio::io_context* io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ServerTcpProxy<Protocol>>();
        tcps->SetIOContext(io_context);
        tcps->SetProxyKey(proxyKey);
        tcps->SetExpireTime(timeout);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->StartProxy(server_ip, server_port);

        auto udps = boost::make_shared<ServerUdpProxy<Protocol>>();
        udps->SetIOContext(io_context);
        udps->SetProxyKey(proxyKey);
        udps->SetExpireTime(timeout);
        udps->SetProxyInfo(server_ip, server_port);
        udps->StartProxy(server_ip, server_port);

        return ServerProxy(tcps, udps);
    }


    template<class Protocol>
    static ClientProxy CreateClientProxyWithContext(boost::asio::io_context* io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ClientTcpProxy<Protocol>>();
        tcps->SetIOContext(io_context);
        tcps->SetProxyKey(proxyKey);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->SetExpireTime(timeout);
        tcps->StartProxy(socks5_ip, socks5_port);

        auto udps = boost::make_shared<ClientUdpProxy<Protocol>>();
        udps->SetIOContext(io_context);
        udps->SetProxyKey(proxyKey);
        udps->SetProxyInfo(server_ip, server_port);
        udps->SetExpireTime(timeout);
        udps->StartProxy(socks5_ip, socks5_port);

        return ClientProxy(tcps, udps);
    }
};

