#pragma once

#include "../net/udp/client/client_udp_proxy.h"
#include "../net/tcp/client/client_tcp_proxy.h"
#include "../net/udp/client/client_udp_proxy_withraw.h"
#include "../net/raw/server/server_udp_raw_proxy.h"

#if defined(__linux__) && defined(MULTITHREAD_IO)
#include "../net/tcp/server/server_tcp_proxy_mt.h"
#include "../net/udp/server/server_udp_proxy_mt.h"
#else
#include "../net/tcp/server/server_tcp_proxy.h"
#include "../net/udp/server/server_udp_proxy.h"
#endif

template<class Protocol>
using ServerProxy = std::tuple<boost::shared_ptr<ServerTcpProxy<Protocol>>, boost::shared_ptr<ServerUdpProxy<Protocol>>>;

template<class Protocol>
using ClientProxy = std::tuple<boost::shared_ptr<ClientTcpProxy<Protocol>>, boost::shared_ptr<ClientUdpProxy<Protocol>>>;

class Socks2cFactory {

public:

	// if defined MULTITHREAD_IO, then ServerTcpProxy would be multithread version
	// only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac 
	// use CreateServerProxyMt() instead on linux which provide better performance
    template<class Protocol>
    static ServerProxy<Protocol> CreateServerProxy(std::string proxyKey, std::string server_ip, uint16_t server_port, bool udp2raw, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ServerTcpProxy<Protocol>>();
        tcps->SetProxyKey(proxyKey);
        tcps->SetExpireTime(timeout);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->StartProxy(server_ip, server_port);

        auto udps = boost::make_shared<ServerUdpProxy<Protocol>>();
        udps->SetProxyKey(proxyKey);
        udps->SetExpireTime(timeout);
        udps->SetProxyInfo(server_ip, server_port);
        udps->StartProxy(server_ip, server_port);

        if (udp2raw)
        {
            auto pudp2raw = ServerUdpRawProxy<Protocol>::GetInstance(udps->GetDefaultIO());
            pudp2raw->SetUpSniffer("4567");
            pudp2raw->SetProxyKey(proxyKey);
            pudp2raw->StartProxy();
        }

        return ServerProxy<Protocol>(tcps, udps);
    }

	// if defined MULTITHREAD_IO, then ClientTcpProxy would be multithread version
	// only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac 
    template<class Protocol>
    static ClientProxy<Protocol> CreateClientProxy(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, bool resolve_dns, bool udp2raw, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ClientTcpProxy<Protocol>>();

		tcps->SetSocks5Host(socks5_ip, socks5_port);
        tcps->SetProxyKey(proxyKey);
        tcps->SetProxyInfo(server_ip, server_port);
        if (resolve_dns) tcps->EnableDnsResolver();
        tcps->StartProxy();

        boost::shared_ptr<ClientUdpProxy<Protocol>> udps;
        if (udp2raw)
        {
            udps = boost::make_shared<ClientUdpProxyWithRaw<Protocol>>();
            udps->SetProxyKey(proxyKey);
            udps->SetProxyInfo(server_ip, server_port);
            udps->StartProxy(socks5_ip, socks5_port);
            boost::static_pointer_cast<ClientUdpProxyWithRaw<Protocol>>(udps)->InitUdp2Raw("192.168.1.214", server_ip, "4567", "4444");
        }else
        {
            udps = boost::make_shared<ClientUdpProxy<Protocol>>();
            udps->SetProxyKey(proxyKey);
            udps->SetProxyInfo(server_ip, server_port);
            udps->StartProxy(socks5_ip, socks5_port);
        }

        return ClientProxy<Protocol>(tcps, udps);
    }

	/*
		Two Proxy function below are single threaded, you need to manage the io_context but don't run it on different thread
	*/
    template<class Protocol>
    static ServerProxy<Protocol> CreateServerProxyWithContext(boost::asio::io_context* io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
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

        return ServerProxy<Protocol>(tcps, udps);
    }


    template<class Protocol>
    static ClientProxy<Protocol> CreateClientProxyWithContext(boost::asio::io_context* io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0)
    {
        auto tcps = boost::make_shared<ClientTcpProxy<Protocol>>();
        tcps->SetIOContext(io_context);
        tcps->SetProxyKey(proxyKey);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->SetExpireTime(timeout);
        tcps->StartProxy();

        auto udps = boost::make_shared<ClientUdpProxy<Protocol>>();
        udps->SetIOContext(io_context);
        udps->SetProxyKey(proxyKey);
        udps->SetProxyInfo(server_ip, server_port);
        udps->SetExpireTime(timeout);
        udps->StartProxy(socks5_ip, socks5_port);

        return ClientProxy<Protocol>(tcps, udps);
    }
};

