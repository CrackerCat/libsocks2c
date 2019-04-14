#pragma once


#ifdef UDP_OVER_UTCP
    #ifndef _WIN32
        #include "../net/raw/server/server_udp_raw_proxy.h"
    #endif
#endif

#if defined(__linux__) && defined(MULTITHREAD_IO)
#include "../net/tcp/server/server_tcp_proxy_mt.h"
#include "../net/udp/server/server_udp_proxy_mt.h"
#else
#include "../net/tcp/server/server_tcp_proxy.h"
#include "../net/udp/server/server_udp_proxy.h"
#endif

template<class Protocol>
using ServerProxy = std::tuple<boost::shared_ptr<ServerTcpProxy<Protocol>>, boost::shared_ptr<ServerUdpProxy<Protocol>>>;

class ServerFactory {

public:

	// if defined MULTITHREAD_IO, then ServerTcpProxy would be multithread version
	// only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac
	// use CreateServerProxyMt() instead on linux which provide better performance
    template<class Protocol>
    static ServerProxy<Protocol> CreateServerProxy(std::string proxyKey, std::string server_ip, uint16_t server_port, uint16_t server_uout_port, bool udp2raw, uint64_t timeout = 0, int uid = 0)
    {
        auto tcps = boost::make_shared<ServerTcpProxy<Protocol>>();
        tcps->SetUid(uid);
        tcps->SetProxyKey(proxyKey);
        tcps->SetExpireTime(timeout);
        tcps->SetProxyInfo(server_ip, server_port);
        tcps->StartProxy(server_ip, server_port);

        auto udps = boost::make_shared<ServerUdpProxy<Protocol>>();
        udps->SetUid(uid);
        udps->SetProxyKey(proxyKey);
        udps->SetExpireTime(timeout);
        udps->SetProxyInfo(server_ip, server_port);
        udps->StartProxy(server_ip, server_port);

#ifndef _WIN32
#ifdef UDP_OVER_UTCP
        if (udp2raw)
        {
            auto pudp2raw = ServerUdpRawProxy<Protocol>::GetInstance(udps->GetDefaultIO());
            auto init_res = pudp2raw->SetUpSniffer(boost::lexical_cast<std::string>(server_uout_port));
            if (init_res)
            {
                pudp2raw->SetProxyKey(proxyKey);
                pudp2raw->StartProxy();
            }
        }
#endif
#endif
        return ServerProxy<Protocol>(tcps, udps);
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

};

