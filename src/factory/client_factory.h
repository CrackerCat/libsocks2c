#pragma once

#include "../net/udp/client/client_udp_proxy.h"
#include "../net/tcp/client/client_tcp_proxy.h"

#ifdef UDP_OVER_UTCP
#include "../net/udp/client/raw/client_raw_proxy.h"
//#include "../net/udp/client/client_udp_proxy_withraw.h"
#endif

#include "../../lib/libsocks2c.h"

template<class Protocol>
using ClientProxy = std::tuple<boost::shared_ptr<ClientTcpProxy<Protocol>>, boost::shared_ptr<ClientUdpProxy<Protocol>>>;

class ClientFactory {

public:

    // if defined MULTITHREAD_IO, then ClientTcpProxy would be multithread version
    // only the tcp && udp session are multithreaded, the acceptor ain't cause SO_REUSEPORT is not support on win32 && mac
    template<class Protocol>
    static ClientProxy<Protocol> CreateClientProxy(LibSocks2c::Config config)
    {
        auto tcps = boost::make_shared<ClientTcpProxy<Protocol>>();

        tcps->SetSocks5Host(config.socks5_ip, config.socks5_port);
        tcps->SetProxyKey(config.proxyKey);
        tcps->SetProxyInfo(config.server_ip, config.server_port);
        if (config.resolve_dns) tcps->EnableDnsResolver();
        tcps->StartProxy();

        boost::shared_ptr<ClientUdpProxy<Protocol>> udps;
#ifdef UDP_OVER_UTCP
        while (config.udp_over_utcp)
        {
            auto uout = boost::make_shared<ClientRawProxy<Protocol>>();
            uout->SetProxyKey(config.proxyKey);
            uout->SetProxyInfo(config.server_ip, config.server_port);
			auto res = uout->InitUout(config.server_ip, boost::lexical_cast<std::string>(config.server_uout_port), config.local_uout_ip, config.local_uout_ifname);
			if (!res)
				break;

			if (config.dnsuout)
			    uout->EnableDnsViaRaw();
			uout->StartProxy(config.socks5_ip, config.socks5_port);
			//uout->StartUout();
			return ClientProxy<Protocol>(tcps, boost::static_pointer_cast<ClientUdpProxy<Protocol>>(uout));
        }
#endif
        udps = boost::make_shared<ClientUdpProxy<Protocol>>();
        udps->SetProxyKey(config.proxyKey);
        udps->SetProxyInfo(config.server_ip, config.server_port);
        udps->StartProxy(config.socks5_ip, config.socks5_port);

        return ClientProxy<Protocol>(tcps, udps);
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

