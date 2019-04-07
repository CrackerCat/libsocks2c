#pragma once
#include "../../utils/singleton.h"

#include <boost/unordered_map.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/shared_ptr.hpp>
#include "../../utils/ephash.h"

template <class Protocol>
class ServerUdpProxySession;

template <class Protocol>
class udp_proxy_session;

template<class Protocol>
using PUdpProxySession = boost::shared_ptr<ServerUdpProxySession<Protocol>>;
template<class Protocol>
using PRawUdpProxySession = boost::shared_ptr<udp_proxy_session<Protocol>>;

template <class Protocol>
class UdpSocketMap : public Singleton<UdpSocketMap<Protocol>>
{

    using UDP_EP = boost::asio::ip::udp::endpoint;
    using UDP_SOCKET = boost::asio::ip::udp::socket;
    using PUDP_SOCKET = boost::shared_ptr<UDP_SOCKET>;

    using UDP_SOCKET_MAP = boost::unordered_map<UDP_EP, UdpSocketContext>;


    struct UdpSocketContext {
        PUDP_SOCKET psocket;
        PUdpProxySession<Protocol> pudpproxysession;
        PRawUdpProxySession<Protocol> prawudpproxysession;
        bool idle = true;
    };



public:

    enum FromType {
        UDP,
        RAW_UDP
    };

    PUDP_SOCKET FindSocket(UDP_EP udp_ep, FromType from)
    {
        auto it = udp_socket_map.find(udp_ep);
        if (it == udp_socket_map.end()) return nullptr;

        switch(from)
        {
            case UDP: {
                return it->second.idle ? nullptr : it->second.pudpproxysession;
            }
            case RAW_UDP: {
                return it->second.idle ? nullptr : it->second.prawudpproxysession;
            }
        }

    }


    PUDP_SOCKET FindAndInsert(UDP_EP udp_ep, )
    {

    }





private:

    UDP_SOCKET_MAP udp_socket_map;



};