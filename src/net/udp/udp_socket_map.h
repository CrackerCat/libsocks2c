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

    struct UdpSocketContext {
        PUDP_SOCKET psocket;
        PUdpProxySession<Protocol> pudpproxysession;
        PRawUdpProxySession<Protocol> prawudpproxysession;
        bool fallback = false;
    };

    using PUdpSocketContext = std::unique_ptr<UdpSocketContext>;
    using UDP_SOCKET_MAP = boost::unordered_map<UDP_EP, UdpSocketContext>;



public:



private:

    UDP_SOCKET_MAP udp_socket_map;



};