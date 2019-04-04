#pragma once

#include "../../udp/server/server_udp_proxy_session.h"

template <class Protocol>
class ServerUdpRawProxySession;

template <class Protocol>
class ServerUdpProxySessionCrossOver : public ServerUdpProxySession<Protocol>
{
    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ServerUdpProxySession<Protocol>>, EndPointHash>;

    ServerUdpProxySessionCrossOver(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::shared_ptr<boost::asio::ip::udp::socket> local_socket, SESSION_MAP& map_ref) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(local_socket->get_io_context()), timer_(local_socket->get_io_context())
    {

    }



private:
    boost::shared_ptr<ServerUdpRawProxySession<Protocol>> server;
};
