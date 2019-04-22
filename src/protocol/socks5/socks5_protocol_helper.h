#pragma once

#include "socks5_protocol.h"

#include <string>
#include <boost/regex.hpp>
#include <boost/lexical_cast.hpp>
/*
 *
 *  This class provide some helper functions for constructing packets based on socks5 protocol
 *
 */
const boost::regex ipPattern(R"(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]))");
const boost::regex domainPattern(R"((([a-zA-Z0-9]{1,63}|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])\.){0,3}[a-zA-Z]{2,63}\b(?!\.))");

class Socks5ProtocolHelper {


public:


    static bool parseDomainPortFromSocks5Request(socks5::SOCKS_REQ* request, std::string &domain_out, uint16_t &port_out);

    static bool parseIpPortFromSocks5Request(socks5::SOCKS_REQ* request, std::string &ip_out, uint16_t &port_out);

    static bool parseIpPortFromSocks5UdpPacket(socks5::UDP_RELAY_PACKET *data, std::string &ip_out, uint16_t &port_out);

	static bool isDnsPacket(socks5::UDP_RELAY_PACKET *packet);

    static void ConstructSocks5RequestFromIpStringAndPort(unsigned char* data_in_out, std::string&& ip, unsigned short port);

    static void ConstructSocks5UdpPacketFromIpStringAndPort(unsigned char* data_in_out, std::string&& ip, unsigned short port);

    static bool IsUdpSocks5PacketValid(unsigned char* request);


    /*
     * when client send udp proxy request,
     * we need to reply which server it should send the req to
     *
     * the default server is 127.0.0.1:1080 if not set
     */
    static void SetUdpSocks5ReplyEndpoint(std::string&& ip, int16_t port);
};


