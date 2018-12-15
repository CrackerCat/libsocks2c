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


    static bool parseDomainPortFromSocks5Request(socks5::SOCKS_REQ* request, std::string &domain_out, uint16_t &port_out)
    {

        char* tmp = (char*)request;
        char domain_length;
        memcpy(&domain_length, tmp + 4, 1);

        domain_out.clear();
        for (int i = 0 ; i < domain_length; i++)
        {
            domain_out.append(boost::lexical_cast<std::string>(tmp[i + 5]));
        }

        if(boost::regex_match(domain_out, domainPattern))
        {
            char port[2];
            port[0] = tmp[domain_length + 6];
            port[1] = tmp[domain_length + 5];
            memcpy(&port_out, port, 2);
            return true;
        }

        domain_out.clear();

//        if(std::regex_match(domain_in,ipPattern))
//        {
//            return 1;
//        }
        return false;


    }


    static bool parseIpPortFromSocks5Request(socks5::SOCKS_REQ* request, std::string &ip_out, uint16_t &port_out)
    {

        unsigned char temp[10];
        memcpy(temp, request, 10);
        ip_out.clear();
        for (int i = 4; i < 7; i++) {
            ip_out.append(std::to_string(temp[i]));
            ip_out.append(".");
        }
        ip_out.append(std::to_string(temp[7]));

        if (regex_match(ip_out,ipPattern)) {
            char port[2];
            port[0] = temp[9];
            port[1] = temp[8];
            memcpy(&port_out, port, 2);
            return true;
        }else{
            ip_out.clear();
            return false;

        }

    }


    static bool parseIpPortFromSocks5UdpPacket(socks5::UDP_RELAY_PACKET *packet, std::string &ip_out, uint16_t &port_out)
    {

        return parseIpPortFromSocks5Request(reinterpret_cast<socks5::SOCKS_REQ*>(packet), ip_out, port_out);

    }

	static bool isDnsPacket(socks5::UDP_RELAY_PACKET *packet)
	{

		unsigned char* temp = (unsigned char*)packet;
		uint16_t port;
		char* pport = (char*)&port;
		pport[0] = temp[9];
		pport[1] = temp[8];
		
		if (port == 53)
		{
			return true;
		}

		return false;
	}

    static void ConstructSocks5RequestFromIpStringAndPort(unsigned char* data_in, std::string ip, unsigned short port)
    {

        static const char *split = ".";
        auto req = (socks5::SOCKS_REQ*)data_in;
        req->CMD = 0x01;

        req->ATYP = 0x01;

        char *split_res = strtok(const_cast<char*>(ip.c_str()), split);

        int pos = 4;

        while (split_res != nullptr) {
            unsigned char ip_frag = atoi(split_res);

            memcpy(&data_in[pos++], &ip_frag, 1);
            split_res = strtok(nullptr, split);
        }

        auto p = (unsigned char*)&port;

        data_in[8] = p[1];
        data_in[9] = p[0];

    }

    static void ConstructSocks5UdpPacketFromIpStringAndPort(unsigned char* data_in_out, std::string ip, unsigned short port) noexcept
    {

        auto req = (socks5::UDP_RELAY_PACKET*)data_in_out;
        req->RSV = 0x00;
        req->FRAG = 0x00;
        req->ATYP = 0x01;

        static const char *split = ".";
        char *split_res = nullptr;
        if (ip.find("::ffff:") == std::string::npos)
        {
            split_res = strtok(const_cast<char*>(ip.c_str()), split);
        }else
        {
            split_res = strtok(const_cast<char*>(ip.c_str() + 7), split);
        }


        int pos = 4;

        while (split_res != nullptr) {
            unsigned char ip_frag = atoi(split_res);

            memcpy(&data_in_out[pos++], &ip_frag, 1);
            split_res = strtok(nullptr, split);
        }

        auto pport = (unsigned char*)&port;

        data_in_out[8] = pport[1];
        data_in_out[9] = pport[0];
        return;


        // if ipv6 type




    }

    static bool IsUdpSocks5PacketValid(unsigned char* request)
    {

        auto req = (socks5::UDP_RELAY_PACKET*)request;
        if (req->ATYP == 0x01)
        {
            return false;
        }

        return true;
    }


    static void SetUdpSocks5ReplyEndpoint(std::string ip, int16_t port)
    {

        static const char *split = ".";
        auto req = (socks5::SOCKS_REPLY*)socks5::DEFAULT_UDP_REQ_REPLY ;
        req->REP = 0x00;
        req->RSV = 0x00;
        req->ATYP = 0x01;

        char *split_res = strtok(const_cast<char*>(ip.c_str()), split);

        int pos = 4;

        while (split_res != nullptr) {
            unsigned char ip_frag = atoi(split_res);

            memcpy(&socks5::DEFAULT_UDP_REQ_REPLY[pos++], &ip_frag, 1);
            split_res = strtok(nullptr, split);
        }

        auto p = (unsigned char*)&port;

        socks5::DEFAULT_UDP_REQ_REPLY[8] = p[1];
        socks5::DEFAULT_UDP_REQ_REPLY[9] = p[0];


    }
};


