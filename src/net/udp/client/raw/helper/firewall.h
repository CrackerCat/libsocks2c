#pragma once
#include <string>

/*
 * impl helper func for blocking tcp rst packet
 */
class Firewall
{

public:

    static void BlockRst(std::string dst_ip, std::string dst_port);
    static void Unblock(std::string dst_ip, std::string dst_port);
};