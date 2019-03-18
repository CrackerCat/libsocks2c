#pragma once
#include "../../../utils/singleton.h"
#include <string>

/*
 * impl helper func for blocking tcp rst packet
 */
class FirewallHelper : public Singleton<FirewallHelper>
{

public:

    void BlockRst(std::string dst_ip, std::string dst_port);

};