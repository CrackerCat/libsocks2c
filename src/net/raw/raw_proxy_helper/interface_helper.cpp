#include "interface_helper.h"

#ifdef __APPLE__
#include "../../../utils/system/system_exec.h"
std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "route -n get default | grep 'interface' | awk '{print $2}'";

    return ExecAndGetRes(default_if_str.c_str());
}
std::string InterfaceHelper::GetDefaultNetIp()
{
    std::string default_ip_str = "ipconfig getifaddr ";
    default_ip_str += GetDefaultInterface();
    auto res = ExecAndGetRes(default_ip_str.c_str());
    return res;
}
#elif __linux__
#include "../../../utils/system/system_exec.h"
#include <algorithm>
std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "ip route | awk '/default/ { print $5 }'";
    auto res = ExecAndGetRes(default_if_str.c_str());

    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());

    return res;
}
std::string InterfaceHelper::GetDefaultNetIp()
{
    const std::string default_if_str = "ip route | awk '/default/ { print $9 }'";
    auto res = ExecAndGetRes(default_if_str.c_str());

    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());

    return res;
}

#endif
