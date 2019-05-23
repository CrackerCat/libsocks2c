#include "interface_helper.h"
#include <string>
#include <boost/algorithm/string.hpp>


#include "../../../utils/system/system_exec.h"
#include <boost/algorithm/string.hpp>

std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "ip route | awk '/default/ { print $5 }'";
    auto res = ExecAndGetRes(default_if_str.c_str());
    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());
    return res;
}

std::string InterfaceHelper::GetDefaultNetIp()
{
    const std::string default_if_str = "hostname -I";
    auto res = ExecAndGetRes(default_if_str.c_str());

    std::vector<std::string> ips;

    boost::split(ips, res, boost::is_any_of(" "));

    return ips[0];

    return res;
}

