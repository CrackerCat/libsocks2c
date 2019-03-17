#include "firewall_helper.h"

#ifdef __APPLE__
void FirewallHelper::BlockRst(std::string dst_ip)
{

}
#elseif __linux__
void FirewallHelper::BlockRst(std::string dst_ip)
{
    std::string filewall_rule = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + dst_ip + " -j DROP";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)
    system(filewall_rule.c_str());
}
#endif