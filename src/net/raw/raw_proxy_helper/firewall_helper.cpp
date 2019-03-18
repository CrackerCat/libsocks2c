#include "firewall_helper.h"
#include "../../../utils/logger.h"

#ifdef __APPLE__
void FirewallHelper::BlockRst(std::string dst_ip, std::string dst_port)
{
    //TODO add ip port filter
    std::string filewall_rule = "block drop proto tcp from " + dst_ip + " to any flags R/R";


}
#elif __linux__
void FirewallHelper::BlockRst(std::string dst_ip, std::string dst_port)
{
    std::string filewall_rule = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + dst_ip + " -j DROP";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)
    system(filewall_rule.c_str());
}
#endif