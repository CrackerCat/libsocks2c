#include "firewall_helper.h"
#include "../../../utils/logger.h"

#ifdef __APPLE__
#include <boost/filesystem.hpp>
void FirewallHelper::BlockRst(std::string dst_ip, std::string dst_port)
{
    boost::filesystem::path full_path {"/etc/pf.conf"};
    boost::filesystem::path bak_path {"/etc/pf.conf.bak"};

    // no copy if bak file exists
    if (boost::filesystem::exists(full_path)){
        boost::system::error_code ec;
        boost::filesystem::copy_file(full_path, bak_path, boost::filesystem::copy_option::fail_if_exists, ec);
        boost::filesystem::remove(full_path);
    }

    boost::filesystem::ofstream ofs {full_path};
    std::string filewall_rule = "block drop proto tcp from " + dst_ip + " to any flags R/R\n";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)

    ofs << filewall_rule;
    ofs.close();

    system ("pfctl -evf /etc/pf.conf");

}
#elif __linux__
void FirewallHelper::BlockRst(std::string dst_ip, std::string dst_port)
{
    std::string filewall_rule = "iptables -A OUTPUT -p tcp --sport " + dst_port + " --tcp-flags RST RST -s " + dst_ip + " -j DROP";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)
    system(filewall_rule.c_str());
}
#endif