#include "firewall.h"
#include "../../../../../utils/logger.h"

#ifdef __APPLE__
#include <boost/filesystem.hpp>

void Firewall::BlockRst(std::string dst_ip, std::string dst_port)
{
    boost::filesystem::path full_path {"/etc/pf.conf"};
    boost::filesystem::path bak_path {"/etc/pf.conf.bak"};

    // no copy if bak file exists
    if (!boost::filesystem::exists(full_path)){
        boost::system::error_code ec;
        boost::filesystem::copy_file(full_path, bak_path, boost::filesystem::copy_option::fail_if_exists, ec);
        boost::filesystem::remove(full_path);
    }

    boost::filesystem::ofstream ofs {full_path};
    std::string filewall_rule = "block drop proto tcp from any to " + dst_ip + " port " + dst_port + " flags R/R\n";
    LOG_DEBUG("Setting Firewall Rule: {}", filewall_rule)

    ofs << filewall_rule;
    ofs.close();

    system("pfctl -evf /etc/pf.conf &> /dev/null");

}
void Firewall::Unblock(std::string dst_ip, std::string dst_port)
{
    system("pfctl -d &> /dev/null");
}

#elif defined(__linux__)
void FirewallHelper::BlockRst(std::string dst_ip, std::string dst_port)
{
    std::string filewall_rule = "iptables -A OUTPUT -p tcp --sport " + dst_port + " --tcp-flags RST RST -s " + dst_ip + " -j DROP";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)
    system(filewall_rule.c_str());
}

void FirewallHelper::Unblock(std::string dst_ip, std::string dst_port)
{
    std::string filewall_rule = "iptables -D OUTPUT -p tcp --sport " + dst_port + " --tcp-flags RST RST -s " + dst_ip + " -j DROP";
    LOG_INFO("Setting Firewall Rule: {}", filewall_rule)
    system(filewall_rule.c_str());
}
#elif defined(_WIN32)
#include <windivert.h>
#include <Windows.h>
void Firewall::BlockRst(std::string dst_ip, std::string dst_port)
{
	std::string rst_filter = "outbound and !loopback and "
		"ip.DstAddr == " + dst_ip + " and "
		"tcp.SrcPort == " + dst_port + " and "
		"tcp.Rst";

	HANDLE rst_handle = WinDivertOpen(
		rst_filter.c_str(),
		WINDIVERT_LAYER_NETWORK, 0, 0
	);

	if (rst_handle == INVALID_HANDLE_VALUE)
	{
		LOG_INFO("BlockRst err, WinDivertOpen failed, you may need to run as administrator")
			return;
	}
}
#endif