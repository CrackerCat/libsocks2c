#pragma once
#include "../../../utils/logger.h"
#include "../../../utils/singleton.h"
#include "../raw_socket.h"
#include <tins/tins.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/thread.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <boost/asio/deadline_timer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/unordered_map.hpp>
#include "server_udp_raw_proxy_session.h"
#include "../raw_proxy_helper/interface_helper.h"
#include "../raw_proxy_helper/firewall_helper.h"
#include "../sniffer_def.h"

template <class Protocol>
class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy<Protocol>>
{

    using SessionMap = boost::unordered_map<asio::ip::raw::endpoint, boost::shared_ptr<ServerUdpRawProxySession<Protocol>>, RawEpHash>;

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io) {}

    bool SetUpSniffer(std::string server_port, std::string server_ip = std::string(), std::string ifname = std::string())
    {
        //Get Default if ifname is not set
        if (ifname.empty())
            ifname = InterfaceHelper::GetInstance()->GetDefaultInterface();

        if (server_ip.empty())
            server_ip = InterfaceHelper::GetInstance()->GetDefaultNetIp();
        else
            server_ip = server_ip;

        if (ifname.empty() || server_ip.empty())
        {
            LOG_INFO("can not find default interface or ip")
            return false;
        }

        LOG_INFO("Find Default Interface {}", ifname)

        config.set_filter("ip dst "+ server_ip + " and dst port " + server_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);

        sniffer_socket.assign(psniffer->get_fd());

        //block tcp rst
        FirewallHelper::GetInstance()->BlockRst(server_ip, server_port);

        this->server_ep = asio::ip::raw::endpoint(boost::asio::ip::address::from_string(server_ip), boost::lexical_cast<unsigned short>(server_port));

        return true;
    }

    void SetProxyKey(std::string key)
    {
        bzero(this->proxyKey_, 32U);
        memcpy(this->proxyKey_, key.c_str(), key.size() < 32 ? key.size() : 32);
    }

    // start sniffing from local
    void StartProxy()
    {
        RecvFromLocal();
    }

private:

	SnifferSocket sniffer_socket;
    std::unique_ptr<Tins::Sniffer> psniffer;
    Tins::SnifferConfiguration config;

    SessionMap session_map_;

    asio::ip::raw::endpoint server_ep;

    unsigned char proxyKey_[32U];

    void RecvFromLocal()
    {
        using Tins::PDU;
        using Tins::IP;
        using Tins::TCP;

        //recv
        boost::asio::spawn(sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

            while(1)
            {

                boost::system::error_code ec;
                this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);
                if (ec)
                {
                    LOG_INFO("wait err")
                    return;
                }

                std::unique_ptr<PDU> pdu_ptr(this->psniffer->next_packet());

                auto ip = pdu_ptr->find_pdu<IP>();
                auto tcp = pdu_ptr->find_pdu<TCP>();

                if (ip == nullptr || tcp == nullptr) continue;

                asio::ip::raw::endpoint tcp_src_ep(boost::asio::ip::address::from_string(ip->src_addr().to_string()), tcp->sport());
				LOG_INFO("RAW TCP Packet from {}:{}", tcp_src_ep.address().to_string(), tcp_src_ep.port())

                auto map_it = session_map_.find(tcp_src_ep);
                // if new connection create session
                if (map_it == session_map_.end())
                {
                    LOG_INFO("new raw session")
                    //in_addr src_ip_addr = {src_ep.src_ip};
                    //std::string src_ip = inet_ntoa(src_ip_addr);
                    auto psession = boost::make_shared<ServerUdpRawProxySession<Protocol>>(sniffer_socket.get_io_context(), tcp_src_ep, server_ep, session_map_, this->proxyKey_);
                    psession->SaveOriginalTcpEp(tcp->sport(), tcp->dport());
                    psession->InitRawSocketAndTimer(sniffer_socket.get_io_context());
                    psession->HandlePacket(ip, tcp);
                    psession->Start();
                    session_map_.insert({tcp_src_ep, psession});

                }else { // if connection already created
                    LOG_INFO("old raw session")
                    auto psession = map_it->second;
                    psession->HandlePacket(ip, tcp);
                }
            }

        });


    }


};