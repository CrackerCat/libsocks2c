#pragma once
#include "../../../utils/logger.h"
#include "../../../utils/singleton.h"
#include "../raw_socket.h"
#include <tins/tins.h>
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


template <class Protocol>
class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy<Protocol>>
{

    using SessionMap = boost::unordered_map<tcp_session_src_tuple, boost::shared_ptr<ServerUdpRawProxySession<Protocol>>, TCPSrcTupleHash, TCPSrcTupleEQ>;

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io) {}

    void SetUpSniffer(std::string server_port, std::string server_ip = std::string(), std::string ifname = std::string())
    {
        if (ifname.empty())
            ifname = InterfaceHelper::GetInstance()->GetDefaultInterface();

        if (server_ip.empty())
            server_ip = InterfaceHelper::GetInstance()->GetDefaultNetIp();


        LOG_INFO("Find Default Interface {}", ifname)

        config.set_filter("ip dst "+ server_ip + " and dst port " + server_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        //block tcp rst
        FirewallHelper::GetInstance()->BlockRst(server_ip);

        //this->local_ip = local_ip;
        //this->local_port = boost::lexical_cast<unsigned short>(local_port);
    }

    void SetProxyKey(std::string key)
    {
        bzero(this->proxyKey_, 32U);
        memcpy(this->proxyKey_, key.c_str(), key.size() < 32 ? key.size() : 32);
    }

    void StartProxy()
    {
        RecvFromLocal();
    }

private:

    boost::asio::posix::stream_descriptor sniffer_socket;
    std::unique_ptr<Tins::Sniffer> psniffer;
    Tins::SnifferConfiguration config;

    SessionMap session_map_;

    unsigned char proxyKey_[32U];

    unsigned short remote_port = 4444;

    unsigned short local_port = 4567;

    unsigned int local_seq = 10000;
    unsigned int last_ack = 0;

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

                // when recv tcp packet from local
                // find session by src ip port pair
                tcp_session_src_tuple src_ep = {};
                src_ep.src_ip = inet_addr(ip->src_addr().to_string().c_str());
                src_ep.src_port = tcp->sport();


                auto map_it = session_map_.find(src_ep);
                // if new connection create session
                if (map_it == session_map_.end())
                {
                    in_addr src_ip_addr = {src_ep.src_ip};
                    std::string dst_ip = inet_ntoa(src_ip_addr);
                    auto psession = boost::make_shared<ServerUdpRawProxySession<Protocol>>(dst_ip, src_ep.src_port, session_map_, this->proxyKey_);
                    psession->SaveOriginalTcpEp(tcp->sport(), tcp->dport());
                    psession->InitRawSocket(sniffer_socket.get_io_context());
                    psession->HandlePacket(ip, tcp);
                    session_map_.insert({src_ep, psession});

                }else { // if connection already created
                    auto psession = map_it->second;
                    psession->HandlePacket(ip, tcp);
                }
            }

        });


    }


};