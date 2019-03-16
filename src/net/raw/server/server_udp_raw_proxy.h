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


template <class Protocol>
class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy<Protocol>>
{

    using SessionMap = boost::unordered_map<tcp_session_src_tuple, boost::shared_ptr<ServerUdpRawProxySession<Protocol>>, TCPSrcTupleHash, TCPSrcTupleEQ>;

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io) {}

    void SetUpSniffer(std::string ifname, std::string server_ip, std::string server_port)
    {

        config.set_filter("ip dst "+ server_ip + " and dst port " + server_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        std::string filewall_rule_blocking_rst = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + server_ip + " -j DROP";
        system(filewall_rule_blocking_rst.c_str());

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


//    void proxyUdp(Tins::PDU* raw_data)
//    {
//
//        if (raw_data == nullptr)
//        {
//            LOG_INFO("null raw_data")
//            return;
//        }
//
//        auto full_data = raw_data->serialize().data();
//        // decrypt data
//        auto protocol_hdr = (typename Protocol::ProtocolHeader*)full_data;
//        // decrypt packet and get payload length
//        // n bytes protocol header + 6 bytes src ip port + 10 bytes socks5 header + payload
//        auto bytes_read = protocol_.OnUdpPayloadReadFromServerLocal(protocol_hdr);
//
//        ep_tuple ep_tp;
//        std::string ip_str;
//        if (!Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(full_data + Protocol::ProtocolHeader::Size() + 4, ip_str, ep_tp.dst_port))
//        {
//            LOG_INFO("unable to parse socks5 udp header")
//            return;
//        }
//        auto ip_dst_bytes = boost::asio::ip::address::from_string(ip_str).to_v4().to_bytes();
//        memcpy(&ep_tp.dst_ip, &ip_dst_bytes[0], 4);
//        memcpy(&ep_tp.src_ip, full_data + Protocol::ProtocolHeader::Size(), 4);
//        memcpy(&ep_tp.src_port, full_data + Protocol::ProtocolHeader::Size() + 4, 2);
//
//
//        auto map_it = session_map_.find(local_ep_);
//        if (map_it == session_map_.end())
//        {
//
//
//
//
//
//        }else
//        {
//
//
//
//
//        }
//        // fetch ip src port
//
//        // find and new session
//
//        // send data and recv session
//
//        //
//
//
//    }
//
//
//
//    void ackReply(uint32_t remote_seq, uint32_t remote_ack, uint32_t packet_size, boost::asio::yield_context yield)
//    {
//        using Tins::TCP;
//        auto tcp = TCP(remote_port, local_port);
//        tcp.flags(TCP::ACK);
//        // we always reply the latest seq as ack reply
//        tcp.ack_seq(remote_seq + packet_size);
//        tcp.seq(local_seq);
//        LOG_INFO("ack reply")
//        sendPacket(tcp.serialize().data(), tcp.size(), yield);
//        this->last_ack = remote_seq;
//    }


};