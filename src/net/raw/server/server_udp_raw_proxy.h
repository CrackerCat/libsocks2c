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
#include "../../../protocol/socks5_protocol_helper.h"


template <class Protocol>
class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy<Protocol>>
{
    enum SESSION_STATUS
    {
        SYN_RCVD,
        ESTABLISHED
    };

    using SESSION_MAP = boost::unordered_map<udp2raw_session_ep_tuple, ServerUdpRawProxySession, EndPointTupleHash>;

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io)
    {

    }

    void SetUpSniffer(std::string ifname, std::string local_ip, std::string local_port)
    {
        if (isSnifferInit) return;

        config.set_filter("ip src "+ local_ip + " and src port " + local_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        std::string filewall_rule_blocking_rst = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + local_ip + " -j DROP";
        system(filewall_rule_blocking_rst.c_str());

        this->local_ip = local_ip;
        this->local_port = boost::lexical_cast<unsigned short>(local_port);

        isSnifferInit = true;
    }


    void StartProxy(uint16_t local_port)
    {
        if (isProxyRunning) return;
        this->local_port = local_port;
        RecvFromLocal();
        isProxyRunning = true;
    }

    size_t SendPacketViaRaw(void* data, size_t size, boost::asio::yield_context& yield)
    {
        using Tins::TCP;
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::PSH | TCP::ACK);
        //local_seq += size;
        tcp.seq(local_seq);
        tcp.ack_seq(last_ack + 1);

        auto payload = Tins::RawPDU((uint8_t*)data, size);

        tcp = tcp / payload;

        LOG_INFO("send {} bytes PSH | ACK seq: {}, ack: {}", size, tcp.seq(), tcp.ack_seq())
        return sendPacket(tcp.serialize().data(), tcp.size(), yield);

    }



private:
    Protocol protocol_;

    boost::asio::posix::stream_descriptor sniffer_socket;
    std::unique_ptr<Tins::Sniffer> psniffer;
    Tins::SnifferConfiguration config;
    bool isSnifferInit = false;
    bool isProxyRunning = false;

    SESSION_MAP session_map_;


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
                udp2raw_session_ep_tuple src_ep;
                src_ep.src_ip = ip->src_addr().uint32_t();
                src_ep.src_port = tcp->sport();

                auto map_it = session_map_.find(src_ep);
                // if new connection create session
                if (map_it == session_map_.end())
                {
                    auto psession = boost::make_shared<ServerUdpRawProxySession>(ip->src_addr().uint32_t(), tcp->sport());

                    psession->HandlePacket(ip, tcp);


                    //session_map_.insert()

                }else { // if connection already created



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