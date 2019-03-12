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

template <class Protocol>
class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy<Protocol>>
{
    enum SESSION_STATUS
    {
        SYN_RCVD,
        ESTABLISHED
    };

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io), send_socket_stream(io)
    {
        if (!send_socket_stream.is_open())
        {
            send_socket_stream.open();
        }
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

    size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield, bool shouldcopy = true)
    {

        unsigned char* copy_data;

        if (shouldcopy){
            copy_data = new unsigned char[size];
            memcpy(copy_data, data, size);
        }
        copy_data = (unsigned char*)data;

        asio::ip::raw::endpoint ep(boost::asio::ip::address::from_string(remote_ip), remote_port);
        boost::system::error_code ec;

        auto bytes_send = send_socket_stream.async_send_to(boost::asio::buffer(copy_data, size), ep, yield[ec]);

        if (ec)
        {
            LOG_INFO("async_send_to err --> {}", ec.message().c_str())
            return 0;
        }

        LOG_INFO("send {} bytes via raw socket", bytes_send)

        return bytes_send;
    }

private:
    Protocol protocol_;

    boost::asio::posix::stream_descriptor sniffer_socket;
    std::unique_ptr<Tins::Sniffer> psniffer;
    Tins::SnifferConfiguration config;
    bool isSnifferInit = false;
    bool isProxyRunning = false;
    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    SESSION_STATUS status;

    std::string remote_ip;
    std::string local_ip;

    unsigned short remote_port = 4444;

    unsigned short local_port = 4567;

    unsigned int local_seq = 10000;
    unsigned int last_ack = 0;

    void RecvFromLocal()
    {
        using Tins::PDU;
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

                auto tcp = pdu_ptr->find_pdu<TCP>();
                if (tcp == nullptr) continue;


                switch (tcp->flags())
                {
                    case (TCP::SYN):
                    {
                        LOG_INFO("recv syn seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                        auto ip = pdu_ptr->find_pdu<Tins::IP>();
                        remote_ip = ip->src_addr().to_string();
                        remote_port = tcp->sport();
                        handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
                        continue;
                    }
                        // without data
                    case TCP::ACK :
                    {
                        LOG_INFO("get ack seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())

                        if (this->status != ESTABLISHED) {
                            LOG_INFO("ESTABLISHED")
                            this->status = ESTABLISHED;
                        }
                        break;
                    }
                        // with data
                    case (TCP::PSH | TCP::ACK) :
                    {
                        LOG_INFO("get psh | ack seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                        ackReply(tcp->seq(), tcp->ack_seq(), tcp->inner_pdu()->size(), yield);

                        proxyUdp(tcp->inner_pdu());
                        break;
                    }
                    case TCP::RST :
                    {
                        LOG_INFO("rst")
                        break;
                    }
                    default:
                    {
                        LOG_INFO("default")
                        continue;
                    }
                }

                //LOG_INFO("read {} bytes\n", pdu_ptr->size())
            }

        });


    }


    void proxyUdp(Tins::PDU* raw_data)
    {

        if (raw_data == nullptr)
        {
            LOG_INFO("null raw_data")
            return;
        }

        // decrypt data
        auto protocol_hdr = (typename Protocol::ProtocolHeader*)raw_data->serialize().data();
        // decrypt packet and get payload length
        auto bytes_read = protocol_.OnUdpPayloadReadFromServerLocal(protocol_hdr);

        // fetch ip src port

        // find and new session

        // send data and recv session

        //






    }



    void handshakeReply(uint32_t remote_seq, uint32_t remote_ack, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        static time_t last_send_time = time(nullptr) - 22;

        auto now = time(nullptr);

        auto diff = now - last_send_time;
        if (diff < 1)
        {
            LOG_INFO("time short \n");
            return;
        }

        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK | TCP::SYN);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(local_seq);

        LOG_INFO("send syn ack back, seq: {}, ack: {}", local_seq, remote_seq + 1);

        sendPacket(tcp.serialize().data(), tcp.size(), yield);
        last_send_time = time(nullptr);

        this->last_ack = remote_seq;
        this->status = SYN_RCVD;
    }

    void ackReply(uint32_t remote_seq, uint32_t remote_ack, uint32_t packet_size, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK);
        // we always reply the latest seq as ack reply
        tcp.ack_seq(remote_seq + packet_size);
        tcp.seq(local_seq);
        LOG_INFO("ack reply")
        sendPacket(tcp.serialize().data(), tcp.size(), yield);
        this->last_ack = remote_seq;
    }


};