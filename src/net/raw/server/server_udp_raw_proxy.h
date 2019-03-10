#pragma once
#include "../../../utils/singleton.h"
#include "../../../utils/logger.h"
#include "../raw_socket.h"
#include <tins/tins.h>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/thread.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>

class ServerUdpRawProxy : public Singleton<ServerUdpRawProxy>
{
    enum SESSION_STATUS
    {
        SYN_RCVD,
        ESTABLISHED
    };

public:

    ServerUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io)
    {
        send_socket_stream.open();
    }

    void SetUpSniffer(std::string ifname, std::string client_ip, std::string client_port)
    {
        config.set_filter("ip dst "+ client_ip + " and dst port " + client_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + client_ip + " -j DROP");

        this->client_port = client_port;

    }


    void StartProxy(uint16_t listen_port)
    {
        this->listen_port = listen_port;
        ListenAndRecv();
    }

private:

    boost::asio::posix::stream_descriptor sniffer_socket;
    std::unique_ptr<Sniffer> psniffer;
    SnifferConfiguration config;

    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    SESSION_STATUS status;

    unsigned short listen_port = 4567;
    unsigned short client_port = 80;

    unsigned int local_seq = 10000;
    unsigned int last_ack = 0;

    void sendPacket(void* data, size_t size)
    {

        auto copy_data = new unsigned char[size];
        memcpy(copy_data, data, size);

        boost::asio::ip::address_v4::bytes_type b = {{127, 0, 0, 1}};
        asio::ip::raw::endpoint ep(boost::asio::ip::address_v4(b), 4567);

        boost::system::error_code ec;

        send_socket_stream.async_send_to(boost::asio::buffer(copy_data, size), ep, [](const boost::system::error_code& ec, size_t bytes_send){
            if (ec)
            {
                LOG_INFO("async_send_to err --> {}", ec.message().c_str())
                return;
            }
            //LOG_INFO("send {} bytes vie raw socket", bytes_send)
        });
    }


    void ListenAndRecv()
    {
        //recv
        boost::asio::spawn(io, [this](boost::asio::yield_context yield){

            int i = 1;
            while(1)
            {

                boost::system::error_code ec;
                this->socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);
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
                        LOG_INFO("recv handshake SYN seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                        handshakeReply(tcp->seq(), tcp->ack_seq());
                        continue;
                    }
                        // without data
                    case TCP::ACK :
                    {
                        LOG_INFO("recv ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())

                        if (this->status != ESTABLISHED) {
                            LOG_INFO("ESTABLISHED")
                            this->status = ESTABLISHED;
                        }
                        break;
                    }
                        // with data
                    case (TCP::PSH | TCP::ACK) :
                    {
                        auto v = tcp->serialize();
                        auto size = v.size();
                        LOG_INFO("recv {} bytes, PSH | ACK seq: {}, ack: {}", pdu_ptr->serialize().size(), tcp->seq(), tcp->ack_seq())
                        ackReply(tcp->seq(), tcp->ack_seq());
                        break;
                    }
                    case TCP::RST :
                    {
                        LOG_INFO("recv RST")
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

    void handshakeReply(uint32_t remote_seq, uint32_t remote_ack)
    {
        static time_t last_send_time = time(nullptr) - 1;

        if (time(nullptr) - last_send_time < 1)
        {
            LOG_INFO("time short \n");
            return;
        }

        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK | TCP::SYN);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(local_seq);

        LOG_INFO("send handshake SYN | ACK back seq: {}, ack: {}", local_seq, remote_seq + 1);

        sendPacket(tcp.serialize().data(), tcp.size());
        last_send_time = time(nullptr);

        this->last_ack = remote_seq;
        this->status = SYN_RCVD;
    }

    void ackReply(uint32_t remote_seq, uint32_t remote_ack)
    {
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(local_seq);
        LOG_INFO("ack reply seq: {}, ack: {}", local_seq, remote_seq + 1)
        sendPacket(tcp.serialize().data(), tcp.size());
        this->last_ack = remote_seq;
    }

};