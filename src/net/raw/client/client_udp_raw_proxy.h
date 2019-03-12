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






/*
 * ClientUdpProxySession run in single thread mode
 * only client_udp_proxy_session will interact with this class when sending packet
 *
 * when recv packet from remote, we need to parse the dst endpoint which is encrypted together with data
 * format:
 * ip(4 bytes) + port(2 bytes) + data
 * and send it to local via raw socket
 *
 * when sending packet to remote
 */
class ClientUdpRawProxy : public Singleton<ClientUdpRawProxy>
{
    enum SESSION_STATUS
    {
        SYN_SENT,
        ESTABLISHED
    };

public:

    ClientUdpRawProxy(boost::asio::io_context& io) : sniffer_socket(io), send_socket_stream(io)
    {
        if (!send_socket_stream.is_open())
        {
            send_socket_stream.open();
        }
    }

    void SetUpSniffer(std::string ifname, std::string remote_ip, std::string remote_port)
    {
        if (isSnifferInit) return;

        config.set_filter("ip src "+ remote_ip + " and src port " + remote_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        std::string filewall_rule_blocking_rst = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -s " + remote_ip + " -j DROP";
        system(filewall_rule_blocking_rst.c_str());

        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);

        isSnifferInit = true;
    }


    void StartProxy(uint16_t local_port)
    {
        if (isProxyRunning) return;
        this->local_port = local_port;
        RecvFromRemote();
        TcpHandShake();
        isProxyRunning = true;
    }


    bool IsRemoteConnected() { return this->status == ESTABLISHED; }


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

        boost::asio::ip::address_v4::bytes_type b = {{127, 0, 0, 1}};
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

    boost::asio::posix::stream_descriptor sniffer_socket;
    std::unique_ptr<Tins::Sniffer> psniffer;
    Tins::SnifferConfiguration config;
    bool isSnifferInit = false;
    bool isProxyRunning = false;
    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    SESSION_STATUS status;

    std::string remote_ip;

    unsigned short local_port = 4567;
    unsigned short remote_port = 80;

    unsigned int local_seq = 20000;
    unsigned int init_seq = 20000;

    unsigned int last_ack = 0;

    void RecvFromRemote();

    void TcpHandShake()
    {
        LOG_INFO("TcpHandShake Start")
        using Tins::TCP;
        //start up
        boost::asio::spawn(this->sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

            boost::asio::deadline_timer timer(this->sniffer_socket.get_io_context());
            boost::system::error_code ec;

            while(this->status != ESTABLISHED)
            {
                auto tcp = TCP(remote_port, local_port);
                tcp.flags(TCP::SYN);
                tcp.seq(init_seq);

                LOG_INFO("send SYN seq: {}, ack: {}", tcp.seq(), tcp.ack_seq())

                auto bytes_send = sendPacket(tcp.serialize().data(), tcp.size(), yield);

                timer.expires_from_now(boost::posix_time::seconds(2));
                timer.async_wait(yield[ec]);
                if (ec)
                {
                    LOG_INFO("timer async_wait err")
                    return;
                }
            }

        });

    }

    void handshakeReply(uint32_t remote_seq, uint32_t remote_ack, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        static time_t last_send_time = time(nullptr) - 1;

        if (time(nullptr) - last_send_time < 1)
        {
            printf("short time\n");
            return;
        }

        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(++local_seq);
        LOG_INFO("send handshake ACK back, seq: {}, ack: {}", local_seq, remote_seq + 1);
        sendPacket(tcp.serialize().data(), tcp.size(), yield);
        this->status = ESTABLISHED;
        last_send_time = time(nullptr);

        this->local_seq = init_seq + 1;
        this->last_ack = remote_seq;
    }

    void ackReply(uint32_t remote_seq, uint32_t remote_ack)
    {
        using Tins::TCP;

        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(local_seq);
        //sendPacket(tcp.serialize().data(), tcp.size());
        this->last_ack = remote_seq;
    }


};