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
#include <boost/asio/ip/udp.hpp>
#include "../../../protocol/socks5_protocol_helper.h"
#include "../../../utils/ephash.h"
#include "../raw_proxy_helper/interface_helper.h"
#include "../raw_proxy_helper/firewall_helper.h"

#define MAX_HANDSHAKE_TRY 10

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
template <class Protocol>
class ClientUdpRawProxy : public Singleton<ClientUdpRawProxy<Protocol>>
{
    enum SESSION_STATUS
    {
        SYN_SENT,
        ESTABLISHED,
        DISCONNECT
    };

public:

    ClientUdpRawProxy(boost::asio::io_context& io, Protocol& prot, boost::shared_ptr<boost::asio::ip::udp::socket> pls) : protocol_(prot), sniffer_socket(io), plocal_socket(pls), send_socket_stream(io)
    {
        if (!send_socket_stream.is_open())
            send_socket_stream.open();
    }

    void SetUpSniffer(std::string remote_ip, std::string remote_port, std::string ifname = std::string())
    {

        //Get Default if ifname is not set
        if (ifname.empty())
            ifname = InterfaceHelper::GetInstance()->GetDefaultInterface();

        LOG_INFO("Find Default Interface {}", ifname)

        //setup sniffer
        config.set_filter("ip src "+ remote_ip + " and src port " + remote_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        //block tcp rst
        FirewallHelper::GetInstance()->BlockRst(remote_ip, remote_port);

        //save server endpoint
        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);
    }


    // we use local_port as the tcp src port to connect remote
    void StartProxy(std::string local_raw_port)
    {
        this->local_port = boost::lexical_cast<unsigned short>(local_raw_port);
        RecvFromRemote();
        TcpHandShake();
    }


    bool IsRemoteConnected() { return this->status == ESTABLISHED; }

    void TryConnect()
    {
        if (handshake_failed)
            TcpHandShake();
        return;
    }

    void SendPacketViaRaw(void* data, size_t size, boost::asio::yield_context& yield)
    {
        using Tins::TCP;
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::PSH | TCP::ACK);
        tcp.seq(local_seq);
        tcp.ack_seq(last_ack);

        auto payload = Tins::RawPDU((uint8_t*)data, size);

        tcp = tcp / payload;

        LOG_INFO("send {} bytes PSH | ACK seq: {}, ack: {}", size, tcp.seq(), tcp.ack_seq())
        sendPacket(tcp.serialize().data(), tcp.size(), yield);

        local_seq += tcp.size();
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
    Protocol& protocol_;

    boost::shared_ptr<boost::asio::ip::udp::socket> plocal_socket;

    Tins::SnifferConfiguration config;
    std::unique_ptr<Tins::Sniffer> psniffer;
    boost::asio::posix::stream_descriptor sniffer_socket;

    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    SESSION_STATUS status;

    std::string remote_ip;

    unsigned short local_port = 4567;
    unsigned short remote_port = 80;

    unsigned int local_seq = 20000;
    unsigned int init_seq = 20000;

    unsigned int last_ack = 0;

    bool handshake_failed = false;

    void RecvFromRemote()
    {
        //recv
        boost::asio::spawn(this->sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

            using Tins::TCP;
            while(1)
            {

                boost::system::error_code ec;
                this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);
                if (ec)
                {
                    LOG_INFO("wait err --> {}\n", ec.message().c_str());
                    return;
                }

                std::unique_ptr<Tins::PDU> pdu_ptr(this->psniffer->next_packet());

                auto tcp = pdu_ptr->find_pdu<TCP>();
                if (tcp == nullptr)
                {
                    LOG_INFO("TCP Header not found")
                    continue;
                }

                switch (tcp->flags())
                {
                    case (TCP::SYN):
                    {
                        LOG_INFO("SYN")
                        continue;
                    }
                    case (TCP::SYN | TCP::ACK):
                    {
                        LOG_INFO("recv SYN | ACK seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                        handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
                        continue;
                    }
                        // without data
                    case TCP::ACK :
                    {
                        LOG_INFO("recv ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
//                        if (tcp->ack_seq() > local_seq)
//                        {
//                            local_seq = tcp->ack_seq();
//                        }
                        break;
                    }
                        // with data
                    case (TCP::PSH | TCP::ACK) :
                    {
                        LOG_INFO("recv PSH | ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                        ackReply(tcp, yield);
                        sendToLocal(tcp->inner_pdu());
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

            }

        });
    }

    void TcpHandShake()
    {
        LOG_INFO("TcpHandShake Start")
        handshake_failed = false;
        static size_t handshake_count = 0;
        using Tins::TCP;
        //start up
        boost::asio::spawn(this->sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

            boost::asio::deadline_timer timer(this->sniffer_socket.get_io_context());
            boost::system::error_code ec;

            while(this->status != ESTABLISHED && handshake_count++ < MAX_HANDSHAKE_TRY)
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
            if (this->status != ESTABLISHED) {
                LOG_INFO("Raw Tcp handshake failed")
                handshake_failed = true;
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
        LOG_INFO("send handshake ACK back, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());
        sendPacket(tcp.serialize().data(), tcp.size(), yield);
        this->status = ESTABLISHED;
        last_send_time = time(nullptr);

        this->local_seq = init_seq + 1;
        this->last_ack = remote_seq;
    }

    void ackReply(Tins::TCP* remote_tcp, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        this->last_ack = remote_tcp->seq() + remote_tcp->inner_pdu()->size();

        auto tcp = TCP(remote_tcp->sport(), remote_tcp->dport());
        tcp.flags(TCP::ACK);

        tcp.ack_seq(this->last_ack);
        tcp.seq(local_seq);
        LOG_INFO("ACK Reply, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

        sendPacket(tcp.serialize().data(), tcp.size(), yield);
    }

    void sendToLocal(Tins::PDU* raw_data)
    {

        std::unique_ptr<unsigned char[]> data_copy(new unsigned char[raw_data->size()]);
        memcpy(data_copy.get(), raw_data->serialize().data(), raw_data->size());
        boost::asio::spawn([this, data_copy {std::move(data_copy)}](boost::asio::yield_context yield){

            // decrypt data
            auto protocol_hdr = (typename Protocol::ProtocolHeader*)data_copy.get();

            // decrypt packet and get payload length
            // n bytes protocol header + 6 bytes src ip port + 10 bytes socks5 header + payload
            auto bytes_read = protocol_.OnUdpPayloadReadFromClientRemote(protocol_hdr);

            char buff[6];
            uint32_t src_ip;
            uint16_t src_port;
            memcpy(&src_ip, &data_copy[Protocol::ProtocolHeader::Size()], 4);
            memcpy(&src_port, &data_copy[Protocol::ProtocolHeader::Size() + 4], 2);

            boost::asio::ip::udp::endpoint local_ep(boost::asio::ip::address::from_string(inet_ntoa(in_addr({src_ip}))), src_port);

            boost::system::error_code ec;

            LOG_INFO("send udp back to local {} : {}", local_ep.address().to_string(), local_ep.port())

            auto bytes_send = this->plocal_socket->async_send_to(boost::asio::buffer(data_copy.get() + Protocol::ProtocolHeader::Size() + 6, bytes_read - 6), local_ep, yield[ec]);

            if (ec)
            {
                LOG_INFO("async_send_to err --> {}", ec.message().c_str())
                return;
            }

            LOG_INFO("send {} bytes via raw socket", bytes_send)

        });

    }

};