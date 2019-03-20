#pragma once
#include "../../../utils/logger.h"
#include "../../../utils/singleton.h"
#include "../raw_socket.h"
#include <tins/tins.h>
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
#include "../raw_proxy_helper/tcp_checksum_helper.h"
#include "../sniffer_def.h"

#include "basic_client_udp_raw_proxy.h"

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
class ClientUdpRawProxy : public BasicClientUdpRawProxy<Protocol>, public Singleton<ClientUdpRawProxy<Protocol>>
{

public:

    ClientUdpRawProxy(boost::asio::io_context& io, Protocol& prot, boost::shared_ptr<boost::asio::ip::udp::socket> pls) : \
        BasicClientUdpRawProxy<Protocol>(io, prot),
        protocol_(prot), sniffer_socket(io), plocal_socket(pls), send_socket_stream(io)
    {
        if (!send_socket_stream.is_open())
            send_socket_stream.open();
        this->init_seq = time(nullptr);
        this->local_seq = this->init_seq;
    }

    virtual void SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_raw_port, std::string local_ip = std::string(), std::string ifname = std::string()) override
    {

        this->local_port = boost::lexical_cast<unsigned short>(local_raw_port);

        //Get Default if ifname is not set
        if (ifname.empty())
            ifname = InterfaceHelper::GetInstance()->GetDefaultInterface();
        if (local_ip.empty())
        {
            local_ip = InterfaceHelper::GetInstance()->GetDefaultNetIp();
        }else
        {
            this->local_ip = local_ip;
        }

        LOG_INFO("Find Default Interface {}", ifname)

        //setup sniffer
        config.set_filter("ip src "+ remote_ip + " and src port " + remote_port);
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        //block tcp rst
        FirewallHelper::GetInstance()->BlockRst(local_ip, local_raw_port);

        //save server endpoint
        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);
    }


    // we use local_port as the tcp src port to connect remote
    void StartProxy(std::string local_raw_port)
    {
        RecvFromRemote();
        this->TcpHandShake();
    }


    bool IsRemoteConnected() { return this->status == this->ESTABLISHED; }

    void TryConnect()
    {
        if (this->handshake_failed)
            this->TcpHandShake();
        return;
    }

    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield, bool shouldcopy = true) override
    {

        unsigned char* copy_data;

        if (shouldcopy){
            copy_data = new unsigned char[size];
            memcpy(copy_data, data, size);
        }
        copy_data = (unsigned char*)data;

        asio::ip::raw::endpoint ep(boost::asio::ip::address::from_string(this->remote_ip), this->remote_port);
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
    SnifferSocket sniffer_socket;

    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    virtual void RecvFromRemote()
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
                        this->handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
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
                        this->ackReply(tcp, yield);
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

    virtual void TcpHandShake() override
    {
        LOG_INFO("TcpHandShake Start")
        this->handshake_failed = false;
        static size_t handshake_count = 0;
        using Tins::TCP;
        using Tins::IP;

        //start up
        boost::asio::spawn(this->sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

            boost::asio::deadline_timer timer(this->sniffer_socket.get_io_context());
            boost::system::error_code ec;

            while(this->status != this->ESTABLISHED && handshake_count++ < MAX_HANDSHAKE_TRY)
            {

                auto ip = IP(this->remote_ip, this->local_ip);

                auto tcp = TCP(this->remote_port, this->local_port);
                tcp.flags(TCP::SYN);
                tcp.seq(this->init_seq);

                LOG_INFO("send SYN seq: {}, ack: {}", tcp.seq(), tcp.ack_seq())

                ip = ip / tcp;

                auto vip_data = ip.serialize();
                auto ip_data = vip_data.data();
                CalTcpChecksum(ip, ip_data);

                // we send tcp only, ip hdr is for checksum cal only
                auto bytes_send = sendPacket(ip_data + ip.header_size(), tcp.size(), yield);

                timer.expires_from_now(boost::posix_time::seconds(2));
                timer.async_wait(yield[ec]);
                if (ec)
                {
                    LOG_INFO("timer async_wait err")
                    return;
                }
            }
            if (this->status != this->ESTABLISHED) {
                LOG_INFO("Raw Tcp handshake failed")
                this->handshake_failed = true;
            }

        });

    }


    virtual void sendToLocal(Tins::PDU* raw_data) override
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