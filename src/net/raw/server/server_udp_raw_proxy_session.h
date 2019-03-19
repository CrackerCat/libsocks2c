#pragma once
#include <boost/enable_shared_from_this.hpp>
#include "../../../utils/ephash.h"
#include <boost/unordered_map.hpp>
#include <tins/ip.h>
#include <tins/tcp.h>
#include "../raw_socket.h"
#include "../../../protocol/socks5_protocol_helper.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <random>
#include "../raw_proxy_helper/tcp_checksum_helper.h"

#define UDP_PROXY_SESSION_TIMEOUT 60

template <class Protocol>
class ServerUdpRawProxySession : public boost::enable_shared_from_this<ServerUdpRawProxySession<Protocol>>
{
    enum SESSION_STATUS
    {
        INIT,
        SYN_RCVD,
        ESTABLISHED
    };

    using SessionMap = boost::unordered_map<tcp_session_src_tuple, boost::shared_ptr<ServerUdpRawProxySession<Protocol>>, TCPSrcTupleHash, TCPSrcTupleEQ>;

    using RawSenderSocket = boost::asio::basic_raw_socket<asio::ip::raw>;
    using PRawSenderSocket = std::unique_ptr<RawSenderSocket>;

    class udp_proxy_session;
    using UdpSessionMap = boost::unordered_map<udp_ep_tuple, boost::shared_ptr<udp_proxy_session>, UdpEndPointTupleHash, UdpEndPointTupleEQ>;
    class udp_proxy_session : public boost::enable_shared_from_this<udp_proxy_session>
    {


    public:
        udp_proxy_session(boost::shared_ptr<ServerUdpRawProxySession<Protocol>> server, boost::asio::io_context& io, UdpSessionMap& map) : pserver(server), io_context_(io), udpsession_map(map), remote_socket_(io), timer(io)
        {
            last_active_time = time(nullptr);
            this->remote_socket_.open(remote_recv_ep_.protocol());
        }


        void SaveSrcEndpoint(udp_ep_tuple src)
        {
            src_ep = src;
        }

        // copy data, start coroutine and send it
        void SendToRemote(void* data, size_t size, const boost::asio::ip::udp::endpoint& remote_ep)
        {

            last_active_time = time(nullptr);

            auto self(this->shared_from_this());

            std::unique_ptr<char[]> copy_data(new char[size]);
            memcpy(copy_data.get(), data, size);

            boost::asio::spawn([this, self, copy_data { std::move(copy_data) }, size, remote_ep { std::move(remote_ep) }](boost::asio::yield_context yield){

                boost::system::error_code ec;

                auto bytes_send = this->remote_socket_.async_send_to(boost::asio::buffer(copy_data.get(), size),
                                                                     remote_ep, yield[ec]);

                if (ec)
                {
                    UDP_DEBUG("onRemoteSend err --> {}", ec.message().c_str())
                    return;
                }

                LOG_INFO("send {} bytes udp data to remote", bytes_send)

            });
        }

        void Start()
        {
            readFromRemote();
            runTimer();
        }

    private:

        boost::asio::io_context& io_context_;

        UdpSessionMap& udpsession_map;

        boost::shared_ptr<ServerUdpRawProxySession<Protocol>> pserver;
        boost::asio::ip::udp::socket remote_socket_;
        boost::asio::ip::udp::endpoint remote_recv_ep_;
        boost::asio::deadline_timer timer;
        size_t last_active_time;

        udp_ep_tuple src_ep;

        unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];
        unsigned char remote_recv_buff_[UDP_REMOTE_RECV_BUFF_SIZE];


        void readFromRemote()
        {
            auto self(this->shared_from_this());
            boost::asio::spawn([this, self](boost::asio::yield_context yield){

                while (1)
                {
                    boost::system::error_code ec;

                    // 10 extra bytes reserved for socks5 udp header
                    uint64_t bytes_read = this->remote_socket_.async_receive_from(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size() + 6 + 10, UDP_REMOTE_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 6 - 10), remote_recv_ep_, yield[ec]);

                    if (ec)
                    {
                        UDP_DEBUG("Udp readFromRemote err --> {}", ec.message().c_str())
                        return 0;
                    }
                    
                    last_active_time = time(nullptr);

                    LOG_INFO("recv {} bytes udp data from remote", bytes_read)

                    for (int i = 0; i < bytes_read; i++)
                    {
                        printf("%x ", remote_recv_buff_[Protocol::ProtocolHeader::Size() + 6 + 10 + i]);
                    }

                    auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;
                    Socks5ProtocolHelper::ConstructSocks5UdpPacketFromIpStringAndPort(remote_recv_buff_ + Protocol::ProtocolHeader::Size() + 6, remote_recv_ep_.address().to_string(), remote_recv_ep_.port());
                    // paddle the socks5 udp header
                    LOG_INFO("encrypting payload size {}", bytes_read + 10 + 6)

                    memcpy(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), &this->src_ep.src_ip, 4);
                    memcpy(remote_recv_buff_ + Protocol::ProtocolHeader::Size() + 4, &this->src_ep.src_port, 2);

                    protocol_hdr->PAYLOAD_LENGTH = bytes_read + 10 + 6;

                    auto bytes_tosend = pserver->GetProtocol().OnUdpPayloadReadFromServerRemote(protocol_hdr);

                    pserver->SendPacketViaRaw(remote_recv_buff_, bytes_tosend);

                }


            });
        }

        void runTimer()
        {
            auto self(this->shared_from_this());
            boost::asio::spawn([this, self](boost::asio::yield_context yield){

                while (1)
                {
                    boost::system::error_code ec;
                    this->timer.expires_from_now(boost::posix_time::seconds(10));
                    this->timer.async_wait(yield[ec]);

                    if (ec)
                    {
                        LOG_INFO("udp_proxy_session(raw) err -->{}", ec.message())
                        return;
                    }

                    // if session timeout
                    if (time(nullptr) - last_active_time > UDP_PROXY_SESSION_TIMEOUT)
                    {
                        this->remote_socket_.cancel();
                        this->udpsession_map.erase(src_ep);
                        return;
                    }

                }
            });
        }
    };

public:

    ServerUdpRawProxySession(std::string local_ip, uint16_t local_port, std::string server_ip, uint16_t server_port, SessionMap& map_ref, unsigned char key[32U]) : session_map(map_ref)
    {
        this->protocol_.SetKey(key);
        local_ep = asio::ip::raw::endpoint(boost::asio::ip::address::from_string(local_ip), local_port);
        server_ep = asio::ip::raw::endpoint(boost::asio::ip::address::from_string(server_ip), server_port);

        this->init_seq = time(nullptr);
        this->server_seq = init_seq;
    }

    void InitRawSocket(boost::asio::io_context& io)
    {
        prawsender_socket = std::make_unique<RawSenderSocket>(io);
        prawsender_socket->open();
    }

    void SaveOriginalTcpEp(uint16_t sport, uint16_t dport)
    {
        this->tcp_sport = sport;
        this->tcp_dport = dport;
    }

    Protocol& GetProtocol()
    {
        return this->protocol_;
    }

    // ip && tcp always vaild
    bool HandlePacket(Tins::IP* ip, Tins::TCP* tcp)
    {

        using Tins::TCP;
        switch (tcp->flags())
        {
            // client start syn process
            // send syn | ack reply back base on client's seq number
            // turn status to SYN_RCVD
            // client may send multiple syn req
            // we send reply back for each syn
            case (TCP::SYN):
            {
                LOG_INFO("recv syn seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                // clone tcp cause we have to start new coroutine context
                handshakeReply(tcp);
                this->status = SYN_RCVD;
                return true;
            }
            // if client send ack which ack match the init seq + 1,
            // which means the connection is established
            // set status to ESTABLISHED
            case TCP::ACK :
            {
                LOG_INFO("GET ACK, seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())

                if (this->status != ESTABLISHED) {
                    LOG_INFO("ESTABLISHED")
                    this->status = ESTABLISHED;
                }

                if (tcp->inner_pdu() != nullptr)
                    proxyUdp(tcp->inner_pdu());

                break;
            }
            // when recv data
            // decrypt first
            case (TCP::PSH | TCP::ACK) :
            {

                //send rst back if not connect
//                if (this->status != ESTABLISHED)
//                {
//                    sendRst(tcp);
//                    return false;
//                }

                LOG_INFO("GET PSH | ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                ackReply(tcp);
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
            }
        }

        return true;
    }


    void SendPacketViaRaw(void* data, size_t size)
    {
        using Tins::IP;
        using Tins::TCP;

        auto ip = IP(local_ep.address().to_string(), server_ep.address().to_string());

        // swap sport and dport here cause we are sending data back
        auto tcp = TCP(tcp_sport, tcp_dport);
        tcp.flags(TCP::PSH | TCP::ACK);
        tcp.seq(server_seq);
        tcp.ack_seq(server_ack);

        auto payload = Tins::RawPDU((uint8_t*)data, size);

        tcp = tcp / payload;

        ip = ip / tcp;

        auto vip_data = ip.serialize();
        auto ip_data = vip_data.data();
        CalTcpChecksum(ip, ip_data);

        // we send tcp only, ip hdr is for checksum cal only
        sendPacket(ip_data + ip.header_size(), tcp.size());
        LOG_INFO("send {} bytes PSH | ACK seq: {}, ack: {}", size, tcp.seq(), tcp.ack_seq())

        server_seq += (tcp.size() - tcp.header_size());
    }


private:
    Protocol protocol_;

    SessionMap& session_map;
    UdpSessionMap udpsession_map;

    SESSION_STATUS status;

    // store client's tcp src ip src port
    asio::ip::raw::endpoint local_ep;
    asio::ip::raw::endpoint server_ep;

    uint16_t tcp_sport;
    uint16_t tcp_dport;

    PRawSenderSocket prawsender_socket;

    uint32_t server_seq;
    uint32_t init_seq;
    uint32_t server_ack = 0;

    void handshakeReply(Tins::TCP* local_tcp)
    {
        static time_t last_send_time = time(nullptr) - 22;

        auto now = time(nullptr);

        auto diff = now - last_send_time;
        if (diff < 1)
        {
            LOG_INFO("time short \n");
            return;
        }

        // swap src port and dst port
        auto tcp_reply = Tins::TCP(local_tcp->sport(), local_tcp->dport());
        tcp_reply.flags(Tins::TCP::ACK | Tins::TCP::SYN);
        tcp_reply.ack_seq(local_tcp->seq() + 1); // +1 client's seq
        tcp_reply.seq(init_seq++);

        LOG_INFO("send syn ack back, seq: {}, ack: {}", tcp_reply.seq(), tcp_reply.ack_seq());

        auto ip = Tins::IP(local_ep.address().to_string(), server_ep.address().to_string());

        ip = ip / tcp_reply;

        LOG_INFO("cal checksum")
        auto bytes_tosend = tcp_reply.serialize().size();

        auto vip_data = ip.serialize();
        auto ip_data = vip_data.data();
//        printf("before cal\n");
//        for (int i = 0; i < bytes_tosend; i++)
//        {
//            printf("%x ", ip_data[ip.header_size() + i]);
//            fflush(stdout);
//        }
        //printf("\n");
        CalTcpChecksum(ip, ip_data);
//        printf("after cal\n");
//        for (int i = 0; i < bytes_tosend; i++)
//        {
//            printf("%x ", ip_data + ip.header_size() + i);
//            fflush(stdout);
//        }
//        printf("\n");

        // we send tcp only, ip hdr is for checksum cal only
        LOG_INFO("iphdr size {} handshake reply {} bytes", ip.header_size(), bytes_tosend)
        sendPacket(ip_data + ip.header_size(), bytes_tosend);
        last_send_time = time(nullptr);
        //this->server_ack = local_tcp->seq() + 1;
    }

    // data will be copy
    // use this method to send TCP data
    void sendPacket(void* data, size_t size)
    {

        auto self(this->shared_from_this());
        std::unique_ptr<unsigned char[]> copy_data(new unsigned char[size]);
        memcpy(copy_data.get(), data, size);

        boost::asio::spawn([this, self, copy_data{std::move(copy_data)}, size](boost::asio::yield_context yield){

            boost::system::error_code ec;

            for (int i = 0; i < size; i++)
            {
                printf("%x ", copy_data[i]);
                fflush(stdout);
            }
            printf("\n");
            fflush(stdout);
            auto bytes_send = prawsender_socket->async_send_to(boost::asio::buffer(copy_data.get(), size), local_ep, yield[ec]);

            if (ec)
            {
                LOG_INFO("async_send_to err --> {}", ec.message().c_str())
                return 0;
            }

            LOG_INFO("send {} bytes via raw socket", bytes_send)

        });

    }


    void proxyUdp(Tins::PDU* raw_data)
    {
        auto data_copy = raw_data->clone();

        auto self(this->shared_from_this());
        boost::asio::spawn([this, self, data_copy](boost::asio::yield_context yield){

            LOG_INFO("TCP DATA SIZE {}", data_copy->size());

            auto full_data = data_copy->serialize();

            // decrypt data
            auto protocol_hdr = (typename Protocol::ProtocolHeader*)&full_data[0];
            // decrypt packet and get payload length
            // n bytes protocol header + 6 bytes src ip port + 10 bytes socks5 header + payload
            auto bytes_read = protocol_.OnUdpPayloadReadFromServerLocal(protocol_hdr);

            if (bytes_read == 0 || bytes_read > UDP_LOCAL_RECV_BUFF_SIZE)
            {
                LOG_INFO("decrypt err")
                return;
            }

            udp_ep_tuple udp_ep = {0};

            udp_ep.src_ip = *(uint32_t*)&full_data.at(Protocol::ProtocolHeader::Size());
            udp_ep.src_port = *(uint16_t*)&full_data.at(Protocol::ProtocolHeader::Size() + 4);

            std::string ip_dst;
            if (!Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(full_data.data() + Protocol::ProtocolHeader::Size() + 4 + 2, ip_dst, udp_ep.dst_port))
            {
                LOG_INFO("unable to parse socks5 udp header")
                return;
            }

            std::string src_ip_str = inet_ntoa(in_addr({udp_ep.src_ip}));
            LOG_INFO("raw packet from {}:{} to {}:{}", src_ip_str, udp_ep.src_port, ip_dst, udp_ep.dst_port)

            // hdr size include the protocol hdr + src ip + src port + socks5 hdr
            size_t header_size = Protocol::ProtocolHeader::Size() + 4 + 2 + 10;
            boost::asio::ip::udp::endpoint remote_ep(boost::asio::ip::address::from_string(ip_dst), udp_ep.dst_port);

            auto udpsession_it = udpsession_map.find(udp_ep);
            // if new udp proxy
            if (udpsession_it == udpsession_map.end())
            {

                auto psession = boost::make_shared<udp_proxy_session>(this->shared_from_this(), this->prawsender_socket->get_io_context(), this->udpsession_map);

                udpsession_map.insert({udp_ep, psession});
                psession->SaveSrcEndpoint(udp_ep);
                psession->Start();
                psession->SendToRemote(&full_data.at(header_size), bytes_read - 6 - 10, remote_ep);

            } else
            {
                udpsession_it->second->SendToRemote(&full_data.at(header_size), bytes_read - 6 - 10, remote_ep);
            }


        });

    }


    //call only when recv data
    void ackReply(Tins::TCP* local_tcp)
    {
        using Tins::TCP;
        auto ip = Tins::IP(local_ep.address().to_string(), server_ep.address().to_string());

        auto tcp = TCP(local_tcp->sport(), local_tcp->dport());
        tcp.flags(TCP::ACK);
        tcp.seq(server_seq);

        if (local_tcp->seq() >= this->server_ack)
        {
            //save server_ack
            //cause we have to know what ack to send when recv udp packet from remote
            this->server_ack = local_tcp->seq() + local_tcp->inner_pdu()->size();
        }
        tcp.ack_seq(this->server_ack);

        ip = ip / tcp;

        LOG_INFO("ACK Reply, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

        auto vip_data = ip.serialize();
        auto ip_data = vip_data.data();
        CalTcpChecksum(ip, ip_data);

        // we send tcp only, ip hdr is for checksum cal only
        sendPacket(ip_data + ip.header_size(), tcp.size());
    }


    void sendRst(Tins::TCP* local_tcp)
    {
        using Tins::TCP;

        auto tcp = TCP(local_tcp->sport(), local_tcp->dport());
        tcp.flags(TCP::RST);
        tcp.ack_seq(local_tcp->seq() + 1);
        tcp.seq(server_seq + local_tcp->inner_pdu()->size());
        sendPacket(tcp.serialize().data(), tcp.size());
    }

};