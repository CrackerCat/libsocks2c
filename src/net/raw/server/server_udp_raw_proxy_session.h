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


    class udp_proxy_session : public boost::enable_shared_from_this<udp_proxy_session>
    {


    public:
        udp_proxy_session(boost::shared_ptr<ServerUdpRawProxySession<Protocol>> server, boost::asio::io_context& io) : pserver(server), io_context_(io), remote_socket_(io), timer(io)
        {
            last_active_time = time(nullptr);
        }

        // copy data, start coroutine and send it
        void SendToRemote(void* data, size_t size)
        {

            auto self(this->shared_from_this());
            boost::asio::spawn([this, self](boost::asio::yield_context yield){



            });
        }

        void Start()
        {
            readFromRemote();
            runTimer();
        }

    private:
        boost::asio::io_context& io_context_;
        boost::shared_ptr<ServerUdpRawProxySession<Protocol>> pserver;
        boost::asio::ip::udp::socket remote_socket_;
        boost::asio::ip::udp::endpoint remote_recv_ep_;
        boost::asio::deadline_timer timer;
        size_t last_active_time;

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


                    this->pserver->sendPacket()
                }


            });
        }

        void runTimer()
        {
            auto self(this->shared_from_this());
            boost::asio::spawn([this, self](boost::asio::yield_context yield){



            });
        }
    };
    using UdpSessionMap = boost::unordered_map<udp_ep_tuple, udp_proxy_session, UdpEndPointTupleHash, UdpEndPointTupleEQ>;

    using UdpSocketMap = boost::unordered_map<udp_ep_tuple, boost::shared_ptr<boost::asio::ip::udp::socket>, UdpEndPointTupleHash, UdpEndPointTupleEQ>;

public:

    ServerUdpRawProxySession(std::string local_ip, uint16_t local_port, SessionMap& map_ref, unsigned char key[32U]) : session_map(map_ref)
    {
        this->protocol_.SetKey(key);
        local_ep = asio::ip::raw::endpoint(boost::asio::ip::address::from_string(local_ip), local_port);
    }

    void InitRawSocket(boost::asio::io_context& io)
    {
        prawsender_socket = std::make_unique<RawSenderSocket>(io);
        prawsender_socket->open();
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



private:
    Protocol protocol_;

    SessionMap& session_map;
    UdpSessionMap udpsession_map;
    UdpSocketMap udpsocket_map;

    SESSION_STATUS status;

    // store client's tcp src ip src port
    asio::ip::raw::endpoint local_ep;

    PRawSenderSocket prawsender_socket;

    uint32_t server_seq = 10000;
    uint32_t server_ack;

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
        tcp_reply.seq(server_seq++);

        LOG_INFO("send syn ack back, seq: {}, ack: {}", tcp_reply.seq(), tcp_reply.ack_seq());

        sendPacket(tcp_reply.serialize().data(), tcp_reply.serialize().size());
        last_send_time = time(nullptr);

    }

    // data will be copy
    // use this method to send TCP data
    void sendPacket(void* data, size_t size)
    {

        auto self(this->shared_from_this());

        std::unique_ptr<char[]> copy_data(new char[size]);
        memcpy(copy_data.get(), data, size);

        boost::asio::spawn([this, self, copy_data{std::move(copy_data)}, size](boost::asio::yield_context yield){

            boost::system::error_code ec;
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
            LOG_INFO("raw packet from {}:{} to {}:{}", src_ip_str, udp_ep.src_port, 0, 0)

            auto udp_socketmap_it = udpsocket_map.find(udp_ep);
            auto ps = boost::make_shared<udp_proxy_session>(this->shared_from_this(), this->prawsender_socket->get_io_context());
            // if new udp proxy
            if (udp_socketmap_it == udpsocket_map.end())
            {

                auto pudpsocket = boost::make_shared<boost::asio::ip::udp::socket>(this->prawsender_socket->get_io_context());

                boost::asio::ip::udp::endpoint remote_ep(boost::asio::ip::address::from_string(ip_dst), udp_ep.dst_port);

                boost::system::error_code ec;
                int header_size = Protocol::ProtocolHeader::Size() + 4 + 2 + 10;
                auto bytes_send = pudpsocket->async_send_to(boost::asio::buffer(&full_data.at(header_size), full_data.size() - header_size), remote_ep, yield[ec]);
                if (ec)
                {
                    return;
                }
                udpsocket_map.insert({udp_ep, pudpsocket});

                auto self(this->shared_from_this());
                boost::asio::spawn([this, self, pudpsocket](boost::asio::yield_context yield){

                });
                boost::asio::spawn([this, self, pudpsocket](boost::asio::yield_context yield){

                });

            } else
            {

                //udp_socketmap_it->second->


            }


        });

    }


    //call only when recv data
    void ackReply(Tins::TCP* local_tcp)
    {
        using Tins::TCP;

        auto tcp = TCP(local_tcp->sport(), local_tcp->dport());
        tcp.flags(TCP::ACK);
        tcp.ack_seq(local_tcp->seq() + 1);
        tcp.seq(server_seq);
        sendPacket(tcp.serialize().data(), tcp.size());
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