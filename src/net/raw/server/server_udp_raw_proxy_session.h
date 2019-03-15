#pragma once
#include <boost/enable_shared_from_this.hpp>
#include "../../../utils/ephash.h"
#include <boost/unordered_map.hpp>
#include <tins/ip.h>
#include <tins/tcp.h>
#include "../raw_socket.h"

class ServerUdpRawProxySession;
using SessionMap = boost::unordered_map<tcp_session_src_tuple, ServerUdpRawProxySession, TCPSrcTupleHash, TCPSrcTupleEQ>;

class ServerUdpRawProxySession : public boost::enable_shared_from_this<ServerUdpRawProxySession>
{
    enum SESSION_STATUS
    {
        INIT,
        SYN_RCVD,
        ESTABLISHED
    };

    class udp_session
    {

    };
    using UdpSessionMap = boost::unordered_map<udp_ep_tuple, udp_session, UdpEndPointTupleHash>;

    using RawSenderSocket = boost::asio::basic_raw_socket<asio::ip::raw>;
    using PRawSenderSocket = std::unique_ptr<RawSenderSocket>;

public:

    ServerUdpRawProxySession(std::string local_ip, uint16_t local_port, SessionMap& map_ref) : session_map(map_ref)
    {
        local_ep = asio::ip::raw::endpoint(boost::asio::ip::address::from_string(local_ip), local_port);
    }

    void InitRawSocket(boost::asio::io_context io)
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
            // turn status to SYN_RECV
            // client may send multiple syn req
            // we send reply back for each syn
            case (TCP::SYN):
            {
                LOG_INFO("recv syn seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                // clone tcp cause we have to start new coroutine context
                handshakeReply(tcp);
                return true;
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
                //ackReply(tcp->seq(), tcp->ack_seq(), tcp->inner_pdu()->size(), yield);

                //proxyUdp(tcp->inner_pdu());
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

    SessionMap& session_map;
    UdpSessionMap udpsession_map;
    SESSION_STATUS status;

    // store client's tcp src ip src port
    asio::ip::raw::endpoint local_ep;

    PRawSenderSocket prawsender_socket;

    uint32_t server_seq = 0;
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
        local_tcp->flags(Tins::TCP::ACK | Tins::TCP::SYN);
        local_tcp->ack_seq(local_tcp->seq() + 1); // +1 client's seq
        local_tcp->seq(server_seq);

        LOG_INFO("send syn ack back, seq: {}, ack: {}", local_tcp->seq(), local_tcp->ack_seq());

        sendPacket(tcp_reply);
        last_send_time = time(nullptr);

        //this->last_ack = remote_seq;
        this->status = SYN_RCVD;
    }



    void sendPacket(Tins::TCP& tcp_to_send)
    {

        auto self(this->shared_from_this());
        boost::asio::spawn([this, self, &tcp_to_send](boost::asio::yield_context yield){

            boost::system::error_code ec;
            auto raw_data = tcp_to_send.serialize();
            auto bytes_send = prawsender_socket->async_send_to(boost::asio::buffer(raw_data.data(), raw_data.size()), local_ep, yield[ec]);

            if (ec)
            {
                LOG_INFO("async_send_to err --> {}", ec.message().c_str())
                return 0;
            }

            LOG_INFO("send {} bytes via raw socket", bytes_send)

        });

    }


};