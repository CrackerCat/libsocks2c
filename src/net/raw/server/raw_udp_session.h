#pragma once
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio/io_context.hpp>
#include "../../../utils/ephash.h"
#include <boost/unordered_map.hpp>
#include "../../../utils/logger.h"
#include <boost/asio/spawn.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/deadline_timer.hpp>

#include "../../../protocol/socks5/socks5_protocol_helper.h"

#include "buffersize_def.h"

template <class Protocol>
class ServerUdpRawProxySession;

// timeout for ServerUdpRawProxySession's inner udp session class
#define UDP_PROXY_SESSION_TIMEOUT 60


template <class Protocol>
class udp_proxy_session : public boost::enable_shared_from_this<udp_proxy_session<Protocol>>
{
    using UdpSessionMap = boost::unordered_map<udp_ep_tuple, boost::shared_ptr<udp_proxy_session>, UdpEndPointTupleHash, UdpEndPointTupleEQ>;

public:
    udp_proxy_session(boost::shared_ptr<ServerUdpRawProxySession<Protocol>> server, boost::asio::io_context& io, UdpSessionMap& map) : pserver(server), io_context_(io), udpsession_map(map), remote_socket_(io), timer(io)
    {
        last_active_time = time(nullptr);
        this->remote_socket_.open(remote_recv_ep_.protocol());
    }

    ~udp_proxy_session()
    {
        LOG_INFO("udp proxy session die")
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

    void Stop()
    {
        this->remote_socket_.cancel();
        this->timer.cancel();
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

    unsigned char local_recv_buff_[RAW_UDP_LOCAL_RECV_BUFF_SIZE];
    unsigned char remote_recv_buff_[RAW_UDP_REMOTE_RECV_BUFF_SIZE];

    void readFromRemote()
    {
        auto self(this->shared_from_this());
        boost::asio::spawn([this, self](boost::asio::yield_context yield){

            while (1)
            {
                boost::system::error_code ec;

                // 10 extra bytes reserved for socks5 udp header
                uint64_t bytes_read = this->remote_socket_.async_receive_from(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size() + 6 + 10, RAW_UDP_REMOTE_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 6 - 10), remote_recv_ep_, yield[ec]);

                if (ec)
                {
                    UDP_DEBUG("Udp readFromRemote err --> {}", ec.message().c_str())
                    return 0;
                }

                last_active_time = time(nullptr);

                LOG_INFO("recv {} bytes udp data from remote", bytes_read)


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
                this->timer.expires_from_now(boost::posix_time::seconds(UDP_PROXY_SESSION_TIMEOUT));
                this->timer.async_wait(yield[ec]);

                // we don't erase self in map if udp session is cancel
                // the caller will do
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
