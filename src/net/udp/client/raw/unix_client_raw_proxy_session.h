#pragma once
#include <tins/tins.h>
#include <boost/thread.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <boost/asio/deadline_timer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/udp.hpp>
#include "../../../../protocol/socks5/socks5_protocol_helper.h"
#include "../../../../utils/ephash.h"
#include "helper/available_port.h"

#include "basic_client_raw_proxy_session.h"

template <class Protocol>
class ClientRawProxySession : public BasicClientRawProxySession<Protocol>
{

    using RAW_SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientRawProxySession<Protocol>>, EndPointHash>;

public:

    ClientRawProxySession(boost::asio::io_context& io, std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::shared_ptr<boost::asio::ip::udp::socket> local_socket, RAW_SESSION_MAP& map_ref) : \
        BasicClientRawProxySession<Protocol>(io, local_socket),
        sniffer_socket(io), send_socket_stream(io), raw_session_map(map_ref),dummy_socket(io)
    {
        this->protocol_.SetKey(key);

        boost::system::error_code ec;
        send_socket_stream.open(asio::ip::raw::endpoint().protocol(), ec);
        if (ec) {
            LOG_INFO("raw send_socket_stream open err --> {}", ec.message())
            return;
        }
    }

    virtual ~ClientRawProxySession() override
    {
        LOG_DEBUG("ClientRawProxySession die")
    }


    virtual void Stop() override
    {
        cleanUp();
    }

    virtual bool SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_ip, std::string ifname) override
    {
        auto lport = GetPort();
        if (lport == 0) return false;

        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("0.0.0.0"), lport);

        boost::system::error_code ec;
        dummy_socket.open(ep.protocol());
        dummy_socket.bind(ep, ec);

        if (ec) {
            LOG_INFO("SetUpSniffer err --> {}", ec.message().c_str())
            return false;
        }

        this->local_port = lport;
        this->local_ip = local_ip;

        //setup sniffer
        config.set_filter("ip dst "+ local_ip + " and dst port " + boost::lexical_cast<std::string>(this->local_port));
        config.set_immediate_mode(true);
        psniffer = std::make_unique<Tins::Sniffer>(ifname, config);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_setnonblock(psniffer->get_pcap_handle(), 1, errbuf);
        sniffer_socket.assign(psniffer->get_fd());

        //save server endpoint
        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);

        return true;
    }


    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield) override
    {

        asio::ip::raw::endpoint ep(boost::asio::ip::address::from_string(this->remote_ip), this->remote_port);
        boost::system::error_code ec;

        auto bytes_send = send_socket_stream.async_send_to(boost::asio::buffer(data, size), ep, yield[ec]);

        if (ec)
        {
            LOG_INFO("async_send_to err --> {}", ec.message().c_str())
            return 0;
        }

        //LOG_INFO("send {} bytes via raw socket", bytes_send)

        return bytes_send;
    }

private:

    RAW_SESSION_MAP& raw_session_map;

    Tins::SnifferConfiguration config;
    std::unique_ptr<Tins::Sniffer> psniffer;
    SnifferSocket sniffer_socket;

    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;

    boost::asio::ip::tcp::socket dummy_socket;

    virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code& ec) override
    {

        this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);

        if (ec)
        {
            LOG_DEBUG("wait err --> {}", ec.message().c_str());
            return nullptr;
        }

        std::unique_ptr<Tins::PDU> pdu_ptr(this->psniffer->next_packet());
        return pdu_ptr;
    }


    virtual void onTimesup(const boost::system::error_code &ec) override
    {
        if (ec)
        {
            LOG_INFO("Udp timer err --> {}", ec.message().c_str())
            cleanUp();
            return;
        }

        if (time(nullptr) - this->last_update_time > this->session_timeout)
        {
            cleanUp();
            return;
        }

        this->timer_.expires_from_now(boost::posix_time::seconds(RAW_SESSION_TIMEOUT));
        this->timer_.async_wait(boost::bind(&BasicClientRawProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));

    }

    void cleanUp()
    {
        boost::system::error_code ec;
        this->sniffer_socket.close(ec);
        this->send_socket_stream.close(ec);
        this->raw_session_map.erase(this->local_ep_);
        ReleasePort(this->local_port);
    }
};