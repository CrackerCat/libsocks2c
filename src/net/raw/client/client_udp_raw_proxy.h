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
    }

    virtual void Stop() override
    {

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


    virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield) override
    {
        boost::system::error_code ec;
        this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);

        if (ec)
        {
            LOG_INFO("wait err --> {}\n", ec.message().c_str());
            return nullptr;
        }

        std::unique_ptr<Tins::PDU> pdu_ptr(this->psniffer->next_packet());
        return pdu_ptr;
    }



    virtual bool sendToLocal_(void* data, size_t size, boost::asio::ip::udp::endpoint local_ep, boost::asio::yield_context yield) override
    {
        boost::system::error_code ec;

        LOG_INFO("send udp back to local {} : {}", local_ep.address().to_string(), local_ep.port())

        auto bytes_send = this->plocal_socket->async_send_to(boost::asio::buffer(data, size), local_ep, yield[ec]);

        if (ec)
        {
            LOG_INFO("async_send_to err --> {}", ec.message().c_str())
            return false;
        }

        LOG_INFO("send {} bytes via raw socket", bytes_send)

        return true;
    }

};