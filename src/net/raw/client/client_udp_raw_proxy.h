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
        BasicClientUdpRawProxy<Protocol>(io, prot, pls),
        sniffer_socket(io), send_socket_stream(io)
    {
        if (!send_socket_stream.is_open())
            send_socket_stream.open();
    }

    virtual void Stop() override
    {
		if (this->status == CLOSED) return;
		this->sniffer_socket.cancel();
		this->send_socket_stream.cancel();
        FirewallHelper::GetInstance()->Unblock(local_ip, local_raw_port);
    }

    virtual bool SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_raw_port = std::string(), std::string local_ip = std::string(), std::string ifname = std::string()) override
    {
		if (local_raw_port.empty())
		{
			std::random_device rd;
			std::mt19937 eng(rd());
			std::uniform_int_distribution<unsigned short> distr(10000, 65535);
			this->local_port = distr(eng);
		}
		else this->local_port = boost::lexical_cast<unsigned short>(local_raw_port);

        //Get Default if ifname is not set
        if (ifname.empty())
            ifname = InterfaceHelper::GetInstance()->GetDefaultInterface();

		if (local_ip.empty())
		{
			LOG_INFO("local_ip not provided, trying to get default ip")
			LOG_INFO("if i retrive the wrong ip, you are probably fucked")
			this->local_ip = InterfaceHelper::GetInstance()->GetDefaultNetIp();
			LOG_INFO("get {} as default ip", local_ip)
		}else
            this->local_ip = local_ip;

        if (ifname.empty() || local_ip.empty())
        {
            LOG_INFO("can not find default interface or ip")
            return false;
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

        LOG_INFO("send {} bytes via raw socket", bytes_send)

        return bytes_send;
    }

private:
    Tins::SnifferConfiguration config;
    std::unique_ptr<Tins::Sniffer> psniffer;
	SnifferSocket sniffer_socket;

    boost::asio::basic_raw_socket<asio::ip::raw> send_socket_stream;


    virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code& ec) override
    {

        this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);

        if (ec)
        {
            LOG_INFO("wait err --> {}\n", ec.message().c_str());
            return nullptr;
        }

        std::unique_ptr<Tins::PDU> pdu_ptr(this->psniffer->next_packet());
        return pdu_ptr;
    }

};