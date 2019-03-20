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
        BasicClientUdpRawProxy<Protocol>(io, prot, pls),
        protocol_(prot)
    {
        if (!send_socket_stream.is_open())
            send_socket_stream.open();
        this->init_seq = time(nullptr);
        this->local_seq = this->init_seq;
    }

	virtual void Stop() override
	{

	}

    virtual void SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_raw_port, std::string local_ip = std::string(), std::string ifname = std::string()) override
    {

        this->local_port = boost::lexical_cast<unsigned short>(local_raw_port);

		this->local_ip = local_ip;


        //save server endpoint
        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);
    }


    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield, bool shouldcopy = true) override
    {

		return 0;
    }

private:
    Protocol& protocol_;


	virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield) override
	{
		return nullptr;
	}

};