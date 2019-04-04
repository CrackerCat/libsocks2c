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
#include "../../../protocol/socks5_protocol_helper.h"
#include "../raw_proxy_helper/tcp_checksum_helper.h"
#include "../raw_proxy_helper/interface_helper.h"

#include "../sniffer_def.h"

#include "basic_client_udp_raw_proxy.h"
#include <windivert.h>
#include <Windows.h>

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
class ClientUdpRawProxy : public BasicClientUdpRawProxy<Protocol>, public boost::enable_shared_from_this<ClientUdpRawProxy<Protocol>>
{

public:

    ClientUdpRawProxy(boost::asio::io_context& io, Protocol& prot, boost::shared_ptr<boost::asio::ip::udp::socket> pls) : \
        BasicClientUdpRawProxy<Protocol>(io, prot, pls)
    {
    }

	virtual void Stop() override
	{
		if (this->status == CLOSED) return;
		WinDivertClose(this->rst_handle);
		this->psniffer_socket->close();
		this->psend_socket->close();
		WinDivertClose(this->recv_handle);
		this->status = CLOSED;
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
		
		if (local_ip.empty())
		{
			LOG_INFO("local_ip not provided, trying to get default ip")
			LOG_INFO("if i retrive the wrong ip, you are probably fucked")
		    this->local_ip = InterfaceHelper::GetInstance()->GetDefaultNetIp();
			LOG_INFO("get {} as default ip", this->local_ip)
		}
		else
			this->local_ip = local_ip;
        //save server endpoint
        this->remote_ip = remote_ip;
        this->remote_port = boost::lexical_cast<unsigned short>(remote_port);

		bool init_handles_res = initHandles();

		if (!init_handles_res) return false;

		LOG_INFO("UOUT init, local ep {}:{}", this->local_ip, this->local_port)

		return true;
    }


    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield) override
    {
		UINT sendLen;
		WINDIVERT_ADDRESS addr;
		addr.Direction = WINDIVERT_DIRECTION_OUTBOUND;
		addr.Loopback = 0;
		addr.Impostor = 0;
		addr.PseudoIPChecksum = 1;
		addr.PseudoTCPChecksum = 1;

		WinDivertSendEx(rst_handle, data, size, 0, &addr, &sendLen, &send_overlapped);

		boost::system::error_code ec;
		psend_socket->async_wait(yield[ec]);
		if (ec)
		{
			LOG_INFO("psend_socket async_wait err --> {}", ec.message())
			return 0;
		}

		DWORD transferred;
		GetOverlappedResult(sniffer_overlapped.hEvent, &sniffer_overlapped, &transferred, FALSE);

		LOG_INFO("send {} bytes", size);
		return size;
    }

private:
	HANDLE rst_handle;
	
	HANDLE recv_handle;
	std::unique_ptr<SnifferSocket> psniffer_socket;
	std::unique_ptr<SendSocket> psend_socket;

	OVERLAPPED sniffer_overlapped;
	OVERLAPPED send_overlapped;

	unsigned char remote_recv_buff[1500];

	bool initHandles()
	{
		
		std::string rst_filter = "outbound and !loopback and "
			"ip.DstAddr == " + remote_ip + " and "
			"tcp.SrcPort == " + boost::lexical_cast<std::string>(remote_port) + " and "
			"tcp.Rst";

		rst_handle = WinDivertOpen(
			rst_filter.c_str(),
			WINDIVERT_LAYER_NETWORK, 0, 0
		);

		if (rst_handle == INVALID_HANDLE_VALUE)
		{
			LOG_INFO("err WinDivertOpen RST filter, you may run as administrator")
			return false;
		}

		std::string recv_filter = "inbound and !loopback and "
			"ip.SrcAddr == " + remote_ip + " and tcp.SrcPort == " + boost::lexical_cast<std::string>(remote_port);

		recv_handle = WinDivertOpen(
			recv_filter.c_str(),
			WINDIVERT_LAYER_NETWORK, 0, 0
		);

		if (recv_handle == INVALID_HANDLE_VALUE)
		{
			LOG_INFO("err WinDivertOpen RST filter")
				return false;
		}

		ZeroMemory(&sniffer_overlapped, sizeof(sniffer_overlapped));
		ZeroMemory(&send_overlapped, sizeof(send_overlapped));

		sniffer_overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		psniffer_socket = std::make_unique<SnifferSocket>(this->io_context_, sniffer_overlapped.hEvent);

		send_overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		psend_socket = std::make_unique<SnifferSocket>(this->io_context_, send_overlapped.hEvent);

		return true;
	}

	virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code& ec) override
	{
		WINDIVERT_ADDRESS addr; 
		UINT packetLen;

		WinDivertRecvEx(recv_handle, remote_recv_buff, sizeof(remote_recv_buff), 0, &addr, &packetLen, &sniffer_overlapped);

		psniffer_socket->async_wait(yield[ec]);
		if (ec)
		{
			LOG_INFO("psniffer_socket async_wait err --> {}", ec.message())
			return nullptr;
		}

		DWORD transferred;
		GetOverlappedResult(sniffer_overlapped.hEvent, &sniffer_overlapped, &transferred, FALSE);

		LOG_INFO("recv {} bytes from remote", transferred)

		auto ip_pdu = std::make_unique<Tins::IP>(remote_recv_buff, transferred);
		return ip_pdu;
	}

};