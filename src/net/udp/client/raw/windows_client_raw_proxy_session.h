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

#include <windivert.h>
#include <Windows.h>

template <class Protocol>
class ClientRawProxySession : public BasicClientRawProxySession<Protocol>
{

	using RAW_SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientRawProxySession<Protocol>>, EndPointHash>;

public:

	ClientRawProxySession(boost::asio::io_context& io, std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::shared_ptr<boost::asio::ip::udp::socket> local_socket, RAW_SESSION_MAP& map_ref) : \
		BasicClientRawProxySession<Protocol>(io, local_socket), raw_session_map(map_ref), dummy_socket(io)
	{
		this->protocol_.SetKey(key);
	}

	virtual ~ClientRawProxySession() override
	{
		LOG_DEBUG("[{}] ClientRawProxySession die", (void*)this)
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

		
		//save server endpoint
		this->remote_ip = remote_ip;
		this->remote_port = boost::lexical_cast<unsigned short>(remote_port);
		
		//setup sniffer
		bool init_handles_res = initWinDivert();

		if (!init_handles_res) return false;

		return true;
	}

	bool initWinDivert()
	{

		std::string recv_filter = "inbound and !loopback and "
			"ip.DstAddr == " + this->local_ip + " and tcp.DstPort == " + boost::lexical_cast<std::string>(this->local_port);

		recv_handle = WinDivertOpen(
			recv_filter.c_str(),
			WINDIVERT_LAYER_NETWORK, 0, 0
		);

		if (recv_handle == INVALID_HANDLE_VALUE)
		{
			LOG_INFO("err WinDivertOpen recv_handle filter")
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


	virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context & yield) override
	{

		UINT sendLen;
		WINDIVERT_ADDRESS addr;
		addr.Direction = WINDIVERT_DIRECTION_OUTBOUND;
		addr.Loopback = 0;
		addr.Impostor = 0;
		addr.PseudoIPChecksum = 1;
		addr.PseudoTCPChecksum = 1;

		WinDivertSendEx(recv_handle, data, size, 0, &addr, &sendLen, &send_overlapped);

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

	RAW_SESSION_MAP& raw_session_map;

	HANDLE recv_handle;
	std::unique_ptr<SnifferSocket> psniffer_socket;
	std::unique_ptr<SendSocket> psend_socket;

	OVERLAPPED sniffer_overlapped;
	OVERLAPPED send_overlapped;

	unsigned char remote_recv_buff[1500];

	boost::asio::ip::tcp::socket dummy_socket;

	bool cleanup_started = false;

	virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code & ec) override
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

		if (transferred == 0)
		{
			LOG_DEBUG("recvFromRemote err");
			return nullptr;
		}
		auto ip_pdu = std::make_unique<Tins::IP>(remote_recv_buff, transferred);
		return ip_pdu;

	}


	virtual void onTimesup(const boost::system::error_code & ec) override
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

		this->timer_.expires_from_now(boost::posix_time::seconds(RAW_SESSION_TIMSUP));
		this->timer_.async_wait(boost::bind(&BasicClientRawProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));

	}

	void cleanUp()
	{
		if (cleanup_started) return;
		cleanup_started = true;
		this->status = CLOSED;

		auto self(this->shared_from_this());
		boost::asio::spawn(this->io_context_, [self, this](boost::asio::yield_context yield) {
			if (!this->handshake_failed)
				this->finReply(yield);
			boost::system::error_code ec;
			this->psniffer_socket->cancel(ec);
			this->psend_socket->cancel(ec);
			WinDivertClose(this->recv_handle);
			this->raw_session_map.erase(this->local_ep_);
			ReleasePort(this->local_port);
		});
	
	}
};