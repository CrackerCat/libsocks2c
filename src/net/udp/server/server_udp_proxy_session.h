#pragma once

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>
#include <string>

#include "../../../utils/logger.h"
#include "../../../protocol/socks5_protocol_helper.h"
#include "../../../utils/ephash.h"
#include "../../bufferdef.h"



template <class Protocol>
class ServerUdpProxySession : public boost::enable_shared_from_this<ServerUdpProxySession<Protocol>> {

	using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ServerUdpProxySession<Protocol>>, EndPointHash>;


public:

	ServerUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::asio::ip::udp::socket &local_socket, SESSION_MAP& map_ref) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(local_socket.get_io_context()), timer_(local_socket.get_io_context())
	{
		//LOG_DEBUG("[{}] ServerUdpProxySession created", (void*)this)
		this->protocol_.SetKey(key);
		this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);
	}	

	ServerUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::asio::ip::udp::socket &local_socket, SESSION_MAP& map_ref, boost::asio::io_context& downstream_context) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(downstream_context), timer_(local_socket.get_io_context())
	{
		LOG_DEBUG("[{}] ServerUdpProxySession created", (void*)this)
		this->protocol_.SetKey(key);
		this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);
	}

	~ServerUdpProxySession()
	{
		LOG_DETAIL(LOG_DEBUG("[{:p}] udp session die", (void*)this))
	}

	unsigned char* GetLocalDataBuffer()
	{
		return local_recv_buff_ + Protocol::ProtocolHeader::Size();
	}

	unsigned char* GetLocalBuffer()
	{
		return local_recv_buff_;
	}

	auto& GetLocalSocketRef()
	{
		return local_socket_;
	}

	auto& GetLocalEndPoint()
	{
		return local_ep_;
	}

	// packet already decrypted
	void sendToRemote(uint64_t bytes)
	{

		auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
		auto udp_socks_packet = (socks5::UDP_RELAY_PACKET*)protocol_hdr->GetDataOffsetPtr();

		std::string ip_str;
		uint16_t port;

		if (!Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(udp_socks_packet, ip_str, port)) return;

		remote_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(ip_str), port);

		if (port == 53) isDnsReq = true;

		LOG_DEBUG("sending {} bytes to {}:{}", bytes - 10, remote_ep_.address().to_string().c_str(), remote_ep_.port())

		this->remote_socket_.async_send_to(boost::asio::buffer(protocol_hdr->GetDataOffsetPtr() + 10, bytes - 10),
				remote_ep_, boost::bind(&ServerUdpProxySession::onRemoteSend, this->shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));



	}



	void onRemoteSend(const boost::system::error_code &ec, const uint64_t &bytes_send)
	{
		if (ec)
		{
			LOG_INFO("onRemoteSend err --> {}", ec.message().c_str())
				this->session_map_.erase(local_ep_);
			return;
		}
		LOG_DETAIL(LOG_DEBUG("[{}] udp send {} bytes to remote : {}:{}", (void*)this, bytes_send, remote_ep_.address().to_string().c_str(), remote_ep_.port()))

		last_update_time = time(nullptr);

	}

	// Handle Downstream only
	void Start() {

		auto self(this->shared_from_this());
		boost::asio::spawn(this->local_socket_.get_io_context(), [this, self](boost::asio::yield_context yield) {

			boost::system::error_code ec;

			while (1) {

				auto bytes_read = readFromRemote(yield);
				if (bytes_read == 0) {
					return;
				}
				if (!sendToLocal(bytes_read, yield)) {
					this->remote_socket_.cancel(ec);
					return;
				}


			}


		});

		timer_.expires_from_now(boost::posix_time::seconds(TIMER_EXPIRE_TIME));
		timer_.async_wait(boost::bind(&ServerUdpProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));



	}



private:

	Protocol protocol_;

	SESSION_MAP& session_map_;

	boost::asio::ip::udp::endpoint local_ep_;
	boost::asio::ip::udp::endpoint remote_ep_;
	boost::asio::ip::udp::endpoint remote_recv_ep_;

	unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];
	unsigned char remote_recv_buff_[UDP_REMOTE_RECV_BUFF_SIZE];

	boost::asio::ip::udp::socket &local_socket_;
	boost::asio::ip::udp::socket remote_socket_;

	boost::asio::deadline_timer timer_;
	time_t last_update_time = 0;

	bool isDnsReq = false;

	uint64_t readFromRemote(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;

		// 10 extra bytes reserved for socks5 udp header
		uint64_t bytes_read = this->remote_socket_.async_receive_from(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size() + 10, UDP_REMOTE_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 10), remote_recv_ep_, yield[ec]);

		if (ec)
		{
			LOG_DEBUG("Udp readFromRemote err --> {}", ec.message().c_str())
				this->session_map_.erase(local_ep_);
			return 0;
		}

		LOG_DETAIL(LOG_DEBUG("[{}] udp read {} bytes from remote : {}:{}", (void*)this, bytes_read, remote_recv_ep_.address().to_string().c_str(), remote_recv_ep_.port()))

			last_update_time = time(nullptr);

		auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;
		Socks5ProtocolHelper::ConstructSocks5UdpPacketFromIpStringAndPort(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), remote_recv_ep_.address().to_string(), remote_recv_ep_.port());
		// paddle the socks5 udp header
		protocol_hdr->PAYLOAD_LENGTH = bytes_read + 10;
		return protocol_.OnUdpPayloadReadFromServerRemote(protocol_hdr);
	}




	bool sendToLocal(uint64_t bytes, boost::asio::yield_context yield)
	{
		boost::system::error_code ec;

		// Read Header Decode Length
		uint64_t bytes_send = this->local_socket_.async_send_to(boost::asio::buffer(remote_recv_buff_, bytes), local_ep_, yield[ec]);

		if (ec)
		{
			LOG_DEBUG("Udp sendToLocal err --> {}", ec.message().c_str())
				this->session_map_.erase(local_ep_);
			return false;
		}
		LOG_DETAIL(LOG_DEBUG("[{}] udp send {} bytes to Local {}:{}", (void*)this, bytes_send, local_ep_.address().to_string().c_str(), local_ep_.port()))
		
		if (this->isDnsReq)
		{
			timer_.cancel();
			return false;
		}

		return true;
	}


	void onTimesup(const boost::system::error_code &ec)
	{
		if (ec)
		{
			LOG_DEBUG("Udp timer err --> {}", ec.message().c_str())
			this->session_map_.erase(local_ep_);
			return;
		}


		if (time(nullptr) - last_update_time > SESSION_TIMEOUT)
		{
			LOG_DEBUG("Udp session {}:{} timeout", local_ep_.address().to_string().c_str(), local_ep_.port())

				boost::system::error_code ec;
			this->remote_socket_.cancel(ec);
			return;
		}

		timer_.expires_from_now(boost::posix_time::seconds(TIMER_EXPIRE_TIME));
		timer_.async_wait(boost::bind(&ServerUdpProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));


	}

};


