#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio/spawn.hpp>

#include "../../../utils/logger.h"
#include "../../../utils/randomNumberGenerator.h"

#include "../../../protocol/socks5_protocol.h"
#include "../../../protocol/socks5_protocol_helper.h"
#include "../../../protocol/iproxy_protocol.h"

#include "../../bufferdef.h"


#define DestorySession { onDestruction(yield); return; }

template<class Protocol>
class ServerTcpProxySession : public boost::enable_shared_from_this<ServerTcpProxySession<Protocol>> {

	using IO_CONTEXT = boost::asio::io_context;
	using SOCKET = boost::asio::ip::tcp::socket;

	using DNS_RESOLVER = boost::asio::ip::tcp::resolver;
	using PDNS_RESOLVER = std::unique_ptr<DNS_RESOLVER>;

public:

	ServerTcpProxySession(IO_CONTEXT &io_context, unsigned char key[32U]) \
		: local_socket_(io_context), remote_socket_(io_context), dns_resolver_(io_context), protocol_()
	{
		this->protocol_.SetKey(key);
	}

	~ServerTcpProxySession()
	{
		LOG_DETAIL(LOG_DEBUG("[{:p}] tcp session die", (void*)this))
	}


	void Start()
	{
		if (!setNoDelay()) return;

		auto self(this->shared_from_this());
		boost::asio::spawn(this->local_socket_.get_io_context(), [this, self](boost::asio::yield_context yield) {

			if (!handleSocks5Request(yield)) DestorySession
				if (!handleTunnelFlow(yield)) DestorySession

		});

	}


	SOCKET& GetLocalSocketRef()
	{
		return local_socket_;
	}



private:

	Protocol protocol_;

	SOCKET local_socket_;
	SOCKET remote_socket_;

	DNS_RESOLVER dns_resolver_;

	unsigned char local_recv_buff_[TCP_LOCAL_RECV_BUFF_SIZE];
	unsigned char remote_recv_buff_[TCP_REMOTE_RECV_BUFF_SIZE];

	bool setNoDelay()
	{
		boost::system::error_code ec;
		this->local_socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
		if (ec)
		{
			LOG_DEBUG("setNoDelay err")
				return false;
		}
		return true;
	}



	/*
	 *  After this func, session will be in tunnel status
	 *  if there's a domain proxy request, resolve here
	 */
	bool handleSocks5Request(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;

		/*
		 *  Read header first, then read the full content
		 */
		uint64_t bytes_read = boost::asio::async_read(this->local_socket_, boost::asio::buffer(local_recv_buff_, Protocol::ProtocolHeader::Size()), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("handleSocks5Request read err --> {}", ec.message().c_str())
			return false;
		}

		auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
		auto data_len = protocol_.onSocks5RequestHeaderRead(protocol_hdr);
		if (data_len == 0) return false;

		// Read the full content
		bytes_read = boost::asio::async_read(this->local_socket_, boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), data_len), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("handleSocks5Request read err --> {}", ec.message().c_str())
				return false;
		}

		if (!protocol_.onSocks5RequestPayloadRead(protocol_hdr)) return false;

		auto socks5_req_header = (socks5::SOCKS_REQ*)(local_recv_buff_ + Protocol::ProtocolHeader::Size());

		if (socks5_req_header->VER != 0x05 || socks5_req_header->RSV != 0x00)
		{
			LOG_DEBUG("VER or RSV field of handleSocks5Request err, drop connection")
				return false;
		}

		if (socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::IPV4 || socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::IPV6)
		{

			std::string ip_str;
			uint16_t port;

			if (!Socks5ProtocolHelper::parseIpPortFromSocks5Request(socks5_req_header, ip_str, port)) return false;

			auto remote_ep_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(ip_str), port);

			if (!openRemoteSocket(remote_ep_)) return false;

			if (!connectToRemote(yield, remote_ep_)) return false;

			return true;

		}
		else if (socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::DOMAINNAME)
		{

			std::string ip_str;
			uint16_t port;

			if (!Socks5ProtocolHelper::parseDomainPortFromSocks5Request(socks5_req_header, ip_str, port))
			{
				LOG_DEBUG("parseDomainPortFromSocks5Request err ")
					return false;
			}

			boost::system::error_code ec;
			boost::asio::ip::tcp::resolver::query query{ ip_str,std::to_string(port),boost::asio::ip::resolver_query_base::all_matching };

			LOG_INFO("resolving {}:{}", ip_str.c_str(), port)

				auto dns_result = dns_resolver_.async_resolve(query, yield[ec]);

			if (ec)
			{
				LOG_DEBUG("async_resolve {} err --> {}", ip_str.c_str(), ec.message().c_str())
					return false;
			}

			LOG_INFO("Dns Resolved: {} --> {}:{}", ip_str.c_str(), dns_result->endpoint().address().to_string().c_str(), dns_result->endpoint().port());

			if (!openRemoteSocket(dns_result->endpoint())) return false;

			if (!connectToRemote(yield, dns_result->endpoint())) return false;

			return true;


		}
		else
		{
			LOG_DEBUG("unknow ATYP")
				return false;
		}


	}


	bool openRemoteSocket(boost::asio::ip::tcp::endpoint ep)
	{
		boost::system::error_code ec;
		//might throw too many open files
		remote_socket_.open(ep.protocol(), ec);

		if (ec)
		{
			LOG_ERROR("err when opening remote_socket_ --> {}", ec.message().c_str())
				return false;
		}

		boost::asio::ip::tcp::acceptor::reuse_address reuse_address(true);
		boost::asio::ip::tcp::no_delay no_delay(true);

		remote_socket_.set_option(reuse_address, ec);
		if (ec)
		{
			LOG_ERROR("err reuse_address remote_socket_ --> {}", ec.message().c_str())
				return false;
		}

		remote_socket_.set_option(no_delay, ec);
		if (ec)
		{
			LOG_ERROR("err no_delay remote_socket_ --> {}", ec.message().c_str())
				return false;
		}
		return true;
	}


	bool handleTunnelFlow(boost::asio::yield_context yield)
	{

		auto self(this->shared_from_this());
		boost::asio::spawn(this->local_socket_.get_io_context(), [this, self](boost::asio::yield_context yield) {

			boost::system::error_code ec;

			while (1)
			{
				auto bytes_read = readFromRemote(yield);
				if (bytes_read == 0)
				{
					this->local_socket_.cancel(ec);
					return;
				}
				if (!sendToLocal(bytes_read, yield))
				{
					this->remote_socket_.cancel(ec);
					return;
				}
			}
		});

		boost::system::error_code ec;

		while (1)
		{
			auto bytes_read = readFromLocal(yield);
			if (bytes_read == 0)
			{
				this->remote_socket_.cancel(ec);
				return false;
			}
			if (!sendToRemote(bytes_read, yield))
			{
				this->local_socket_.cancel(ec);
				return false;
			}
		}



	}


	uint64_t readFromRemote(boost::asio::yield_context yield)
	{

		boost::system::error_code ec;

		// Read Header Decode Length
		uint64_t bytes_read = this->remote_socket_.async_read_some(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), TCP_REMOTE_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size()), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("handleTunnelFlow async_read from remote err --> {}", ec.message().c_str())
				return 0;
		}

		LOG_DETAIL(LOG_DEBUG("read {} bytes from remote", bytes_read))

			return bytes_read;
	}


	bool sendToLocal(uint64_t bytes, boost::asio::yield_context yield)
	{

		boost::system::error_code ec;

		auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;

		/*
		 *  The DATA_LENGTH setting here may not be the len sending to remote
		 *
		 *  it's the protocol (see below) that decides how many bytes should be send, but we could assume that at least bytes_read + Protocol::ProtocolHeader::Size() will be send
		 */
		protocol_hdr->PAYLOAD_LENGTH = bytes;

		uint64_t bytes_write = async_write(this->local_socket_, boost::asio::buffer(remote_recv_buff_, protocol_.onPayloadReadFromRemote(protocol_hdr)), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("sendToLocal err --> {}", ec.message().c_str())
				return false;
		}
		LOG_DETAIL(LOG_DEBUG("send {} bytes to local", bytes_write))

			return true;
	}


	// return bytes send to remote, 0 if err
	uint64_t readFromLocal(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;

		/*
		 *  Read header first, then read the full content
		 */
		uint64_t bytes_read = boost::asio::async_read(this->local_socket_, boost::asio::buffer(local_recv_buff_, Protocol::ProtocolHeader::Size()), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("handleTunnelFlow read header err --> {}", ec.message().c_str())
				return 0;
		}

		auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
		auto data_len = protocol_.onPayloadHeaderReadFromLocal(protocol_hdr);
		if (data_len == 0) return 0;


		// Read the full content
		bytes_read = boost::asio::async_read(this->local_socket_, boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), data_len), yield[ec]);

		if (ec)
		{
			LOG_DEBUG("handleTunnelFlow read payload err --> {}", ec.message().c_str())
				return 0;
		}

		if (!protocol_.onPayloadReadFromLocal(protocol_hdr)) return 0;

		return protocol_hdr->PAYLOAD_LENGTH;
	}



	bool sendToRemote(uint64_t bytes, boost::asio::yield_context yield)
	{
		boost::system::error_code ec;
		uint64_t bytes_write = async_write(this->remote_socket_, boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), bytes), yield[ec]);
		if (ec)
		{
			LOG_DEBUG("sendToRemote payload err --> {}", ec.message().c_str())
				return false;
		}
		LOG_DEBUG("send {} bytes to remote", bytes_write)
			return true;
	}




	bool connectToRemote(boost::asio::yield_context yield, boost::asio::ip::tcp::endpoint ep)
	{
		boost::system::error_code ec;
		LOG_INFO("connecting to --> {}:{}", ep.address().to_string().c_str(), ep.port())

			this->remote_socket_.async_connect(ep, yield[ec]);

		if (ec)
		{
			LOG_DEBUG("can't connect to remote --> {}", ec.message().c_str())
				return false;
		}
		LOG_DEBUG("connected to --> {}:{}", ep.address().to_string().c_str(), ep.port())

			return true;
	}


	// we wait for random seconds before closing session for unknown reason
	inline void onDestruction(boost::asio::yield_context yield)
	{
		boost::system::error_code ec;

		//LOG_DEBUG("Destroy session from {}:{}", this->local_socket_.remote_endpoint(ec).address().to_string().c_str(), this->local_socket_.remote_endpoint(ec).port())

		if (ec)
		{
			LOG_DEBUG("this->local_socket_.remote_endpoint Transport endpoint is not connected")
				ec.clear();
		}

		auto num = RandomNumberGenerator::GetRandomIntegerBetween<uint16_t>(3, 10);

		boost::asio::deadline_timer timer(this->local_socket_.get_io_context());
		timer.expires_from_now(boost::posix_time::seconds(num));
		timer.async_wait(yield[ec]);

	}



};


