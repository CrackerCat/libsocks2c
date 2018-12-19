#pragma once

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>
#include <boost/bind.hpp>

#include "../../../protocol/socks5_protocol_helper.h"
#include "../../../utils/logger.h"
#include "../../../utils/ephash.h"
#include "../../bufferdef.h"

#ifdef MULTITHREAD_IO
#define COROUTINE_CONTEXT this->remote_socket_.get_io_context()
#else
#define COROUTINE_CONTEXT this->local_socket_.get_io_context()
#endif

template <class Protocol>
class ClientUdpProxySession : public boost::enable_shared_from_this<ClientUdpProxySession<Protocol>>{

    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientUdpProxySession<Protocol>>, EndPointHash>;

public:

    ClientUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::asio::ip::udp::socket &local_socket, SESSION_MAP& map_ref) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(local_socket.get_io_context()), timer_(local_socket.get_io_context())
    {
        this->protocol_.SetKey(key);
        remote_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(server_ip), server_port);
        this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);

    }

	ClientUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::asio::ip::udp::socket &local_socket, SESSION_MAP& map_ref, boost::asio::io_context& downstream_context) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(downstream_context), timer_(local_socket.get_io_context())
	{
		this->protocol_.SetKey(key);
		remote_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(server_ip), server_port);
		this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);
	}


	~ClientUdpProxySession()
	{
		LOG_DETAIL(LOG_DEBUG("[{:p}] udp session die", (void*)this))
	}

    auto& GetLocalEndpoint()
    {
        return local_ep_;
    }

    unsigned char* GetLocalBuffer()
    {
        return local_recv_buff_;
    }

    unsigned char* GetLocalDataBuffer()
    {
        return local_recv_buff_ + Protocol::ProtocolHeader::Size();
    }

    unsigned char* GetRemoteDataBuffer()
    {
        return remote_recv_buff_ + Protocol::ProtocolHeader::Size();
    }

	void SetDnsPacket()
	{
		this->isDnsReq = true;
	}

    void Start()
    {

        auto self(this->shared_from_this());
        boost::asio::spawn(COROUTINE_CONTEXT, [this, self](boost::asio::yield_context yield){

            boost::system::error_code ec;

            while (1)
            {

                auto bytes_read = readFromRemote(yield);
                if (bytes_read == 0)
                {
                    return;
                }
                if (!sendToLocal(bytes_read, yield))
                {
                    this->remote_socket_.cancel(ec);
					return;
                }


            }



        });

		timer_.expires_from_now(boost::posix_time::seconds(TIMER_EXPIRE_TIME));
		timer_.async_wait(boost::bind(&ClientUdpProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));


    }


    auto& GetLocalSocketRef()
    {
        return local_socket_;
    }

    auto& GetLocalEndPoint()
    {
        return local_ep_;
    }


    void sendToRemote(uint64_t bytes)
    {

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
        auto udp_socks_packet = (socks5::UDP_RELAY_PACKET*)protocol_hdr->GetDataOffsetPtr();

        this->remote_socket_.async_send_to(boost::asio::buffer(local_recv_buff_, bytes),
                                           remote_ep_, boost::bind(&ClientUdpProxySession::onRemoteSend,this->shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));


    }

    bool ShouldClose()
    {
        return should_close;
    }

private:

    Protocol protocol_;

    bool should_close = false;

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

    void onRemoteSend(const boost::system::error_code &ec, const uint64_t &bytes_send)
    {
        if(ec)
        {
            LOG_INFO("[{:p}] udp onRemoteSend err --> {}", (void*)this, ec.message().c_str())
            return;
        }

		LOG_INFO("[{:p}] send {} bytes to remote", (void*)this, bytes_send)

    }

    uint64_t readFromRemote(boost::asio::yield_context yield)
    {
        boost::system::error_code ec;

        uint64_t bytes_read = this->remote_socket_.async_receive_from(boost::asio::buffer(remote_recv_buff_, UDP_REMOTE_RECV_BUFF_SIZE), remote_recv_ep_, yield[ec]);

        if (ec)
        {
            LOG_DEBUG("[{:p}] Udp readFromRemote err --> {}", (void*)this, ec.message().c_str())
			return 0;
        }
		LOG_DETAIL(LOG_DEBUG("[{:p}] Udp read {} bytes FromRemote : {}:{}", (void*)this, bytes_read, remote_recv_ep_.address().to_string().c_str(), remote_recv_ep_.port()))

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;
        return protocol_.OnUdpPayloadReadFromClientRemote(protocol_hdr);
    }

    bool sendToLocal(uint64_t bytes, boost::asio::yield_context yield)
    {
        boost::system::error_code ec;
		/*
			auto udpreq = (socks5::UDP_RELAY_PACKET*)(remote_recv_buff_ + Protocol::ProtocolHeader::Size());

			std::string ip;
			uint16_t port;
			Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(udpreq, ip, port);

			printf("udp packet original is : %s:%d\n", ip.c_str(), port);
		*/
		uint64_t bytes_send = this->local_socket_.async_send_to(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), bytes), local_ep_, yield[ec]);

        if (ec)
        {
            LOG_DEBUG("[{:p}] Udp sendToLocal err --> {}", (void*)this, ec.message().c_str())
			return false;
        }
		LOG_DETAIL(LOG_DEBUG("[{:p}] Udp send {} bytes to Local", (void*)this, bytes_send))


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
			LOG_DEBUG("session_map_ size --> {}, max size -> {}, max bucket count -> {}", session_map_.size(), session_map_.max_size(), session_map_.max_bucket_count());

			this->session_map_.erase(local_ep_);
			return;
		}


		if (time(nullptr) - last_update_time > SESSION_TIMEOUT)
		{
			LOG_DEBUG("[{}] udp session {}:{} timeout --> {}", (void*)this,local_ep_.address().to_string().c_str(), local_ep_.port(), ec.message().c_str())

			boost::system::error_code ec;
			this->remote_socket_.cancel(ec);
			LOG_DEBUG("session_map_ size --> {}, max size -> {}, max bucket count -> {}", session_map_.size(), session_map_.max_size(), session_map_.max_bucket_count());

			this->session_map_.erase(local_ep_);
			return;
		}

		timer_.expires_from_now(boost::posix_time::seconds(TIMER_EXPIRE_TIME));
		timer_.async_wait(boost::bind(&ClientUdpProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));


	}

};

