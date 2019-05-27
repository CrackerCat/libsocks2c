#pragma once

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>
#include <boost/bind.hpp>

#include "../bufferqueue.h"
#include "../../../protocol/socks5/socks5_protocol_helper.h"
#include "../../../utils/logger.h"
#include "../../../utils/ephash.h"
#include "../../../utils/macro_def.h"
#include "../../bufferdef.h"

template <class Protocol>
class ClientUdpProxySession : public boost::enable_shared_from_this<ClientUdpProxySession<Protocol>>{

    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientUdpProxySession<Protocol>>, EndPointHash>;

public:

    ClientUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::shared_ptr<boost::asio::ip::udp::socket> local_socket, SESSION_MAP& map_ref) : session_map_(map_ref), local_socket_(local_socket), remote_socket_(local_socket->get_executor()), timer_(local_socket->get_executor())
    {
        this->protocol_.SetKey(key);
        remote_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(server_ip), server_port);
        this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);
    }

	ClientUdpProxySession(std::string server_ip, uint16_t server_port, unsigned char key[32U], boost::shared_ptr<boost::asio::ip::udp::socket> local_socket, SESSION_MAP& map_ref, boost::asio::io_context& downstream_context) : protocol_(nullptr), session_map_(map_ref), local_socket_(local_socket), remote_socket_(downstream_context), timer_(local_socket->get_executor())
	{
		this->protocol_.SetKey(key);
		remote_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(server_ip), server_port);
		this->remote_socket_.open(remote_ep_.protocol());
		this->last_update_time = time(nullptr);
    }

	~ClientUdpProxySession()
	{
		LOG_DETAIL(UDP_DEBUG("[{:p}] udp session die", (void*)this))
        while (!bufferqueue_.Empty())
        {
            bufferqueue_.Dequeue();
        }
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
        boost::asio::spawn(this->local_socket_->get_executor(), [this, self](boost::asio::yield_context yield){

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

    auto& GetLocalEndPoint()
    {
        return local_ep_;
    }

    void sendToRemote(uint64_t bytes)
    {

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
        auto udp_socks_packet = (socks5::UDP_RELAY_PACKET*)protocol_hdr->GetDataOffsetPtr();

		auto res = bufferqueue_.Enqueue(bytes, GetLocalBuffer(), remote_ep_);

		// queue is full if res == nullptr, we have to discard data
		if (likely(!res)) return;

		// return if there's another coroutine running
		// Enqueue is thread safe cause we are in the same context
		if (remote_sending) return;

		remote_sending = true;

		auto self(this->shared_from_this());
		boost::asio::spawn(this->local_socket_->get_executor(),
			[this, self](boost::asio::yield_context yield) {

			while (!bufferqueue_.Empty())
			{
				boost::system::error_code ec;

				auto bufferinfo = bufferqueue_.GetFront();

				size_t bytes_send = this->remote_socket_.async_send_to(boost::asio::buffer(bufferinfo->payload_, bufferinfo->size_), bufferinfo->remote_ep_, yield[ec]);

				if (ec)
				{
					UDP_DEBUG("onRemoteSend err --> {}", ec.message().c_str())

//					while (!bufferqueue_.Empty()) {
//						bufferqueue_.Dequeue();
//					}

					return;
				}

				LOG_DETAIL(UDP_DEBUG("[{}] udp send {} bytes to remote : {}:{}", (void*)this, bytes_send, bufferinfo->remote_ep_.address().to_string().c_str(), bufferinfo->remote_ep_.port()))
					
				bufferqueue_.Dequeue();
				
				last_update_time = time(nullptr);

			}

			remote_sending = false;

		});

    }

	void ForceCancel()
	{
		boost::system::error_code ec;
		this->remote_socket_.cancel(ec);
		this->timer_.cancel(ec);
	}

private:

    Protocol protocol_;

    SESSION_MAP& session_map_;

    boost::asio::ip::udp::endpoint local_ep_;
    boost::asio::ip::udp::endpoint remote_ep_;
    boost::asio::ip::udp::endpoint remote_recv_ep_;

    unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];
    unsigned char remote_recv_buff_[UDP_REMOTE_RECV_BUFF_SIZE];

	BufferQueue bufferqueue_;
	bool remote_sending = false;

    boost::shared_ptr<boost::asio::ip::udp::socket> local_socket_;
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

        LOG_DETAIL(UDP_DEBUG("[{:p}] send {} bytes to remote", (void*)this, bytes_send))

    }

    uint64_t readFromRemote(boost::asio::yield_context yield)
    {
        boost::system::error_code ec;

        uint64_t bytes_read = this->remote_socket_.async_receive_from(boost::asio::buffer(remote_recv_buff_, UDP_REMOTE_RECV_BUFF_SIZE), remote_recv_ep_, yield[ec]);

        if (ec)
        {
            UDP_DEBUG("[{:p}] Udp readFromRemote err --> {}", (void*)this, ec.message().c_str())
			return 0;
        }
		LOG_DETAIL(UDP_DEBUG("[{:p}] Udp read {} bytes FromRemote : {}:{}", (void*)this, bytes_read, remote_recv_ep_.address().to_string().c_str(), remote_recv_ep_.port()))

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;
        return protocol_.OnUdpPayloadReadFromClientRemote(protocol_hdr);
    }

    bool sendToLocal(uint64_t bytes, boost::asio::yield_context yield)
    {
        boost::system::error_code ec;

		uint64_t bytes_send = this->local_socket_->async_send_to(boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), bytes), local_ep_, yield[ec]);

        if (ec)
        {
            UDP_DEBUG("[{:p}] Udp sendToLocal err --> {}", (void*)this, ec.message().c_str())
			return false;
        }
		LOG_DETAIL(UDP_DEBUG("[{:p}] Udp send {} bytes to Local", (void*)this, bytes_send))

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
			UDP_DEBUG("Udp timer err --> {}", ec.message().c_str())
			UDP_DEBUG("session_map_ size --> {}, max size -> {}, max bucket count -> {}", session_map_.size(), session_map_.max_size(), session_map_.max_bucket_count());

			if (this->isDnsReq){
				this->session_map_.erase(local_ep_);
			}

			return;
		}


		if (time(nullptr) - last_update_time > SESSION_TIMEOUT)
		{
			UDP_DEBUG("[{}] udp session {}:{} timeout --> {}", (void*)this,local_ep_.address().to_string().c_str(), local_ep_.port(), ec.message().c_str())
			UDP_DEBUG("session_map_ size --> {}, max size -> {}, max bucket count -> {}", session_map_.size(), session_map_.max_size(), session_map_.max_bucket_count());

			boost::system::error_code ec;
			this->remote_socket_.cancel(ec);
			this->session_map_.erase(local_ep_);
			return;
		}

		timer_.expires_from_now(boost::posix_time::seconds(TIMER_EXPIRE_TIME));
		timer_.async_wait(boost::bind(&ClientUdpProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));

	}


};

