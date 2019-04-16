#pragma once
#include "../../../utils/logger.h"
#include "../../inetwork_proxy.h"
#include "../../../protocol/socks5/socks5_protocol_helper.h"
#include "server_udp_proxy_session.h"


#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/unordered_map.hpp>
#include <boost/enable_shared_from_this.hpp>


/*
 *  multithread version of udp proxy without reuseport
 *
 *  acceptor ->   session
 *    1     ->      N
 *
 *  N sessions share 1 acceptor,
 *  sessions may or may not in the same thread with acceptor
 *  but the session_map can only be R/W in acceptor's thread
 *
 *  closing method:
 *      iterate the session_map, cancel and remove all the session(including the timer)
 *      cancel timer for acceptor
 *
 */
template <class Protocol>
class ServerUdpProxy : public INetworkProxy, public boost::enable_shared_from_this<ServerUdpProxy<Protocol>> {


	using ACCEPTOR = boost::asio::ip::udp::socket;
	using PACCEPTOR = boost::shared_ptr<ACCEPTOR>;

	using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ServerUdpProxySession<Protocol>>, EndPointHash>;

public:

	ServerUdpProxy() : protocol_(nullptr) {
		UDP_DEBUG("[{}] UDP Server created", (void*)this)
	}

	~ServerUdpProxy() {
		UDP_DEBUG("ServerUdpProxy at port: {} die", this->server_port)
	}

	auto& GetDefaultIO()
	{
		return this->GetIOContext();
	}

	virtual void StartProxy(std::string local_address, uint16_t local_port) override
	{
		pacceptor_ = boost::make_shared<ACCEPTOR>(this->GetIOContext());

		if (expire_time > 0)
		{
			ptimer_ = std::make_unique<TIMER>(this->GetIOContext());
			ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
			ptimer_->async_wait(boost::bind(&ServerUdpProxy::onTimeExpire, this, boost::asio::placeholders::error));
		}

		this->server_ip = local_address;
		this->server_port = local_port;

		this->protocol_.SetKey(this->proxyKey_);

		auto ep = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(local_address), local_port);

		boost::system::error_code ec;

		pacceptor_->open(ep.protocol(), ec);
		if (ec)
		{
			LOG_ERROR("udp acceptor open err--> {}", ec.message().c_str())
				return;
		}
		pacceptor_->bind(ep, ec);

		if (ec)
		{
			LOG_ERROR("udp acceptor bind err--> {}", ec.message().c_str())
				return;
		}

		startAcceptorCoroutine();

		LOG_INFO("ServerUdpProxy started at [{}:{}], key: [{}]", local_address.c_str(), local_port, proxyKey_)

			this->RunIO();

	}

	void StopProxy()
	{
	    auto self(this->shared_from_this());
	    this->pacceptor_->get_io_context().post([this, self]{
            for (auto it = session_map_.begin(); it != session_map_.end(); )
            {

                it->second->ForceCancel();
                it = session_map_.erase(it);
            }

            this->pacceptor_->cancel();
            // only close timer when it is set
            if (this->ptimer_) this->ptimer_->cancel();
	    });
	}

private:

	Protocol protocol_;

	PACCEPTOR pacceptor_;

	SESSION_MAP session_map_;

	unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];

	virtual void startAcceptorCoroutine() override
	{
		auto self(this->shared_from_this());

		boost::asio::spawn(this->GetIOContext(), [this, self](boost::asio::yield_context yield) {

			while (1)
			{
				boost::system::error_code ec;

				boost::asio::ip::udp::endpoint local_ep_;
				//async recv
				uint64_t bytes_read = pacceptor_->async_receive_from(boost::asio::buffer(local_recv_buff_, UDP_LOCAL_RECV_BUFF_SIZE), local_ep_, yield[ec]);

				if (ec == boost::system::errc::operation_canceled)
                {
                    LOG_INFO("udp server accept err --> Operation canceled");
                    return;
                }
				if (ec || bytes_read == 0)
				{
					LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
						continue;
				}
				UDP_DEBUG("read {} bytes udp data from local", bytes_read)

				last_active_time = time(nullptr);

				auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
				// decrypt packet and get payload length
				bytes_read = protocol_.OnUdpPayloadReadFromServerLocal(protocol_hdr, std::string());
				UDP_DEBUG("udp payload length: {}", bytes_read)

				if (bytes_read == 0)
				{
					UDP_DEBUG("decrypt err, drop packet")
					continue;
				}

				auto map_it = session_map_.find(local_ep_);

				if (map_it == session_map_.end())
				{
					UDP_DEBUG("new session from {}:{}", local_ep_.address().to_string().c_str(), local_ep_.port())

					auto new_session = boost::make_shared<ServerUdpProxySession<Protocol>>(this->server_ip, this->server_port, proxyKey_, pacceptor_, session_map_, this->GetRandomIOContext());

					new_session->GetLocalEndPoint() = local_ep_;

					// COPY proxy data only (without protocol header)
					memcpy(new_session->GetLocalBuffer(), protocol_hdr->GetDataOffsetPtr(), bytes_read);

					session_map_.insert(std::make_pair(local_ep_, new_session));
					new_session->sendToRemote(bytes_read);
					new_session->Start();

				}
				else {
					UDP_DEBUG("old session from {}:{}", local_ep_.address().to_string().c_str(), local_ep_.port())

					// COPY proxy data only (without protocol header)
					memcpy(map_it->second->GetLocalBuffer(), protocol_hdr->GetDataOffsetPtr(), bytes_read);
					map_it->second->sendToRemote(bytes_read);
				}

			}

		});
	}


	void onTimeExpire(const boost::system::error_code &ec)
	{
		UDP_DEBUG("[{}] UDP onTimeExpire, mapsize: {}", (void*)this, session_map_.size())

		if (ec)
        {
            LOG_INFO("onTimeExpire err --> {}", ec.message().c_str())
            return;
        }

		if (time(nullptr) - last_active_time > expire_time && session_map_.size() == 0)
		{
			boost::system::error_code ec;
			this->pacceptor_->cancel(ec);
			LOG_INFO("[{}] udp server at port {} timeout", (void*)this, server_port)
			return;
		}

		ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
		ptimer_->async_wait(boost::bind(&ServerUdpProxy::onTimeExpire, this, boost::asio::placeholders::error));

	}


};

