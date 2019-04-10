#pragma once

#include "../../../utils/logger.h"
#include "../../inetwork_proxy.h"
#include "../../../netio/basic_network_io.h"
#include "server_tcp_proxy_session.h"

#include <string>
#include <memory>
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>


/*
 *  multithread version of tcp proxy without reuseport
 *
 *  acceptor ->   session
 *    1     ->      N
 *
 *  sessions may or may not in the same thread with acceptor
 *
 *  closing method:
 *      cancel timer and acceptor only
 *      session will expire when they timeout
 *
 */
template <class Protocol>
class ServerTcpProxy : public INetworkProxy, public boost::enable_shared_from_this<ServerTcpProxy<Protocol>> {

	using ACCEPTOR = boost::asio::ip::tcp::acceptor;
	using PACCEPTOR = std::unique_ptr<ACCEPTOR>;

public:

	ServerTcpProxy() {

		TCP_DEBUG("[{}] TCP Server created", (void*)this)

	}
	~ServerTcpProxy() {

		TCP_DEBUG("ServerTcpProxy at port: {} die", this->server_port)

	}
	virtual void StartProxy(std::string local_address, uint16_t local_port) override
	{
		pacceptor_ = std::make_unique<ACCEPTOR>(this->GetIOContext());

		//timer init for server
		if (expire_time > 0)
		{
			ptimer_ = std::make_unique<TIMER>(this->GetIOContext());
			ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
			ptimer_->async_wait(boost::bind(&ServerTcpProxy::onTimeExpire, this->shared_from_this(), boost::asio::placeholders::error));
		}

		auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(local_address), local_port);

		boost::system::error_code ec;

		// might throw too many open files
		pacceptor_->open(ep.protocol(), ec);

		if (ec)
		{
			LOG_ERROR("err opening acceptor --> {}", ec.message().c_str())
			return;
		}


		struct in6_addr in_val;
		if (inet_pton(AF_INET6, local_address.c_str(), &in_val) == 1)
		{
			boost::asio::ip::v6_only opt1(false);
			pacceptor_->set_option(opt1);
		}

		boost::asio::ip::tcp::acceptor::reuse_address option(true);
		pacceptor_->set_option(option);

		pacceptor_->bind(ep, ec);

		if (ec)
		{
			LOG_ERROR("err binding acceptor --> {}", ec.message().c_str())
			return;
		}

		pacceptor_->listen(SOMAXCONN, ec);

		if (ec)
		{
			LOG_ERROR("err listen acceptor --> {}", ec.message().c_str())
				return;
		}

		startAcceptorCoroutine();

		LOG_INFO("ServerTcpProxy started at [{}:{}], key: [{}]", local_address.c_str(), local_port, proxyKey_)

		this->RunIO();

	}

	void StopProxy()
	{
		this->pacceptor_->cancel();
		if (this->ptimer_) this->ptimer_->cancel();
	}

private:

	PACCEPTOR pacceptor_;

	virtual void startAcceptorCoroutine() override
	{
		auto self(this->shared_from_this());

		boost::asio::spawn(this->GetIOContext(), [this, self](boost::asio::yield_context yield) {

			while (1)
			{
				boost::system::error_code ec;
#ifdef MULTITHREAD_IO
				auto new_session = boost::make_shared<ServerTcpProxySession<Protocol>>(this->GetRandomIOContext(), proxyKey_);
#else
				auto new_session = boost::make_shared<ServerTcpProxySession<Protocol>>(this->GetIOContext(), proxyKey_);
#endif
				this->pacceptor_->async_accept(new_session->GetLocalSocketRef(), yield[ec]);

				if (ec)
				{
					LOG_INFO("tcp server accept err --> {}", ec.message().c_str())
					return;
				}

				LOG_INFO("new connection from {}:{}", new_session->GetLocalSocketRef().remote_endpoint(ec).address().to_string().c_str(), new_session->GetLocalSocketRef().remote_endpoint(ec).port())

				new_session->Start();
			}


		});
	}

	void onTimeExpire(const boost::system::error_code &ec)
	{
		if (ec)
		{
			LOG_INFO("onTimeExpire err --> {}", ec.message().c_str())
			return;
		}
		TCP_DEBUG("[{}] TCP onTimeExpire", (void*)this)

		if (time(nullptr) - last_active_time > expire_time)
		{
			boost::system::error_code ec;
			this->pacceptor_->cancel(ec);
			LOG_INFO("[{}] tcp server [port {}] timeout", (void*)this, server_port)
				return;
		}

		ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
		ptimer_->async_wait(boost::bind(&ServerTcpProxy::onTimeExpire, this->shared_from_this(), boost::asio::placeholders::error));


	}

};


