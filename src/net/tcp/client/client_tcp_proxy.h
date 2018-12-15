#pragma once

#include "../../../netio/basic_network_io.h"

#include <string>
#include <memory>

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>
#include "client_tcp_proxy_session.h"
#include "../../../utils/logger.h"

#include "../../../protocol/iproxy_protocol.h"
#include "../../inetwork_proxy.h"
#include <boost/enable_shared_from_this.hpp>



template <class Protocol>
class ClientTcpProxy : public INetworkProxy, public boost::enable_shared_from_this<ClientTcpProxy<Protocol>>{

    using ACCEPTOR = boost::asio::ip::tcp::acceptor;
    using PACCEPTOR = std::unique_ptr<ACCEPTOR>;


public:

    ClientTcpProxy()
    {
        last_active_time = time(nullptr);
    }

    void EnableDnsResolver()
    {
        resolve_dns = true;
    }

    virtual void StartProxy(std::string local_address, uint16_t local_port) override
    {
        pacceptor_ = std::make_unique<ACCEPTOR>(this->GetIOContext());
//  we currently don't set expire time for client
//        ptimer_ = std::make_unique<TIMER>(this->GetIOContext());
//        ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
//        ptimer_->async_wait(boost::bind(&ClientTcpProxy::onTimeExpire, this, boost::asio::placeholders::error));

        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

        boost::system::error_code ec;

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

        boost::asio::ip::tcp::acceptor::reuse_address opt2(true);
        pacceptor_->set_option(opt2);

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

        LOG_INFO("ClientTcpProxy started, Server: [{}:{}], Key: [{}], Local socks5 Port: [{}:{}]", this->server_ip.c_str(), this->server_port, proxyKey_, local_address.c_str(), local_port)

        this->RunIO();

    }


private:

    PACCEPTOR pacceptor_;

    bool resolve_dns = false;

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());

        boost::asio::spawn(this->GetIOContext(),[this, self](boost::asio::yield_context yield) {

            while (1)
            {
				
                boost::system::error_code ec;
				#ifdef MULTITHREAD_IO
				auto new_session = boost::make_shared<ClientTcpProxySession<Protocol>>(this->GetRandomIOContext(), this->server_ip, this->server_port, proxyKey_, resolve_dns);
				#else
				auto new_session = boost::make_shared<ClientTcpProxySession<Protocol>>(this->GetIOContext(), this->server_ip, this->server_port, proxyKey_, resolve_dns);
				#endif
                this->pacceptor_->async_accept(new_session->GetLocalSocketRef(), yield[ec]);

                if (ec)
                {
                    LOG_INFO("client accept err --> {}", ec.message().c_str())
                    return;
                }
                LOG_INFO("new connection from {}:{}", new_session->GetLocalSocketRef().remote_endpoint().address().to_string().c_str(), new_session->GetLocalSocketRef().remote_endpoint().port())
                //last_active_time = time(nullptr);

                new_session->Start();
            }


        });
    }


    void onTimeExpire(const boost::system::error_code &ec)
    {
        LOG_DEBUG("onTimeExpire")

        if (ec) return;

        if (time(nullptr) - last_active_time > expire_time)
        {
            boost::system::error_code ec;
            this->pacceptor_->cancel(ec);
            LOG_INFO("client at port {} timeout", server_port)
            return;
        }

        ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
        ptimer_->async_wait(boost::bind(&ClientTcpProxy::onTimeExpire, this, boost::asio::placeholders::error));


    }

};


