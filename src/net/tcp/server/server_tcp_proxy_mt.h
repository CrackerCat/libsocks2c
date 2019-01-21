#pragma once

#include "../../../netio/basic_network_io_mt.h"
#include <string>
#include <memory>

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <atomic>
#include "server_tcp_proxy_session.h"
#include "../../../utils/logger.h"

#include <arpa/inet.h>

template <class Protocol>
class ServerTcpProxy : public INetworkProxy , public boost::enable_shared_from_this<ServerTcpProxy<Protocol>>{


    using ACCEPTOR = boost::asio::ip::tcp::acceptor;
    using PACCEPTOR = std::unique_ptr<ACCEPTOR>;
    using VPACCEPTOR = std::vector<PACCEPTOR>;
    using VPTIMER = std::vector<PTIMER>;
public:

    ServerTcpProxy() {

        TCP_DEBUG("[{}] TCP Server created", (void*)this)

    }
    ~ServerTcpProxy() {


        TCP_DEBUG("ServerTcpProxy at port: {} die", this->server_port)

    }

    void StartProxy(std::string local_address, uint16_t local_port)
    {

        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

        boost::system::error_code ec;

        for(int i = 0; i < this->GetVIOContextSize(); i++)
        {
            TCP_DEBUG("Start tcp acceptor {}", i)

            int opt = 1;

            vpacceptor_.emplace_back(std::make_unique<ACCEPTOR>(this->GetIOContextAt(i)));
            vpacceptor_.back()->open(ep.protocol(), ec);
            if (ec)
            {
                LOG_ERROR("err opening acceptor --> {}", ec.message().c_str())
                return;
            }

            struct in6_addr in_val;
            if (inet_pton(AF_INET6, local_address.c_str(), &in_val) == 1)
            {
                boost::asio::ip::v6_only opt1(false);
                vpacceptor_.back()->set_option(opt1, ec);
            }
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
            vpacceptor_.back()->bind(ep, ec);
            if (ec)
            {
                LOG_ERROR("err bind acceptor {} --> {}", ec.message().c_str(), i)
                return;
            }
            vpacceptor_.back()->listen(SOMAXCONN, ec);
            if (ec)
            {
                LOG_ERROR("err listen acceptor {} --> {}", ec.message().c_str(), i)
                return;
            }

            if (expire_time > 0)
            {
                vptimer_.emplace_back(std::make_unique<TIMER>(this->GetIOContextAt(i)));
                vptimer_.back()->expires_from_now(boost::posix_time::seconds(expire_time));
                vptimer_.back()->async_wait(boost::bind(&ServerTcpProxy::onTimeExpire, this->shared_from_this(), boost::asio::placeholders::error, i));
            }

            ++acceptor_alive;
        }

        startAcceptorCoroutine();

        LOG_INFO("ServerTcpProxy[MT] started at [{}:{}], key: [{}]", local_address.c_str(), local_port, proxyKey_)

        this->RunIO();

    }

    void StopProxy()
    {
        for(int i = 0; i < GetVIOContextSize(); i++)
        {
            TCP_DEBUG("stopping tcp acceptor {}", i)
            this->vpacceptor_[i]->cancel();
            this->vptimer_[i]->cancel();
        }
        stopped = true;
    }

    bool Stopped()
    {
        return stopped;
    }

    bool ShouldClose()
    {
        return acceptor_alive == 0;
    }

private:

    VPACCEPTOR vpacceptor_;
    VPTIMER vptimer_;
    bool stopped = false;
    std::atomic<int> acceptor_alive = {0};

    void startAcceptorCoroutine()
    {
        auto self(this->shared_from_this());

        for(int i = 0; i < GetVIOContextSize(); i++)
        {

            boost::asio::spawn(GetIOContextAt(i), [this, self, i](boost::asio::yield_context yield) {


                while (1)
                {
                    boost::system::error_code ec;
                    auto new_session = boost::make_shared<ServerTcpProxySession<Protocol>>(GetIOContextAt(i), proxyKey_);
                    this->vpacceptor_[i]->async_accept(new_session->GetLocalSocketRef(), yield[ec]);

                    if (ec)
                    {
                        LOG_INFO("acceptor {} err --> {}", i, ec.message().c_str())
                        --acceptor_alive;
                        return;
                    }

                    TCP_DEBUG("new connection from {}:{}", new_session->GetLocalSocketRef().remote_endpoint().address().to_string().c_str(), new_session->GetLocalSocketRef().remote_endpoint().port())

                    new_session->Start();
                }


            });

        }

    }


    void onTimeExpire(const boost::system::error_code &ec, int index)
    {
        if (ec)
        {
            LOG_ERROR("timer {} onTimeExpire err --> {}", index, ec.message().c_str())
            return;
        }
        TCP_DEBUG("[{}] timer {} TCP onTimeExpire", index, (void*)this)

        if (time(nullptr) - last_active_time > expire_time)
        {
            boost::system::error_code ec;
            this->vpacceptor_[index]->cancel(ec);
            LOG_INFO("[{}] tcp server [port {}] acceptor {} timeout", (void*)this, server_port, index)
            return;
        }

        vptimer_[index]->expires_from_now(boost::posix_time::seconds(expire_time));
        vptimer_[index]->async_wait(boost::bind(&ServerTcpProxy::onTimeExpire, this->shared_from_this(), boost::asio::placeholders::error, index));


    }


};


