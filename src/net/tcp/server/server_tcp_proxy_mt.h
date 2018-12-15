#pragma once

#include "../../../netio/basic_network_io_mt.h"
#include <string>
#include <memory>

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>

#include "server_tcp_proxy_session.h"
#include "../../../utils/logger.h"

#include "../../../utils/Singleton.h"
#include <arpa/inet.h>

template <class Protocol>
class ServerTcpProxy_MT : public INetworkProxy , public Singleton<ServerTcpProxy_MT<Protocol>>{


    using ACCEPTOR = boost::asio::ip::tcp::acceptor;
    using PACCEPTOR = std::unique_ptr<ACCEPTOR>;
    using VPACCEPTOR = std::vector<PACCEPTOR>;
public:

    ServerTcpProxy_MT(){}



    void StartProxy(std::string local_address, uint16_t local_port)
    {

        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

        boost::system::error_code ec;

        for(int i = 0; i < this->GetVIOContextSize(); i++)
        {
            int opt = 1;



            vpacceptor_.emplace_back(std::make_unique<ACCEPTOR>(this->GetIOContextAt(i)));
            vpacceptor_.back()->open(ep.protocol(), ec);
            struct in6_addr in_val;
            if (inet_pton(AF_INET6, local_address.c_str(), &in_val) == 1)
            {
                boost::asio::ip::v6_only opt1(false);
                vpacceptor_.back()->set_option(opt1);
            }
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
            vpacceptor_.back()->bind(ep);
            vpacceptor_.back()->listen(SOMAXCONN);

        }



        startAcceptorCoroutine();


        //LOG_INFO("start tcp proxy with {} thread, using key: {}, local: {}:{}", boost::thread::physical_concurrency(), proxyKey_, local_address.c_str(), local_port)
        LOG_INFO("ServerTcpProxyMt started at [{}:{}], key: [{}]", local_address.c_str(), local_port, proxyKey_)

        this->RunIO();




    }


private:

    VPACCEPTOR vpacceptor_;


    void startAcceptorCoroutine()
    {

        for(int i = 0; i < GetVIOContextSize(); i++)
        {

            boost::asio::spawn(GetIOContextAt(i), [this, i](boost::asio::yield_context yield) {


                while (1)
                {
                    boost::system::error_code ec;
                    auto new_session = boost::make_shared<ServerTcpProxySession<Protocol>>(GetIOContextAt(i), proxyKey_);
                    this->vpacceptor_[i]->async_accept(new_session->GetLocalSocketRef(), yield[ec]);

                    if (ec)
                    {
                        LOG_INFO("acceptor {} err --> {}", i, ec.message().c_str())
                        return;
                    }

                    LOG_DEBUG("[Thread: {}] new connection from {}:{}", boost::lexical_cast<std::string>(boost::this_thread::get_id()).c_str(), new_session->GetLocalSocketRef().remote_endpoint().address().to_string().c_str(), new_session->GetLocalSocketRef().remote_endpoint().port())

                    new_session->Start();
                }


            });

        }

    }


};


