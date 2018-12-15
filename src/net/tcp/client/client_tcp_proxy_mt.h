#pragma once

#include "../../../netio/basic_network_io_mt.h"

#include <string>
#include <vector>
#include <memory>

#define BOOST_COROUTINES_NO_DEPRECATION_WARNING
#include <boost/asio/spawn.hpp>
#include <boost/make_shared.hpp>

#include "client_tcp_proxy_session.h"
#include "../../../utils/logger.h"

#include "../../../utils/Singleton.h"
#include <boost/lexical_cast.hpp>

template <class Protocol>
class ClientTcpProxy_MT : public INetworkProxy , public Singleton<ClientTcpProxy_MT<Protocol>>{

    using ACCEPTOR = boost::asio::ip::tcp::acceptor;
    using PACCEPTOR = std::unique_ptr<ACCEPTOR>;
    using VPACCEPTOR = std::vector<PACCEPTOR>;

public:

    ClientTcpProxy_MT() {}



    void SetServerInfo(std::string server_ip, uint16_t server_port, std::string key)
    {
        this->server_ip = server_ip;
        this->server_port = server_port;
        bzero(proxyKey_, 32U);
        memcpy(proxyKey_, key.c_str(), key.size());
    }


    void StartProxy(std::string local_address, uint16_t local_port)
    {

        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

        for(int i = 0; i < vpio_context_.size(); i++)
        {
            int opt = 1;

            vpacceptor_.emplace_back(std::make_unique<ACCEPTOR>(*vpio_context_[i]));
            vpacceptor_.back()->open(ep.protocol());
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(vpacceptor_.back()->native_handle(), SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
            vpacceptor_.back()->bind(ep);
            vpacceptor_.back()->listen(SOMAXCONN);

        }


        startAcceptorCoroutine();


        LOG_INFO("start tcp proxy with {} thread, server: {}:{}, using key: {}, local: {}:{}", boost::thread::physical_concurrency(), this->server_ip.c_str(), this->server_port, this->key, local_address.c_str(), local_port)

        this->RunIO();

    }


private:

    unsigned char proxyKey_[32U];

    VPACCEPTOR vpacceptor_;

    std::string server_ip;
    uint16_t server_port;
    std::string key;


    void startAcceptorCoroutine()
    {

        for(int i = 0; i < vpio_context_.size(); i++)
        {

            boost::asio::spawn(*vpio_context_[i], [this, i](boost::asio::yield_context yield) {

                bool isRunning = true;

                while (isRunning)
                {
                    boost::system::error_code ec;
                    auto new_session = boost::make_shared<ClientTcpProxySession<Protocol>>(*vpio_context_[i], this->server_ip, this->server_port, proxyKey_, true);
                    this->vpacceptor_[i]->async_accept(new_session->GetLocalSocketRef(), yield[ec]);

                    if (ec)
                    {
                        LOG_INFO("accept err")
                        isRunning = false;
                        return;
                    }

                    LOG_INFO("[Thread: {}] new connection from {}:{}", boost::lexical_cast<std::string>(boost::this_thread::get_id()).c_str(), new_session->GetLocalSocketRef().remote_endpoint().address().to_string().c_str(), new_session->GetLocalSocketRef().remote_endpoint().port())

                    new_session->Start();
                }


            });

        }



    }


};


