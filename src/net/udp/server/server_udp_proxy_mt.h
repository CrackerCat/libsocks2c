#pragma once

#include "../../../utils/logger.h"
#include "../../inetwork_proxy.h"
#include "../../../protocol/socks5_protocol_helper.h"
#include "server_udp_proxy_session.h"


#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/unordered_map.hpp>
#include <boost/enable_shared_from_this.hpp>

template <class Protocol>
class ServerUdpProxy : public INetworkProxy, public boost::enable_shared_from_this<ServerUdpProxy<Protocol>> {


    using ACCEPTOR = boost::asio::ip::udp::socket;
    using PACCEPTOR = boost::shared_ptr<ACCEPTOR>;
    using VPACCEPTOR = std::vector<PACCEPTOR>;
    using VPTIMER = std::vector<PTIMER>;

    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ServerUdpProxySession<Protocol>>, EndPointHash>;
    using VSESSION_MAP = std::vector<SESSION_MAP>;

public:

    ServerUdpProxy() : vsession_map_(this->GetVIOContextSize())
    {
        UDP_DEBUG("[{}] UDP Server created", (void*)this)

        for (int j = 0; j < this->GetVIOContextSize(); ++j) {
            vprotocol_.emplace_back(Protocol(&this->GetIOContextAt(j)));
        }

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

        auto ep = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(local_address), local_port);


        for(int i = 0; i < this->GetVIOContextSize(); i++)
        {
            UDP_DEBUG("Start udp acceptor {}", i)

            boost::system::error_code ec;

            int opt = 1;

            vpacceptor_.emplace_back(boost::make_shared<ACCEPTOR>(this->GetIOContextAt(i)));
            vpacceptor_.back()->open(ep.protocol(), ec);
            if (ec)
            {
                LOG_ERROR("err opening acceptor --> {}", ec.message().c_str())
                return;
            }

            this->server_ip = local_address;
            this->server_port = local_port;

            this->vprotocol_[i].SetKey(this->proxyKey_);

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

        }

//        if (expire_time > 0)
//        {
//            ptimer_ = std::make_unique<TIMER>(this->GetIOContext());
//            ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
//            ptimer_->async_wait(boost::bind(&ServerUdpProxy::onTimeExpire, this, boost::asio::placeholders::error));
//        }

        startAcceptorCoroutine();

        LOG_INFO("ServerUdpProxy[MT] started at [{}:{}], key: [{}]", local_address.c_str(), local_port, proxyKey_)

        this->RunIO();

    }

    void StopProxy()
    {
        auto self(this->shared_from_this());

        for(int i = 0; i < this->GetVIOContextSize(); i++)
        {
            this->vpacceptor_[i]->get_io_context().post([this, self, i]{
                for (auto it = vsession_map_[i].begin(); it != vsession_map_[i].end(); )
                {

                    it->second->ForceCancel();
                    it = vsession_map_[i].erase(it);
                }

                this->vpacceptor_[i]->cancel();
                // only close timer when it is set
                //if (this->vptimer_[i]) this->ptimer_[i]->cancel();
            });



        }


    }



private:

    std::vector<Protocol> vprotocol_;

    VPACCEPTOR vpacceptor_;

    SESSION_MAP session_map_;
    VSESSION_MAP vsession_map_;

    bool should_close = false;

    unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());

        for(int i = 0; i < GetVIOContextSize(); i++)
        {
            boost::asio::spawn(this->GetIOContextAt(i), [this, self, i](boost::asio::yield_context yield) {

                while (1)
                {
                    boost::system::error_code ec;

                    boost::asio::ip::udp::endpoint local_ep_;

                    //async recv
                    uint64_t bytes_read = this->vpacceptor_[i]->async_receive_from(boost::asio::buffer(local_recv_buff_, UDP_LOCAL_RECV_BUFF_SIZE), local_ep_, yield[ec]);

                    if (ec == boost::system::errc::operation_canceled) return;
                    if (ec || bytes_read == 0)
                    {
                        LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
                        continue;
                    }
                    UDP_DEBUG("[Thread {}] read {} bytes udp data from local", boost::lexical_cast<std::string>(boost::this_thread::get_id()).c_str() ,bytes_read)

                    last_active_time = time(nullptr);

                    auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
                    // decrypt packet and get payload length
                    bytes_read = vprotocol_[i].OnUdpPayloadReadFromServerLocal(protocol_hdr, local_ep_.address().to_string() + ":" + boost::lexical_cast<std::string>(local_ep_.port()));
                    UDP_DEBUG("udp payload length: {}", bytes_read)

                    if (bytes_read == 0)
                    {
                        UDP_DEBUG("decrypt err, drop packet")
                        continue;
                    }

                    auto map_it = vsession_map_[i].find(local_ep_);

                    if (map_it == vsession_map_[i].end())
                    {
                        UDP_DEBUG("new session from {}:{}", local_ep_.address().to_string().c_str(), local_ep_.port())

                        auto new_session = boost::make_shared<ServerUdpProxySession<Protocol>>(this->server_ip, this->server_port, proxyKey_, this->vpacceptor_[i], vsession_map_[i]);

                        new_session->GetLocalEndPoint() = local_ep_;

                        // COPY proxy data only (without protocol header)
                        memcpy(new_session->GetLocalBuffer(), protocol_hdr->GetDataOffsetPtr(), bytes_read);

                        vsession_map_[i].insert(std::make_pair(local_ep_, new_session));
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

    }


    void onTimeExpire(const boost::system::error_code &ec)
    {
//        UDP_DEBUG("[{}] UDP onTimeExpire, mapsize: {}", (void*)this, vsession_map_[i].size())
//
//        if (ec) return;
//
//        if (time(nullptr) - last_active_time > expire_time && vsession_map_[i].size() == 0)
//        {
//            boost::system::error_code ec;
//            this->pacceptor_->cancel(ec);
//            LOG_INFO("[{}] udp server at port {} timeout", (void*)this, server_port)
//
//            should_close = true;
//
//            return;
//        }
//
//        ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
//        ptimer_->async_wait(boost::bind(&ServerUdpProxy::onTimeExpire, this, boost::asio::placeholders::error));


    }


};

