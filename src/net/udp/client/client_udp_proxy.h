#pragma once

#include "../../inetwork_proxy.h"
#include "../../../utils/logger.h"
#include "../../../protocol/socks5_protocol_helper.h"
#include "client_udp_proxy_session.h"


#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/unordered_map.hpp>
#include <boost/enable_shared_from_this.hpp>


template <class Protocol>
class ClientUdpProxy : public INetworkProxy, public boost::enable_shared_from_this<ClientUdpProxy<Protocol>>{

    using ACCEPTOR = boost::asio::ip::udp::socket;
    using PACCEPTOR = boost::shared_ptr<ACCEPTOR>;

    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientUdpProxySession<Protocol>>, EndPointHash>;


public:

    ClientUdpProxy() {}

	~ClientUdpProxy()
	{
		UDP_DEBUG("ClientUdpProxy die")
	}

    virtual void StartProxy(std::string local_address, uint16_t local_port) override
    {
        pacceptor_ = boost::make_shared<ACCEPTOR>(this->GetIOContext());

		Socks5ProtocolHelper::SetUdpSocks5ReplyEndpoint("127.0.0.1", local_port);

        auto ep = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

        pacceptor_->open(ep.protocol());

        int opt = 1;

        setsockopt(pacceptor_->native_handle(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(pacceptor_->native_handle(), SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        pacceptor_->bind(ep);

		this->protocol_.SetKey(this->proxyKey_);

        startAcceptorCoroutine();

        LOG_INFO("ClientUdpProxy started, Server: [{}:{}], Key: [{}], Local socks5 Port: [{}:{}]", this->server_ip.c_str(), this->server_port, proxyKey_, local_address.c_str(), local_port)

        this->RunIO();
    }

	void Pause()
	{
		this->pacceptor_->cancel();
	}

	void Restart()
	{
		startAcceptorCoroutine();
	}

	void StopProxy()
	{
        for (auto it = session_map_.begin(); it != session_map_.end(); )
        {

            it->second->ForceCancel();
            it = session_map_.erase(it);
        }

        this->pacceptor_->cancel();
        // only close timer when it is set
        if (this->ptimer_) this->ptimer_->cancel();
	}

protected:

    Protocol protocol_;

    PACCEPTOR pacceptor_;

    SESSION_MAP session_map_;

    unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());
        boost::asio::spawn(this->GetIOContext(),[this, self](boost::asio::yield_context yield) {

			boost::asio::ip::udp::endpoint local_ep_;

            while (1)
            {
                boost::system::error_code ec;

                //async recv
                uint64_t bytes_read = pacceptor_->async_receive_from(boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), UDP_LOCAL_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 10), local_ep_, yield[ec]);

                if (ec || bytes_read == 0)
                {
					LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
					if (ec == boost::system::errc::operation_canceled) return;
                    continue;
                }

				LOG_DETAIL(UDP_DEBUG("read {} bytes udp data from local ", bytes_read))

				bool isDnsPacket = Socks5ProtocolHelper::isDnsPacket((socks5::UDP_RELAY_PACKET*)(local_recv_buff_ + Protocol::ProtocolHeader::Size()));
                last_active_time = time(nullptr);


                //encrypt packet
                auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
                protocol_hdr->PAYLOAD_LENGTH = bytes_read;
                //get payload length
                bytes_read = protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

                //if (!Socks5ProtocolHelper::IsUdpSocks5PacketValid(new_session->GetLocalBuffer())) continue;

                auto map_it = session_map_.find(local_ep_);

                if (map_it == session_map_.end())
                {

					auto new_session = boost::make_shared<ClientUdpProxySession<Protocol>>(this->server_ip, this->server_port, proxyKey_, pacceptor_, session_map_, this->GetRandomIOContext());
					
					UDP_DEBUG("new session [{}] from {}:{}", (void*)new_session.get(), local_ep_.address().to_string().c_str(), local_ep_.port());

					if (isDnsPacket) new_session->SetDnsPacket();
					new_session->GetLocalEndPoint() = local_ep_;
                    session_map_.insert(std::make_pair(local_ep_, new_session));

					memcpy(new_session->GetLocalBuffer(), local_recv_buff_, bytes_read);
                    new_session->sendToRemote(bytes_read);
                    new_session->Start();
                } else{
					UDP_DEBUG("old session from {}:{}", local_ep_.address().to_string().c_str(), local_ep_.port())

					memcpy(map_it->second->GetLocalBuffer(), local_recv_buff_, bytes_read);
                    map_it->second->sendToRemote(bytes_read);

                }

            }


        });
    }



    void onTimeExpire(const boost::system::error_code &ec)
    {
        UDP_DEBUG("onTimeExpire")

        if (ec) return;

        if (time(nullptr) - last_active_time > expire_time)
        {
            boost::system::error_code ec;
            this->pacceptor_->cancel(ec);
            LOG_INFO("client at port {} timeout", server_port)
            return;
        }

        ptimer_->expires_from_now(boost::posix_time::seconds(expire_time));
        ptimer_->async_wait(boost::bind(&ClientUdpProxy::onTimeExpire, this, boost::asio::placeholders::error));


    }

};

