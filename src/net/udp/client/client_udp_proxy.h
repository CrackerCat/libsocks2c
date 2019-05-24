#pragma once

#include "../../inetwork_proxy.h"
#include "../../../utils/logger.h"
#include "../../../protocol/socks5/socks5_protocol_helper.h"
#include "client_udp_proxy_session.h"


#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/enable_shared_from_this.hpp>


template <class Protocol>
class ClientUdpProxy : public INetworkProxy, public boost::enable_shared_from_this<ClientUdpProxy<Protocol>>{

    using Acceptor = boost::asio::ip::udp::socket;
    using PAcceptor = boost::shared_ptr<Acceptor>;

    using SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientUdpProxySession<Protocol>>, EndPointHash>;


public:

    ClientUdpProxy() : protocol_(nullptr) {}

	virtual ~ClientUdpProxy()
	{
		LOG_DEBUG("ClientUdpProxy die")
	}

    virtual void StartProxy(std::string local_address, uint16_t local_port) override
    {
        pacceptor_ = boost::make_shared<Acceptor>(this->GetIOContext());

		Socks5ProtocolHelper::SetUdpSocks5ReplyEndpoint("127.0.0.1", local_port);

        auto ep = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(local_address),local_port);

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

		this->protocol_.SetKey(this->proxyKey_);

        startAcceptorCoroutine();

        LOG_INFO("[Client] UdpProxy started, Server: [{}:{}], Key: [{}], Local socks5 Port: [{}:{}]", this->server_ip.c_str(), this->server_port, proxyKey_, local_address.c_str(), local_port)

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

		StopRaw();
	}

	virtual void StopRaw() {}


protected:

    Protocol protocol_;

    PAcceptor pacceptor_;

    SESSION_MAP session_map_;

    unsigned char local_recv_buff_[UDP_LOCAL_RECV_BUFF_SIZE];

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());
        boost::asio::spawn(this->GetIOContext(),[this, self](boost::asio::yield_context yield) {

			boost::asio::ip::udp::endpoint local_ep;

            while (1)
            {
                boost::system::error_code ec;

                //async recv
                uint64_t bytes_read = pacceptor_->async_receive_from(boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), UDP_LOCAL_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 10), local_ep, yield[ec]);

                if (ec || bytes_read == 0)
                {
					LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
					if (ec == boost::system::errc::operation_canceled) return;
                    continue;
                }

				LOG_DETAIL(UDP_DEBUG("read {} bytes udp data from local ", bytes_read))

                handleLocalPacket(local_ep, bytes_read);

            }

        });
    }


    void handleLocalPacket(boost::asio::ip::udp::endpoint& local_ep, size_t bytes_read)
    {
        auto socks5_packet = (socks5::UDP_RELAY_PACKET*)(local_recv_buff_ + Protocol::ProtocolHeader::Size());
        bool isDnsPacket = Socks5ProtocolHelper::isDnsPacket(socks5_packet);

        std::string ip;
        uint16_t port;
        Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(socks5_packet, ip, port);

        LOG_INFO("[udp proxy] {}:{}", ip, port)

        //encrypt packet
        auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;
        protocol_hdr->PAYLOAD_LENGTH = static_cast<uint32_t>(bytes_read);
        //get payload length
        bytes_read = protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

        //if (!Socks5ProtocolHelper::IsUdpSocks5PacketValid(new_session->GetLocalBuffer())) continue;

        auto map_it = session_map_.find(local_ep);

        if (map_it == session_map_.end())
        {
#ifdef ENABLE_UOUT
            // when UOUT is enalbe, we don't use lf queue, so we can't dispatch downstream_context to other thread
            auto new_session = boost::make_shared<ClientUdpProxySession<Protocol>>(this->server_ip, this->server_port, proxyKey_, pacceptor_, session_map_, this->GetIOContext());
#else
            auto new_session = boost::make_shared<ClientUdpProxySession<Protocol>>(this->server_ip, this->server_port, proxyKey_, pacceptor_, session_map_, this->GetRandomIOContext());
#endif
            UDP_DEBUG("new session [{}] from {}:{}", (void*)new_session.get(), local_ep.address().to_string().c_str(), local_ep.port());

            if (isDnsPacket) new_session->SetDnsPacket();
            new_session->GetLocalEndPoint() = local_ep;
            session_map_.insert(std::make_pair(local_ep, new_session));

            memcpy(new_session->GetLocalBuffer(), local_recv_buff_, bytes_read);
            new_session->sendToRemote(bytes_read);
            new_session->Start();
        } else{
            UDP_DEBUG("old session from {}:{}", local_ep.address().to_string().c_str(), local_ep.port())

            memcpy(map_it->second->GetLocalBuffer(), local_recv_buff_, bytes_read);
            map_it->second->sendToRemote(bytes_read);

        }
    }


};

