#include "client_udp_proxy.h"
#ifdef _WIN32
#include "../../raw/client/client_udp_raw_proxy_win32.h"
#else
#include "../../raw/client/client_udp_raw_proxy.h"
#endif
template<class Protocol>
class ClientUdpProxyWithRaw : public ClientUdpProxy<Protocol>
{


public:

    void InitUout(std::string server_ip, std::string server_raw_port, std::string local_ip = std::string(), std::string local_raw_port = std::string())
    {
		this->server_ip = server_ip;
		this->server_raw_port = server_raw_port;
		this->local_ip = local_ip;
		this->local_raw_port = local_raw_port;
    }

	virtual void StopUout() {
		if (puout)
		{
			puout->Stop();
			puout.reset();
		}
	}

	void StartUout()
	{
		if (puout) return;

		LOG_INFO("StartUout, server_ip: [{}] server_raw_port: [{}] local_raw_port: [{}]", server_ip, server_raw_port, local_raw_port)
		puout = boost::make_shared<ClientUdpRawProxy<Protocol>>(this->pacceptor_->get_io_context(), this->protocol_, this->pacceptor_);
		auto setup_res = puout->SetUpSniffer(server_ip, server_raw_port, local_raw_port, local_ip);
		if (!setup_res)
		{
			LOG_INFO("ClientRawUdpProxy init failed, fallback to udp proxy")
			return;
		}
		puout->StartProxy();
	}


private:

	std::string server_ip;
	std::string server_raw_port;
	std::string local_ip;
	std::string local_raw_port;

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());
        boost::asio::spawn(this->GetIOContext(),[this, self](boost::asio::yield_context yield) {

            boost::asio::ip::udp::endpoint local_ep;

            while (1)
            {
                boost::system::error_code ec;

                //async recv
                // we have to reserve 4 + 2 bytes for local ip + local port info
                uint64_t bytes_read = this->pacceptor_->async_receive_from(boost::asio::buffer(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 4 + 2, UDP_LOCAL_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 10 - 4 - 2), local_ep, yield[ec]);

                if (ec || bytes_read == 0)
                {
                    LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
                    if (ec == boost::system::errc::operation_canceled) return;
                    continue;
                }

                LOG_DETAIL(UDP_DEBUG("read {} bytes udp data from local {}:{}", bytes_read, local_ep.address().to_string(), local_ep.port()))

                this->last_active_time = time(nullptr);

				if (puout)
				{
					if (puout->IsRemoteConnected())
					{
						handleLocalPacketViaRaw(local_ep, bytes_read, yield);
						continue;
					}

					if (puout->IsClosed())
						puout.reset();

					if (puout->IsDisconnect())
						puout->ReConnect();
				}
				else  // if puout == nullptr
					StartUout();
				
				// send via udp as long as puout is not connected
				memmove(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 6, bytes_read);
				this->handleLocalPacket(local_ep, bytes_read);

            }

        });
    }

    void handleLocalPacketViaRaw(boost::asio::ip::udp::endpoint& local_ep, size_t bytes_read, boost::asio::yield_context yield)
    {
        //place local ep in buff
        memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), local_ep.address().to_v4().to_bytes().data(), 4);
        auto local_port = local_ep.port();
        memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 4, &local_port, 2);

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)this->local_recv_buff_;
        //with ip + port 6 bytes totally
        protocol_hdr->PAYLOAD_LENGTH = static_cast<uint32_t>(bytes_read + 4 + 2);
        //encrypt packet
        auto bytes_tosend = this->protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

        puout->SendPacketViaRaw(this->local_recv_buff_, bytes_tosend, yield);

    }

	

	boost::shared_ptr<BasicClientUdpRawProxy<Protocol>> puout;
    
};