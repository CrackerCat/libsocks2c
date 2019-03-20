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

    void InitUdp2Raw(std::string local_ip, std::string server_ip, std::string server_raw_port, std::string local_raw_port)
    {
        LOG_INFO("ClientRawUdpProxy started, server_ip: [{}] server_raw_port: [{}] local_raw_port: [{}]", server_ip, server_raw_port, local_raw_port)
        pudp2raw = ClientUdpRawProxy<Protocol>::GetInstance(this->pacceptor_->get_io_context(), this->protocol_, this->pacceptor_);
        pudp2raw->SetUpSniffer(server_ip, server_raw_port, local_raw_port, local_ip);
        pudp2raw->StartProxy(local_raw_port);
    }


private:

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

                // send via raw if raw tcp connected
                if (pudp2raw->IsRemoteConnected())
                {
                    handleLocalPacketViaRaw(local_ep, bytes_read, yield);
                } else // or fallback to udp
                {
                    this->handleLocalPacket(local_ep, bytes_read);
                    pudp2raw->TryConnect();
                }

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
        protocol_hdr->PAYLOAD_LENGTH = bytes_read + 4 + 2;
        //encrypt packet
        auto bytes_tosend = this->protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

        pudp2raw->SendPacketViaRaw(this->local_recv_buff_, bytes_tosend, yield);

    }



    BasicClientUdpRawProxy<Protocol>* pudp2raw;
};