#include "client_udp_proxy.h"
#include "../../raw/client/client_udp_raw_proxy.h"

template<class Protocol>
class ClientUdpProxyWithRaw : public ClientUdpProxy<Protocol>
{


public:

    void InitUdp2Raw()
    {
        pudp2raw = ClientUdpRawProxy::GetInstance(this->pacceptor_->get_io_context());
        pudp2raw->SetUpSniffer("ens33", "192.168.1.214", "4567");
        pudp2raw->StartProxy(4444);
    }


private:

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());
        boost::asio::spawn(this->GetIOContext(),[this, self](boost::asio::yield_context yield) {

            boost::asio::ip::udp::endpoint local_ep_;

            while (1)
            {
                boost::system::error_code ec;

                //async recv
                // we have to reserve 4 + 2 bytes for local ip + local port info
                uint64_t bytes_read = this->pacceptor_->async_receive_from(boost::asio::buffer(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 4 + 2, UDP_LOCAL_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size() - 10 - 4 - 2), local_ep_, yield[ec]);

                if (ec || bytes_read == 0)
                {
                    LOG_INFO("UDP async_receive_from local err --> {}", ec.message().c_str())
                    if (ec == boost::system::errc::operation_canceled) return;
                    continue;
                }

                LOG_DETAIL(UDP_DEBUG("read {} bytes udp data from local ", bytes_read))

                this->last_active_time = time(nullptr);

                //place local ep in buff
                memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), local_ep_.address().to_v4().to_bytes().data(), 4);
                auto local_port = local_ep_.port();
                memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 2, &local_port, 2);

                auto protocol_hdr = (typename Protocol::ProtocolHeader*)this->local_recv_buff_;
                //with ip + port 6 bytes totally
                protocol_hdr->PAYLOAD_LENGTH = bytes_read + 4 + 2;
                //encrypt packet
                auto bytes_tosend = this->protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

                //if (!Socks5ProtocolHelper::IsUdpSocks5PacketValid(new_session->GetLocalBuffer())) continue;
                pudp2raw->SendPacketViaRaw(this->local_recv_buff_, bytes_tosend, yield);

            }


        });
    }

    ClientUdpRawProxy* pudp2raw;
};