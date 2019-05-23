#include "../client_udp_proxy.h"
#include "client_raw_proxy_session.h"
#include "helper/firewall.h"




template<class Protocol>
class ClientRawProxy : public ClientUdpProxy<Protocol>
{

    using RAW_SESSION_MAP = boost::unordered_map<boost::asio::ip::udp::endpoint, boost::shared_ptr<ClientRawProxySession<Protocol>>, EndPointHash>;

public:


    bool InitUout(std::string server_ip, std::string server_raw_port, std::string local_uout_ip, std::string ifname)
    {
        this->server_ip = server_ip;
        this->server_raw_port = server_raw_port;

		if (local_uout_ip == "")
		{
			LOG_INFO("TO start raw proxy, you have to specify local_uout_ip")
			return false;
		}
#ifndef _WIN32
		if (ifname == "")
		{
			LOG_INFO("TO start raw proxy, you have to specify ifname")
			return false;
		}
#endif

        this->local_ip = local_uout_ip;
        this->ifname = ifname;
        Firewall::BlockRst(server_ip, server_raw_port);
		return true;
    }


    void EnableDnsViaRaw()
    {
        this->dnsviaraw = true;
    }


private:

    RAW_SESSION_MAP raw_session_map_;

    std::string server_raw_port;
    std::string local_ip;
    std::string ifname;

    bool dnsviaraw = false;

    virtual void startAcceptorCoroutine() override
    {
        auto self(this->shared_from_this());
        boost::asio::spawn(this->GetIOContext(), [this, self](boost::asio::yield_context yield) {

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

                // if send via raw failed, send it via udp
                //dmemmove(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 6, bytes_read);
                this->handlePacket(local_ep, bytes_read);

            }
        });
    }


    void handlePacket(boost::asio::ip::udp::endpoint& local_ep, size_t bytes_read)
    {
        auto socks5_packet = (socks5::UDP_RELAY_PACKET*)(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 4 + 2);
        bool isDnsPacket = Socks5ProtocolHelper::isDnsPacket(socks5_packet);

        std::string ip;
        uint16_t port;
        Socks5ProtocolHelper::parseIpPortFromSocks5UdpPacket(socks5_packet, ip, port);

        if (!dnsviaraw && isDnsPacket)
        {
            handlePacketViaUdp(local_ep, bytes_read);
            return;
        }

        handlePacketViaRaw(local_ep, bytes_read, isDnsPacket);

    }


    void handlePacketViaUdp(boost::asio::ip::udp::endpoint& local_ep, size_t bytes_read)
    {
        memmove(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 6, bytes_read);
        this->handleLocalPacket(local_ep, bytes_read);
    }


    void handlePacketViaRaw(boost::asio::ip::udp::endpoint& local_ep, size_t bytes_read, bool isdns)
    {
        //place local ep in buff
        memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size(), local_ep.address().to_v4().to_bytes().data(), 4);
        auto lp = local_ep.port();
        memcpy(this->local_recv_buff_ + Protocol::ProtocolHeader::Size() + 4, &lp, 2);


        auto protocol_hdr = (typename Protocol::ProtocolHeader*)this->local_recv_buff_;
        //with ip + port 6 bytes totally
        protocol_hdr->PAYLOAD_LENGTH = static_cast<uint32_t>(bytes_read + 4 + 2);
        //encrypt packet
        auto bytes_to_send = this->protocol_.OnUdpPayloadReadFromClientLocal(protocol_hdr);

        auto map_it = raw_session_map_.find(local_ep);

        if (map_it == raw_session_map_.end())
        {

            auto new_session = boost::make_shared<ClientRawProxySession<Protocol>>(this->GetIOContext(), this->server_ip, atoi(this->server_raw_port.c_str()), this->proxyKey_, this->pacceptor_, raw_session_map_);

            LOG_INFO("new session [{}] from {}:{}", (void*)new_session.get(), local_ep.address().to_string().c_str(), local_ep.port());

            raw_session_map_.insert(std::make_pair(local_ep, new_session));
            new_session->SaveLocalEP(local_ep);
            new_session->SetUpSniffer(this->server_ip, this->server_raw_port, this->local_ip, this->ifname);
            if (isdns) new_session->SetDnsPacket();
            new_session->Start();
            new_session->sendToRemote(this->local_recv_buff_, bytes_to_send);

        } else{
            LOG_INFO("old session from {}:{}", local_ep.address().to_string().c_str(), local_ep.port())
            map_it->second->sendToRemote(this->local_recv_buff_, bytes_to_send);
        }

    }


};
