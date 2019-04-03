#pragma once
#include "../../../utils/logger.h"
#include "../../../utils/singleton.h"
#include "../raw_socket.h"
#include <tins/tins.h>
#include <boost/thread.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <boost/asio/deadline_timer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/udp.hpp>
#include "../../../protocol/socks5_protocol_helper.h"
#include "../../../utils/ephash.h"
#include "../raw_proxy_helper/interface_helper.h"
#include "../raw_proxy_helper/firewall_helper.h"
#include "../raw_proxy_helper/tcp_checksum_helper.h"
#include "../sniffer_def.h"
#include <random>

#define MAX_HANDSHAKE_TRY 10222

/*
 * ClientUdpProxySession run in single thread mode
 * only client_udp_proxy_session will interact with this class when sending packet
 *
 * when recv packet from remote, we need to parse the dst endpoint which is encrypted together with data
 * format:
 * ip(4 bytes) + port(2 bytes) + data
 * and send it to local via raw socket
 *
 * when sending packet to remote
 */
template <class Protocol>
class BasicClientUdpRawProxy
{

public:
	~BasicClientUdpRawProxy() {
		LOG_INFO("BasicClientUdpRawProxy die")
	}

    BasicClientUdpRawProxy(boost::asio::io_context& io, Protocol& prot, boost::shared_ptr<boost::asio::ip::udp::socket> pls) : io_context_(io), protocol_(prot), plocal_socket(pls)
    {
        std::random_device rd;
        std::mt19937 eng(rd());
        std::uniform_int_distribution<unsigned int> distr;

        init_seq = distr(eng);
        this->local_seq = init_seq;
    }

    virtual bool SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_raw_port = std::string(), std::string local_ip = std::string(), std::string ifname = std::string()) = 0;

    // we use local_port as the tcp src port to connect remote
    void StartProxy()
    {
        RecvFromRemote();
        TcpHandShake();
    }

    virtual void Stop() = 0;

    bool IsRemoteConnected() { return this->status == ESTABLISHED; }
	bool IsDisconnected() { return this->status == DISCONNECT; }

    void TryConnect()
    {
        if (handshake_failed)
            TcpHandShake();
        return;
    }

    void SendPacketViaRaw(void* data, uint32_t size, boost::asio::yield_context& yield)
    {
        using Tins::TCP;
        using Tins::IP;
        auto ip = IP(remote_ip, local_ip);
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::PSH | TCP::ACK);
        tcp.seq(local_seq);
        tcp.ack_seq(last_ack);

        auto payload = Tins::RawPDU((uint8_t*)data, size);

        tcp = tcp / payload;

        LOG_INFO("send {} bytes PSH | ACK seq: {}, ack: {}", size, tcp.seq(), tcp.ack_seq())

		constructAndSend(ip, tcp, yield);

        local_seq += (tcp.size() - tcp.header_size());
    }

protected:

    enum SESSION_STATUS
    {
        SYN_SENT,
        ESTABLISHED,
        DISCONNECT
    };

    Protocol& protocol_;

    boost::asio::io_context& io_context_;

	boost::shared_ptr<boost::asio::ip::udp::socket> plocal_socket;

    SESSION_STATUS status;

    std::string remote_ip;
    std::string local_ip;

    unsigned short local_port;
    unsigned short remote_port;

    unsigned int local_seq;
    unsigned int init_seq;

    unsigned int last_ack = 0;

    bool handshake_failed = false;

    virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code& ec) = 0;

    void RecvFromRemote()
    {
        //recv
        boost::asio::spawn(this->io_context_, [this](boost::asio::yield_context yield){

            using Tins::TCP;
            while(1)
            {

				boost::system::error_code ec;

                std::unique_ptr<Tins::PDU> pdu_ptr = recvFromRemote(yield, ec);

				if (ec)
				{
					LOG_INFO("recvFromRemote err --> {}", ec.message())
					return;
				}

                auto tcp = pdu_ptr->find_pdu<TCP>();
                if (tcp == nullptr)
                {
                    LOG_INFO("TCP Header not found")
                    continue;
                }

                switch (tcp->flags())
                {
                    case TCP::SYN :
                    {
                        LOG_INFO("SYN")
						this->ackReply(tcp, yield);
						continue;
                    }
                    case (TCP::SYN | TCP::ACK):
                    {
                        LOG_INFO("recv SYN | ACK seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                        this->handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
                        continue;
                    }
                    // without data
                    case TCP::ACK :
                    {
                        LOG_INFO("recv ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                        continue;
                    }
                    // with data
                    case (TCP::PSH | TCP::ACK) :
                    {
                        LOG_INFO("recv PSH | ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                        this->ackReply(tcp, yield);
                        this->sendToLocal(tcp->inner_pdu());
						continue;
                    }
                    case TCP::RST :
                    {
						LOG_INFO("recv RST")
						this->Stop();
						this->status = DISCONNECT;
						return;
                    }
                    default:
                    {
                        LOG_INFO("default")
                        continue;
                    }
                }
            }

        });
    }


    void TcpHandShake()
    {
        LOG_INFO("TcpHandShake Start")
        this->handshake_failed = false;
        static size_t handshake_count = 0;
        using Tins::TCP;
        using Tins::IP;

        //start up
        boost::asio::spawn(this->io_context_, [this](boost::asio::yield_context yield){

            boost::asio::deadline_timer timer(this->io_context_);
            boost::system::error_code ec;

            while(this->status != this->ESTABLISHED && handshake_count++ < MAX_HANDSHAKE_TRY)
            {

                auto ip = IP(this->remote_ip.c_str(), this->local_ip.c_str());
				auto tcp = TCP(this->remote_port, this->local_port);
                tcp.flags(TCP::SYN);
                tcp.seq(this->init_seq);

                LOG_INFO("send SYN seq: {}, ack: {}", tcp.seq(), tcp.ack_seq())

                // we send tcp only, ip hdr is for checksum cal only
                auto bytes_send = constructAndSend(ip, tcp, yield);

                if (bytes_send == 0)
                {
                    break;
                }

                timer.expires_from_now(boost::posix_time::seconds(2));
                timer.async_wait(yield[ec]);
                if (ec)
                {
                    LOG_INFO("timer async_wait err")
                    return;
                }
            }

			if (this->status != this->ESTABLISHED) {
				LOG_INFO("Raw Tcp handshake failed")
				this->handshake_failed = true;
				this->status = DISCONNECT;
			}
        });

    }

    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield) = 0;

    void sendToLocal(Tins::PDU* raw_data)
    {

        std::unique_ptr<unsigned char[]> data_copy(new unsigned char[raw_data->size()]);
        memcpy(data_copy.get(), raw_data->serialize().data(), raw_data->size());
        boost::asio::spawn( [this, data_copy {std::move(data_copy)}] (boost::asio::yield_context yield){

            // decrypt data
            auto protocol_hdr = (typename Protocol::ProtocolHeader*)data_copy.get();

            // decrypt packet and get payload length
            // n bytes protocol header + 6 bytes src ip port + 10 bytes socks5 header + payload
            auto bytes_read = protocol_.OnUdpPayloadReadFromClientRemote(protocol_hdr);

            uint32_t src_ip;
            uint16_t src_port;
            memcpy(&src_ip, &data_copy[Protocol::ProtocolHeader::Size()], 4);
            memcpy(&src_port, &data_copy[Protocol::ProtocolHeader::Size() + 4], 2);

			in_addr addr;
			memcpy(&addr, &src_ip, 4);
            boost::asio::ip::udp::endpoint local_ep(boost::asio::ip::address::from_string(inet_ntoa(addr)), src_port);

            boost::system::error_code ec;

            LOG_INFO("send udp back to local {}:{}", local_ep.address().to_string(), local_ep.port())

			auto bytes_send = this->plocal_socket->async_send_to(boost::asio::buffer(data_copy.get() + Protocol::ProtocolHeader::Size() + 6, bytes_read - 6), local_ep, yield[ec]);

			if (ec)
			{
				LOG_INFO("async_send_to err --> {}", ec.message().c_str())
				return;
			}

			LOG_INFO("send {} bytes via raw socket", bytes_send)

        });

    }

    void handshakeReply(uint32_t remote_seq, uint32_t remote_ack, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        using Tins::IP;

        auto ip = IP(remote_ip, local_ip);
        auto tcp = TCP(remote_port, local_port);
        tcp.flags(TCP::ACK);
        tcp.ack_seq(remote_seq + 1);
        tcp.seq(++local_seq);
        LOG_INFO("send handshake ACK back, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

		constructAndSend(ip, tcp, yield);

        this->status = ESTABLISHED;

        this->local_seq = init_seq + 1;
        this->last_ack = remote_seq;
    }

    void ackReply(Tins::TCP* remote_tcp, boost::asio::yield_context yield)
    {
        using Tins::TCP;
        using Tins::IP;
        this->last_ack = remote_tcp->seq() + remote_tcp->inner_pdu()->size();

        auto ip = IP(remote_ip, local_ip);
        auto tcp = TCP(remote_tcp->sport(), remote_tcp->dport());
        tcp.flags(TCP::ACK);

        tcp.ack_seq(remote_tcp->seq() + remote_tcp->size() - remote_tcp->header_size());
        tcp.seq(local_seq);
        LOG_INFO("ACK Reply, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

		constructAndSend(ip, tcp, yield);
    }

	void rstReply(Tins::TCP* remote_tcp, boost::asio::yield_context yield)
	{
		using Tins::TCP;
		using Tins::IP;
		this->last_ack = remote_tcp->seq() + remote_tcp->inner_pdu()->size();

		auto ip = IP(remote_ip, local_ip);
		auto tcp = TCP(remote_tcp->sport(), remote_tcp->dport());
		tcp.flags(TCP::RST);

		tcp.ack_seq(remote_tcp->seq() + remote_tcp->size() - remote_tcp->header_size());
		tcp.seq(local_seq);
		LOG_INFO("RST Reply, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

		constructAndSend(ip, tcp, yield);
	}

	size_t constructAndSend(Tins::IP& ip, Tins::TCP& tcp, boost::asio::yield_context& yield)
	{
		ip = ip / tcp;
		auto vip_data = ip.serialize();
		auto ip_data = vip_data.data();
#ifdef _WIN32
		return sendPacket(ip_data, ip.size(), yield);
#else
		CalTcpChecksum(ip, ip_data);
		return sendPacket(ip_data + ip.header_size(), tcp.size(), yield);
#endif
	}
};