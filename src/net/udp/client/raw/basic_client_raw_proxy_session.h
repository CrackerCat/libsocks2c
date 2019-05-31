#pragma once
#include "../../../../utils/logger.h"
#include "../../../../utils/singleton.h"
#include "raw_socket.h"
#include <tins/tins.h>
#include <boost/thread.hpp>
#include <boost/asio/spawn.hpp>
#include <memory>
#include <boost/asio/deadline_timer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/udp.hpp>
#include "../../../../protocol/socks5/socks5_protocol_helper.h"
#include "../../../../utils/ephash.h"
#include "helper/tcp_checksum.h"
#include "sniffer_def.h"
#include <random>
#include "../../bufferqueue.h"

// maximum try for resending syn
#define MAX_HANDSHAKE_TRY 5
// IF we send 10 packet out and didn't get any ack, then we close the connection
const int RAW_SESSION_TIMEOUT = 23;
const int RAW_SESSION_TIMEOUT_DNS = 2;
/*
 * BasicClientRawProxySession run in single thread mode
 *
 * when recv packet from remote, we need to parse the dst endpoint which is encrypted together with data
 * format:
 * ip(4 bytes) + port(2 bytes) + data
 * and send it to local via raw socket
 *
 * when sending packet to remote
 */
template <class Protocol>
class BasicClientRawProxySession : public boost::enable_shared_from_this<BasicClientRawProxySession<Protocol>>
{

public:

    BasicClientRawProxySession(boost::asio::io_context& io, boost::shared_ptr<boost::asio::ip::udp::socket> local_socket) : io_context_(io), plocal_socket(local_socket), timer_(io)
    {
        initRandomTCPSeq();
        last_update_time = time(nullptr);
    }

    virtual ~BasicClientRawProxySession() {
        LOG_DEBUG("BasicClientRawProxy die")
    }

    // set up sniffer(pcap)
    // server endpoint must be provided, whereas local endpoint can be chosen automatically
    virtual bool SetUpSniffer(std::string remote_ip, std::string remote_port, std::string local_ip, std::string ifname) = 0;


    // start 2 coroutine here
    void Start()
    {
        readFromRemote();
        tcpHandShake();

        timer_.expires_from_now(boost::posix_time::seconds(RAW_SESSION_TIMEOUT));
        timer_.async_wait(boost::bind(&BasicClientRawProxySession<Protocol>::onTimesup, this->shared_from_this(), boost::asio::placeholders::error));

    }

    // after Stop() status will set to CLOSED
    virtual void Stop() = 0;

    void SetDnsPacket()
    {
        this->session_timeout = RAW_SESSION_TIMEOUT_DNS;
    }

    void sendToRemote(void* data, uint32_t size)
    {

        if (this->status != this->INIT && this->status != this->ESTABLISHED)
        {
            LOG_INFO("status at {} no INIT or EST", this->status)
            return;
        }

        auto remote_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(this->remote_ip), this->remote_port);
        auto res = bufferqueue_.Enqueue(size, data, remote_ep);

        // queue is full if res == nullptr, we have to discard data
        if (!res) return;

        if (this->status != this->ESTABLISHED) return;

        startSendCoroutine();
    }


    void startSendCoroutine()
    {
        // return if there's another coroutine running
        // Enqueue is thread safe cause we are in the same context
        if (this->remote_sending)
        {
            LOG_INFO("remote sending, return")
            return;
        }
        LOG_DEBUG("startSendCoroutine")

        auto self(this->shared_from_this());
        boost::asio::spawn(this->io_context_, [self, this](boost::asio::yield_context yield){

            using Tins::TCP;
            using Tins::IP;

            while (!bufferqueue_.Empty())
            {

                auto bufferinfo = bufferqueue_.GetFront();

                auto ip = IP(this->remote_ip, this->local_ip);
                auto tcp = TCP(this->remote_port, this->local_port);
                tcp.flags(TCP::PSH | TCP::ACK);
                tcp.seq(this->local_seq);
                tcp.ack_seq(this->last_ack);

                auto payload = Tins::RawPDU((uint8_t*)bufferinfo->GetPayload(), bufferinfo->size_);

                tcp = tcp / payload;

                LOG_DEBUG("send {} bytes PSH | ACK seq: {}, ack: {}", bufferinfo->size_, tcp.seq(), tcp.ack_seq())

                auto bytes_send = this->constructAndSend(ip, tcp, yield);

                if (bytes_send == 0)
                {
                    LOG_INFO("constructAndSend ERR set closed")
                    this->status = CLOSED;
                    return;
                }

                bufferqueue_.Dequeue();

                this->local_seq += (tcp.size() - tcp.header_size());

            }
            LOG_DEBUG("send finished")

            this->remote_sending = false;

        });
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

        last_update_time = time(nullptr);

    }


    void SaveLocalEP(boost::asio::ip::udp::endpoint lp)
    {
        local_ep_ = lp;
    }

    virtual void onTimesup(const boost::system::error_code &ec) = 0;

protected:

    enum SESSION_STATUS
    {
        INIT,
        ESTABLISHED,
        DISCONNECT,
        CLOSED
    };

    Protocol protocol_;

    boost::asio::io_context& io_context_;

    SESSION_STATUS status = INIT;

    std::string remote_ip;
    std::string local_ip;

    unsigned short local_port;
    unsigned short remote_port;

    boost::asio::deadline_timer timer_;
    time_t last_update_time = 0;
    int session_timeout = RAW_SESSION_TIMEOUT;

    boost::asio::ip::udp::endpoint local_ep_;

private:
    // flag for distinguishing whether another handshake process is running
    bool handshaking = false;

    unsigned int last_ack = 0;

    unsigned int local_seq;
    unsigned int init_seq;

    // udp socket use to send data back to local
    boost::shared_ptr<boost::asio::ip::udp::socket> plocal_socket;

    BufferQueue bufferqueue_;
    bool remote_sending = false;

    // platform specific impl
    virtual std::unique_ptr<Tins::PDU> recvFromRemote(boost::asio::yield_context yield, boost::system::error_code& ec) = 0;

    void readFromRemote()
    {
		auto self(this->shared_from_this());
        boost::asio::spawn(this->io_context_, [self, this](boost::asio::yield_context yield){

            using Tins::TCP;
            while(1)
            {

                if (this->status == this->CLOSED)
                    return;

                boost::system::error_code ec;

                std::unique_ptr<Tins::PDU> pdu_ptr = recvFromRemote(yield, ec);

                if (ec)
                {
                    LOG_DEBUG("recvFromRemote err --> {}", ec.message())
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
                        LOG_INFO("Recv SYN, send RST back")
                        this->rstReply(tcp, yield);
                        continue;
                    }
                    case (TCP::SYN | TCP::ACK):
                    {
                        LOG_DEBUG("recv SYN | ACK seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                        this->handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
                        continue;
                    }
                        // without data
                    case TCP::ACK :
                    {
                        LOG_DEBUG("recv ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())

                        if (this->status != ESTABLISHED) continue;
                        if (tcp->inner_pdu() == nullptr) continue;

                        this->sendToLocal(tcp->inner_pdu());
                        continue;
                    }
                        // with data
                    case (TCP::PSH | TCP::ACK) :
                    {
                        LOG_DEBUG("recv PSH | ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                        //only reply when ESTABLISHED
                        if (this->status != ESTABLISHED) continue;
                        if (tcp->inner_pdu() == nullptr) continue;

                        this->ackReply(tcp, yield);
                        this->sendToLocal(tcp->inner_pdu());
                        continue;
                    }
                    case TCP::RST :
                    {
                        LOG_INFO("recv RST, closing")
                        this->Stop();
                        this->status = CLOSED;
                        return;
                    }
                        //case TCP::FIN:
                        //{
                        //    LOG_INFO("recv FIN, ignore")
                        //    continue;
                        //}
                    default:
                    {
                        //LOG_INFO("default")
                        continue;
                    }
                }
            }

        });
    }

    void tcpHandShake()
    {
        if (this->handshaking == true) return;
        LOG_DEBUG("[{}] tcpHandShake Start", (void*)this)
        this->handshaking = true;
        using Tins::TCP;
        using Tins::IP;

        auto self(this->shared_from_this());
        boost::asio::spawn(this->io_context_, [self, this](boost::asio::yield_context yield){

            boost::asio::deadline_timer timer(this->io_context_);
            boost::system::error_code ec;
            size_t handshake_count = 0;

            while(this->status == INIT && handshake_count < MAX_HANDSHAKE_TRY)
            {
                //LOG_INFO("remote {}:{}, local {}:{}",this->remote_ip.c_str(), this->remote_port,this->local_ip.c_str(), this->local_port)
                auto ip = IP(this->remote_ip, this->local_ip);
                auto tcp = TCP(this->remote_port, this->local_port);
                tcp.flags(TCP::SYN);
                tcp.seq(this->init_seq);

                LOG_DEBUG("[{}] send SYN seq: {}, ack: {}", (void*)this, tcp.seq(), tcp.ack_seq())

                // we send tcp only, ip hdr is for checksum cal only
                auto bytes_send = constructAndSend(ip, tcp, yield);

                if (bytes_send == 0)
                {
                    break;
                }

                timer.expires_from_now(boost::posix_time::milliseconds(1000));
                timer.async_wait(yield[ec]);
                if (ec)
                {
                    LOG_INFO("timer async_wait err")
                    return;
                }
                handshake_count++;
            }

            // if handshake failed, we set status to CLOSED
            if (this->status != ESTABLISHED)
            {
                LOG_DEBUG("handshake failed, closed")
                this->Stop();
            }
        });

    }


    void sendToLocal(Tins::PDU* raw_data)
    {
        LOG_DEBUG("send {} to local", raw_data->size())
        std::unique_ptr<unsigned char[]> data_copy(new unsigned char[raw_data->size()]);
        memcpy(data_copy.get(), raw_data->serialize().data(), raw_data->size());
		auto self(this->shared_from_this());
		boost::asio::spawn(this->io_context_, [self, this, data_copy {std::move(data_copy)}] (boost::asio::yield_context yield){

            // decrypt data
            auto protocol_hdr = (typename Protocol::ProtocolHeader*)data_copy.get();

            // decrypt packet and get payload length
            // n bytes protocol header + 6 bytes src ip port + 10 bytes socks5 header + payload
            auto bytes_read = protocol_.OnUdpPayloadReadFromClientRemote(protocol_hdr);

            if (bytes_read == 0) {
                LOG_INFO("decrypt err");
                return;
            }

            uint32_t src_ip;
            uint16_t src_port;
            memcpy(&src_ip, &data_copy[Protocol::ProtocolHeader::Size()], 4);
            memcpy(&src_port, &data_copy[Protocol::ProtocolHeader::Size() + 4], 2);

		    in_addr addr;
		    memcpy(&addr, &src_ip, 4);
			
            LOG_DEBUG("setting original src_ep {}:{}", inet_ntoa(addr), src_port)

            boost::asio::ip::udp::endpoint local_ep(boost::asio::ip::address::from_string(inet_ntoa(addr)), src_port);

            boost::system::error_code ec;

            LOG_DEBUG("send {} bytes udp back to local {}:{}", bytes_read, local_ep.address().to_string(), local_ep.port())

            auto bytes_send = this->plocal_socket->async_send_to(boost::asio::buffer(data_copy.get() + Protocol::ProtocolHeader::Size() + 6, bytes_read - 6), local_ep, yield[ec]);

            if (ec)
            {
                LOG_INFO("async_send_to err --> {}", ec.message().c_str())
                return;
            }

            last_update_time = time(nullptr);

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
        LOG_DEBUG("send handshake ACK back, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

        constructAndSend(ip, tcp, yield);

        this->local_seq = init_seq + 1;
        this->last_ack = remote_seq + 1;

		LOG_DEBUG("[{}] raw ESTABLISHED", (void*)this)
        this->status = ESTABLISHED;

        startSendCoroutine();
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
        LOG_DEBUG("ACK Reply, seq: {}, ack: {}", tcp.seq(), tcp.ack_seq());

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

    // platform specific impl
    // on unix like os, data should be TCP hdr
    // on win32, data should be IP hdr
    // return the bytes that actually send
    // return 0 if err
    virtual size_t sendPacket(void* data, size_t size, boost::asio::yield_context& yield) = 0;

    // return the bytes that actually send
    // return 0 if err
    size_t constructAndSend(Tins::IP& ip, Tins::TCP& tcp, boost::asio::yield_context& yield)
    {
        ip = ip / tcp;
        auto vip_data = ip.serialize();
        auto ip_data = vip_data.data();
#ifdef _WIN32 // we don't need to cal tcp checksum on win32
        return sendPacket(ip_data, ip.size(), yield);
#else
        CalTcpChecksum(ip, ip_data);
        return sendPacket(ip_data + ip.header_size(), tcp.size(), yield);
#endif
    }

    inline void initRandomTCPSeq() noexcept
    {
        static std::random_device rd;
        std::mt19937 eng(rd());
        std::uniform_int_distribution<unsigned int> distr;

        init_seq = distr(eng);
        this->local_seq = init_seq;
    }

};