#pragma once

#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include "../../../utils/logger.h"
#include "../../../protocol/socks5/socks5_protocol.h"
#include "../../../protocol/socks5/socks5_protocol_helper.h"

#include "../../../protocol/iproxy_protocol.h"
#include "../../../utils/randomNumberGenerator.h"
#include "../../../utils/trafficcounter.h"

#include "../../bufferdef.h"

#define DestorySession { onDestruction(yield); return; }

template<class Protocol>
class ClientTcpProxySession : public boost::enable_shared_from_this<ClientTcpProxySession<Protocol>>{

    using IO_CONTEXT = boost::asio::io_context;
    using TCP_SOCKET = boost::asio::ip::tcp::socket;

    using DNS_RESOLVER = boost::asio::ip::tcp::resolver;
    using PDNS_RESOLVER = std::unique_ptr<DNS_RESOLVER>;

public:

    ClientTcpProxySession(IO_CONTEXT &io_context, std::string server_ip, uint16_t server_port, unsigned char key[32U], bool resolve_dns_locally) \
            : protocol_(nullptr), local_socket_(io_context), remote_socket_(io_context)
    {
        this->protocol_.SetKey(key);

        remote_ep_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(server_ip),server_port);

        if (resolve_dns_locally)
        {
            this->pdns_resolver_ = std::make_unique<DNS_RESOLVER >(io_context);
        }

	}

    ~ClientTcpProxySession()
    {
        LOG_DETAIL(TCP_DEBUG("[{:p}] tcp session die", (void*)this))
    }

    void Start()
    {
        if (!setNoDelay()) return;

        auto self(this->shared_from_this());
        boost::asio::spawn(this->local_socket_.get_executor(),[this, self](boost::asio::yield_context yield){


            if (!handleMethodSelection(yield)) DestorySession
            if (!handleSocks5Request(yield)) DestorySession
            if (!handleTunnelFlow(yield)) DestorySession

        });

    }

    TCP_SOCKET& GetLocalSocketRef()
    {
        return local_socket_;
    }



private:

    Protocol protocol_;

    unsigned char local_recv_buff_[TCP_LOCAL_RECV_BUFF_SIZE];
    unsigned char remote_recv_buff_[TCP_REMOTE_RECV_BUFF_SIZE];

    //  When a socket is destroyed, it will be closed as-if by socket.close(ec) during the destruction of the socket.
    TCP_SOCKET local_socket_;
    TCP_SOCKET remote_socket_;

    boost::asio::ip::tcp::endpoint remote_ep_;

    PDNS_RESOLVER pdns_resolver_;

    bool setNoDelay()
    {
        boost::system::error_code ec;
        this->local_socket_.set_option(boost::asio::ip::tcp::no_delay(true),ec);
        if (ec)
        {
            TCP_DEBUG("[{:p}] setNoDelay err", (void*)this)
            return false;
        }
        return true;
    }



    bool handleMethodSelection(boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;
        uint64_t bytes_read = this->local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, 3), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleMethodSelection read err --> {}", (void*)this, ec.message().c_str())
            return false;
        }

        uint64_t bytes_write = async_write(this->local_socket_, boost::asio::buffer(socks5::DEFAULT_METHOD_REPLY, 2), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleMethodSelection write err --> {}", (void*)this, ec.message().c_str())
            return false;
        }


        return true;

    }


    void udpReply(boost::asio::yield_context& yield){


        auto self(this->shared_from_this());
        async_write(this->local_socket_,
                    boost::asio::buffer(socks5::DEFAULT_UDP_REQ_REPLY,
                                        sizeof(socks5::DEFAULT_UDP_REQ_REPLY)),
                    [this, self](const boost::system::error_code &ec, const size_t &bytes_send){
                        if (ec)
                        {
                            TCP_DEBUG("[{:p}] udpReply err --> {}", (void*)this, ec.message().c_str())
                            return;
                        }

                    });

        boost::system::error_code ec;

        this->local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_, TCP_LOCAL_RECV_BUFF_SIZE), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] tcp link of socks5 udp proxy disconnect --> {}", (void*)this, ec.message().c_str())
            return;
        }


    }

    void bindReply(){

    }

    inline bool isConnectRequest(socks5::SOCKS_REQ* request)
    {
        if (request->CMD == socks5::SOCKS5_CMD_TYPE::CONNECT) return true;
        return false;
    }

    inline bool isUdpRequest(socks5::SOCKS_REQ* request)
    {
        if (request->CMD == socks5::SOCKS5_CMD_TYPE::UDP_ASSOCIATE) return true;
        return false;
    }

    /*
     *  After this handle, session should be in tunnel status
     *  if there's a domain proxy request, resolve locally or remotely
     */
    bool handleSocks5Request(boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;

        /*
         *  Read socks5 request, reserve Protocol::ProtocolHeader::Size() bytes for proxy protocol
         */
        uint64_t bytes_read = this->local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), TCP_LOCAL_RECV_BUFF_SIZE), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleSocks5Request read err --> {}", (void*)this, ec.message().c_str())
            return false;
        }


        /*
         *  Check if packet is valid
         */
        auto socks5_req_header = (socks5::SOCKS_REQ*)(local_recv_buff_ + Protocol::ProtocolHeader::Size());
		//socks5_req_header->RSV != 0x00
        if (socks5_req_header->VER != 0x05)
        {
            TCP_DEBUG("[{:p}] VER or RSV field of handleSocks5Request err, drop connection", (void*)this)
            return false;
        }


        if (!isConnectRequest(socks5_req_header))
        {
            if (isUdpRequest(socks5_req_header))
            {
                udpReply(yield);
                return false;
            }
            TCP_DEBUG("[{:p}] unknow CMD, drop connection", (void*)this)
            return false;
        }


        /*
         *  If packet is valid, send socks5 reply back
         */
        uint64_t bytes_write = async_write(this->local_socket_, boost::asio::buffer(socks5::DEFAULT_SOCKS_REPLY, 10), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleSocks5Request async_write DEFAULT_METHOD_REPLY to local err --> {}", (void*)this, ec.message().c_str())
            return false;
        }

		if (!openRemoteSocket()) return false;

        if (!connectToRemote(yield)) return false;


        auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;

        /*
         *  The DATA_LENGTH setting here may not be the len sending to remote
         *
         *  it's the protocol (see below) that decides how many bytes should be send, but we could assume that at least bytes_read + Protocol::ProtocolHeader::Size() will be send
         */
        protocol_hdr->PAYLOAD_LENGTH = bytes_read;


        if (socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::IPV4 || socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::IPV6)
        {

            /*
             *
             *  Forward Socks5 request to remote.
             *
             *      -- Remote will disconnect if failed.
             *      -- Remote send no reply back if successful
             *
             */
            if (!sendToRemote(bytes_read, PayloadType::SOCKS5_DATA, yield))
            {
                TCP_DEBUG("[{:p}] handleSocks5Request async_write socks5 request to server err --> {}", (void*)this, ec.message().c_str())
                return false;
            }

            std::string ip_str;
            uint16_t port;

            if (!Socks5ProtocolHelper::parseIpPortFromSocks5Request(socks5_req_header, ip_str, port))
            {
                TCP_DEBUG("[{:p}] parseDomainPortFromSocks5Request err ", (void*)this)
                return false;
            }

            TCP_LOG_INFO("proxy {}:{}", ip_str, port)

            return true;

        }
        else if (socks5_req_header->ATYP == socks5::SOCKS5_ATYP_TYPE::DOMAINNAME)
        {

            std::string domain_str;
            uint16_t port;

            if (!Socks5ProtocolHelper::parseDomainPortFromSocks5Request(socks5_req_header, domain_str, port))
            {
                TCP_DEBUG("[{:p}] parseDomainPortFromSocks5Request err ", (void*)this)
                return false;
            }

            TCP_LOG_INFO("proxy {}:{}", domain_str, port)

            if(pdns_resolver_)
            {

                boost::system::error_code ec;
                boost::asio::ip::tcp::resolver::query query{domain_str,std::to_string(port),boost::asio::ip::resolver_query_base::all_matching};

                TCP_DEBUG("[{:p}] resolving {}:{}", (void*)this, domain_str.c_str(), port)
                auto dns_result = pdns_resolver_->async_resolve(query, yield[ec]);

                if (ec)
                {
                    TCP_DEBUG("[{:p}] async_resolve err --> {}", (void*)this, ec.message().c_str())
                    return false;
                }

                TCP_DEBUG("[{:p}] Dns Resolved: {}:{}", (void*)this, dns_result->endpoint().address().to_string().c_str(), dns_result->endpoint().port());

                // once the ip is resolved, construct socks5 packet with ATYP == ipv4 and send to remote

                Socks5ProtocolHelper::ConstructSocks5RequestFromIpStringAndPort(protocol_hdr->GetDataOffsetPtr(), dns_result->endpoint().address().to_string(), dns_result->endpoint().port());
                if (!sendToRemote(bytes_read,PayloadType::SOCKS5_DATA,yield))
                {
                    TCP_DEBUG("[{:p}] handleSocks5Request async_write socks5 request to server err --> {}", (void*)this, ec.message().c_str())
                    return false;
                }

                return true;

            }else
            {
                uint64_t bytes_write = async_write(this->remote_socket_, boost::asio::buffer(local_recv_buff_, protocol_.OnSocks5RequestSent(protocol_hdr)), yield[ec]);

                if (ec)
                {
                    TCP_DEBUG("[{:p}] handleSocks5Request async_write socks5 request to server err (remote resolve dns)--> {}", (void*)this, ec.message().c_str())
                    return false;
                }

                return true;
            }

        }
        else
        {
            TCP_DEBUG("[{:p}] unknow ATYP", (void*)this)
            return false;
        }


    }


    bool openRemoteSocket()
    {
		boost::system::error_code ec;

		remote_socket_.open(remote_ep_.protocol(), ec);

		if (ec)
		{
			LOG_ERROR("err when opening remote_socket_ --> {}", ec.message().c_str())
			return false;
		}

		boost::asio::ip::tcp::acceptor::reuse_address reuse_address(true);
		boost::asio::ip::tcp::no_delay no_delay(true);

		remote_socket_.set_option(reuse_address, ec);

		if (ec)
		{
			LOG_ERROR("err reuse_address remote_socket_ --> {}", ec.message().c_str())
			return false;
		}

		remote_socket_.set_option(no_delay, ec);

		if (ec)
		{
			LOG_ERROR("err set_option remote_socket_ --> {}", ec.message().c_str())
			return false;
		}

		return true;
    }


    bool handleTunnelFlow(boost::asio::yield_context& yield)
    {


        auto self(this->shared_from_this());
        boost::asio::spawn(this->local_socket_.get_executor(),[this, self](boost::asio::yield_context yield){

            boost::system::error_code ec;

            while (1)
            {
                auto bytes_read = readFromRemote(yield);
                if (bytes_read == 0)
                {
                    this->local_socket_.cancel(ec);
                    return;
                }

                if (!sendToLocal(bytes_read, yield))
                {
                    this->remote_socket_.cancel(ec);
                    return;
                }
            }

        });


        boost::system::error_code ec;

        // Upstream Coroutine
        while (1)
        {
            auto bytes_read = readFromLocal(yield);
            if (bytes_read == 0)
            {
                this->remote_socket_.cancel(ec);
                return false;
            }
            if (!sendToRemote(bytes_read, PayloadType::APPLICATION_DATA, yield))
            {
                this->local_socket_.cancel(ec);
                return false;
            }
        }



    }

    uint64_t readFromRemote(boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;

        /*
         *  Read header first, then read the full content
         */
        uint64_t bytes_read = boost::asio::async_read(this->remote_socket_, boost::asio::buffer(remote_recv_buff_, Protocol::ProtocolHeader::Size()), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleTunnelFlow readHeaderFromRemote  err --> {}", (void*)this, ec.message().c_str())
            return 0;
        }

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)remote_recv_buff_;
        auto data_len = protocol_.OnPayloadHeaderReadFromRemote(protocol_hdr);
        if (data_len == -1) return 0;


        // Read the full content
        bytes_read = boost::asio::async_read(this->remote_socket_, boost::asio::buffer(remote_recv_buff_ +  Protocol::ProtocolHeader::Size(), data_len), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleTunnelFlow readFromRemote err --> {}", (void*)this, ec.message().c_str())
            return 0;
        }

        if (!protocol_.OnPayloadReadFromRemote(protocol_hdr)) return 0;
        LOG_DETAIL(TCP_DEBUG("[{:p}] read {} bytes from remote", (void*)this, bytes_read))

        return protocol_hdr->PAYLOAD_LENGTH;
    }


    bool sendToLocal(uint64_t bytes, boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;

        // Read Header Decode Length
        uint64_t bytes_write = async_write(this->local_socket_, boost::asio::buffer(remote_recv_buff_ + Protocol::ProtocolHeader::Size(), bytes), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] sendToLocal err --> {}", (void*)this, ec.message().c_str())
            return false;
        }
		LOG_DETAIL(TCP_DEBUG("[{:p}] send {} bytes to Local", (void*)this, bytes_write))
		AddDownTraffic(bytes_write)
        return true;
    }


    uint64_t readFromLocal(boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;

        // Read Header Decode Length
        uint64_t bytes_read = this->local_socket_.async_read_some(boost::asio::buffer(local_recv_buff_ + Protocol::ProtocolHeader::Size(), TCP_LOCAL_RECV_BUFF_SIZE - Protocol::ProtocolHeader::Size()), yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{:p}] handleTunnelFlow readFromLocal err --> {}", (void*)this, ec.message().c_str())
            return 0;
        }
		LOG_DETAIL(TCP_DEBUG("[{:p}] read {} bytes from local", (void*)this, bytes_read))

        return bytes_read;
    }

    enum PayloadType
    {
        SOCKS5_DATA,
        APPLICATION_DATA
    };

    bool sendToRemote(uint64_t bytes, PayloadType payload_type, boost::asio::yield_context& yield)
    {

        boost::system::error_code ec;

        auto protocol_hdr = (typename Protocol::ProtocolHeader*)local_recv_buff_;

        /*
         *  The DATA_LENGTH setting here may not be the len sending to remote
         *
         *  it's the protocol (see below) that decides how many bytes should be send, but we could assume that at least bytes_read + Protocol::ProtocolHeader::Size() will be send
         */
        protocol_hdr->PAYLOAD_LENGTH = bytes;

        uint64_t bytes_write;

        if (payload_type == PayloadType::SOCKS5_DATA) {
            bytes_write = async_write(this->remote_socket_, boost::asio::buffer(local_recv_buff_, protocol_.OnSocks5RequestSent(protocol_hdr)), yield[ec]);
        } else {
            bytes_write = async_write(this->remote_socket_, boost::asio::buffer(local_recv_buff_, protocol_.OnPayloadReadFromLocal(protocol_hdr)), yield[ec]);
        }


        if (ec)
        {
            TCP_DEBUG("[{:p}] handleSocks5Request async_write socks5 request to server err --> {}", (void*)this, ec.message().c_str())
            return false;
        }

		LOG_DETAIL(TCP_DEBUG("[{:p}] send {} bytes to remote", (void*)this, bytes_write))
		AddUpTraffic(bytes_write)
        return true;
    }


    bool connectToRemote(boost::asio::yield_context& yield)
    {
        boost::system::error_code ec;
        TCP_DEBUG("[{}] connecting to --> {}:{}", (void*)this, this->remote_ep_.address().to_string().c_str(), this->remote_ep_.port())

        this->remote_socket_.async_connect(remote_ep_, yield[ec]);

        if (ec)
        {
            TCP_DEBUG("[{}] can't connect to remote --> {}",(void*)this, ec.message().c_str())
            return false;
        }
		TCP_DEBUG("[{}] connected to --> {}:{}", (void*)this, this->remote_ep_.address().to_string().c_str(), this->remote_ep_.port())

        return true;
    }


    inline void onDestruction(boost::asio::yield_context& yield)
	{
		boost::system::error_code ec;
        auto num = RandomNumberGenerator::GetRandomIntegerBetween<uint16_t>(3, 10);
        boost::asio::deadline_timer timer(this->local_socket_.get_executor());
        timer.expires_from_now(boost::posix_time::seconds(num));
        timer.async_wait(yield[ec]);

        return;
    }

};


