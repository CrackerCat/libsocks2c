#include "client_udp_raw_proxy.h"
#include "../../udp/client/client_udp_proxy_session.h"

void ClientUdpRawProxy::RecvFromRemote()
{
    //recv
    boost::asio::spawn(this->sniffer_socket.get_io_context(), [this](boost::asio::yield_context yield){

        using Tins::TCP;
        while(1)
        {

            boost::system::error_code ec;
            this->sniffer_socket.async_wait(boost::asio::posix::descriptor_base::wait_read, yield[ec]);
            if (ec)
            {
                LOG_INFO("wait err\n");
                return;
            }

            std::unique_ptr<Tins::PDU> pdu_ptr(this->psniffer->next_packet());

            auto tcp = pdu_ptr->find_pdu<TCP>();
            if (tcp == nullptr)
            {
                LOG_INFO("TCP Header not found")
                continue;
            }

            switch (tcp->flags())
            {
                case (TCP::SYN):
                {
                    LOG_INFO("SYN")
                    continue;
                }
                case (TCP::SYN | TCP::ACK):
                {
                    LOG_INFO("recv SYN | ACK seq: {} ack: {}", tcp->seq(), tcp->ack_seq());
                    handshakeReply(tcp->seq(), tcp->ack_seq(), yield);
                    continue;
                }
                    // without data
                case TCP::ACK :
                {
                    LOG_INFO("recv ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                    if (tcp->ack_seq() > local_seq)
                    {
                        local_seq = tcp->ack_seq();
                    }
                    break;
                }
                    // with data
                case (TCP::PSH | TCP::ACK) :
                {
                    LOG_INFO("recv PSH | ACK seq: {}, ack: {}", tcp->seq(), tcp->ack_seq())
                    ackReply(tcp->seq(), tcp->ack_seq());
                    break;
                }
                case TCP::RST :
                {
                    LOG_INFO("recv RST")
                    break;
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