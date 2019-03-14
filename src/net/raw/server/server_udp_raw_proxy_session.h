#pragma once
#include <boost/enable_shared_from_this.hpp>
#include "../../../utils/ephash.h"
#include <boost/unordered_map.hpp>

class ServerUdpRawProxySession : public boost::enable_shared_from_this<ServerUdpRawProxySession>
{
    enum SESSION_STATUS
    {
        SYN_RCVD,
        ESTABLISHED
    };


    class udp_session
    {

    };

    using UdpSessionMap = boost::unordered_map<udp_ep_tuple, udp_session, EndPointTupleHash>;

public:

    ServerUdpRawProxySession(const ep_tuple& tp) : ep_tp(tp)
    {

    }


    bool HandlePacket(void* data, size_t size)
    {
        return true;
    }



private:

    UdpSessionMap udpsession_map;
    SESSION_STATUS status;

    uint32_t seq;
    uint32_t seq_ack;

};