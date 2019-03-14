#pragma once
#include <boost/enable_shared_from_this.hpp>
#include "../../../utils/ephash.h"

class ServerUdpRawProxySession : public boost::enable_shared_from_this<ServerUdpRawProxySession>
{

public:

    ServerUdpRawProxySession(const ep_tuple& tp) : ep_tp(tp)
    {

    }

private:

    ep_tuple ep_tp;


};