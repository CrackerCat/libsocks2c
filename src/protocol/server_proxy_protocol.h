#pragma once

#include "iproxy_protocol.h"

template<class PH>
class ServerProxyProtocol : public IProxyProtocol<PH>{


public:

    /*
     *  func with return type
     *      1.  uint64_t return 0 if err,
     *      2.  bool     return false if err
     */


    uint64_t onSocks5RequestHeaderRead(typename IProxyProtocol<PH>::ProtocolHeader *header, std::string client_ip)
    {
        return static_cast<PH*>(this)->onSocks5RequestHeaderRead(header, client_ip);
    }

    bool onSocks5RequestPayloadRead(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->onSocks5RequestPayloadRead(header);
    }

    uint64_t onPayloadHeaderReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->onPayloadHeaderReadFromLocal(header);
    }

    bool onPayloadReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->onPayloadReadFromLocal(header);
    }

    uint64_t onPayloadReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->onPayloadReadFromRemote(header);
    }

    uint64_t OnUdpPayloadReadFromServerLocal(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnUdpPayloadReadFromServerLocal(header);
    }
    uint64_t OnUdpPayloadReadFromServerRemote(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnUdpPayloadReadFromServerRemote(header);
    }

};


