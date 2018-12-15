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


    virtual uint64_t onSocks5RequestHeaderRead(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual bool onSocks5RequestPayloadRead(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual uint64_t onPayloadHeaderReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual bool onPayloadReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual uint64_t onPayloadReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual uint64_t OnUdpPayloadReadFromServerLocal(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;
    virtual uint64_t OnUdpPayloadReadFromServerRemote(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

};


