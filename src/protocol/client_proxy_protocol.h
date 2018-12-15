#pragma once

#include "iproxy_protocol.h"

template<class PH>
class ClientProxyProtocol : public IProxyProtocol<PH>{


public:


    /*
     *  return len of sending data
     */
    virtual uint64_t OnSocks5RequestSent(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;


    /*
     *  Data is place at GetDataOffsetPtr()
     */
    virtual uint64_t OnPayloadReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual uint64_t OnPayloadHeaderReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;

    virtual bool OnPayloadReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;




    virtual uint64_t OnUdpPayloadReadFromClientLocal(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;
    virtual uint64_t OnUdpPayloadReadFromClientRemote(typename IProxyProtocol<PH>::ProtocolHeader *header) = 0;



};


