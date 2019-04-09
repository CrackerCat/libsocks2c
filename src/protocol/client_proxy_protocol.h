#pragma once

#include "iproxy_protocol.h"

template<class PH>
class ClientProxyProtocol : public IProxyProtocol<PH>{


public:


    /*
     *  return len of sending data
     */
    uint64_t OnSocks5RequestSent(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnSocks5RequestSent(header);
    }

    /*
     *  Data is place at GetDataOffsetPtr()
     */
    uint64_t OnPayloadReadFromLocal(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnPayloadReadFromLocal(header);
    }

    uint64_t OnPayloadHeaderReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnPayloadHeaderReadFromRemote(header);
    }

    bool OnPayloadReadFromRemote(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnPayloadReadFromRemote(header);
    }




    uint64_t OnUdpPayloadReadFromClientLocal(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnUdpPayloadReadFromClientLocal(header);
    }
    uint64_t OnUdpPayloadReadFromClientRemote(typename IProxyProtocol<PH>::ProtocolHeader *header)
    {
        return static_cast<PH*>(this)->OnUdpPayloadReadFromClientRemote(header);
    }



};


