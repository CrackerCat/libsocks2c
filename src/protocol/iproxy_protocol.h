#pragma once

#include <cstdint>

template<class PH>
struct IProxyProtocol {

    typedef PH ProtocolHeader;
    virtual void SetKey(unsigned char key[32U]) {}
};
