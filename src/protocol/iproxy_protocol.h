#pragma once

#include <cstdint>

template<class PH>
struct IProxyProtocol {

    typedef PH ProtocolHeader;
    void SetKey(unsigned char key[32U]) {
        static_cast<PH*>(this)->SetKey(key);
    }
};
