#pragma once

#include <boost/asio/deadline_timer.hpp>

#include "../netio/basic_network_io_mt.h"

#ifdef _WIN32
#include <WinSock2.h>
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#else
#include <arpa/inet.h>
#endif

class INetworkProxy : public BasicNetworkIO_MT {


public:

    INetworkProxy(){}

   ~INetworkProxy(){
       LOG_DEBUG("INetworkProxy die")

   }

    /*
     *  Start proxy at local_address:local_port
     *
     *  block when using build-in context
     *  no block if you provide your own context
     */
	virtual void StartProxy(std::string local_address, uint16_t local_port) {}

    /*
     *  Key for client-server connection, max length is 32U
     */
    virtual void SetProxyKey(std::string key)
    {
        bzero(proxyKey_, 32U);
        memcpy(proxyKey_, key.c_str(), key.size() < 32 ? key.size() : 32);
    }

    /*
     *  Set the ip && port for server if you are client
     */
    virtual void SetProxyInfo(std::string server_ip, uint16_t server_port)
    {
        this->server_ip = server_ip;
        this->server_port = server_port;
    }

    /*
     *  Timeout for destroying idle proxy instance
     *
     */
    void SetExpireTime(uint64_t time_sec)
    {
        if (time_sec == 0) time_sec = 86400;
        this->expire_time = time_sec;
        last_active_time = time(nullptr);
    }

protected:

    using TIMER = boost::asio::deadline_timer;
    using PTIMER = std::unique_ptr<TIMER>;

    unsigned char proxyKey_[32U];

    PTIMER ptimer_;
    time_t last_active_time;
    time_t expire_time = 0;

    std::string server_ip;
    uint16_t server_port;

    virtual void startAcceptorCoroutine() = 0;


};


