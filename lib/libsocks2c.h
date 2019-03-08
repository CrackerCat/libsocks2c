#pragma once
∂
#include <string>

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )
#else
#define OS_Dll_API
#endif


namespace boost
{
    namespace asio
    {
        class io_context;
    }
}



class OS_Dll_API LibSocks2c {

public:

    struct Config
    {
        bool isServer;
        std::string proxyKey;
        std::string server_ip;
        uint16_t server_port;
        std::string socks5_ip;
        uint16_t socks5_port;
        size_t timeout;
        bool resolve_dns;
    };

    static int  StartProxy(Config);
    static bool StopProxy(int);

    static void StartProxyWithContext(Config, boost::asio::io_context&);

    static std::string GetVersion();
};


