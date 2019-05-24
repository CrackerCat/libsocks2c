#pragma once

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
        std::string proxyKey;

        std::string server_ip;
        uint16_t server_port;
		uint16_t server_uout_port;

        bool udp_over_utcp = false;
        std::string local_uout_ifname;
		std::string local_uout_ip;
		uint16_t local_uout_port;
        bool dnsuout;

        std::string socks5_ip = "127.0.0.1";
        uint16_t socks5_port = 1080;

        bool resolve_dns = false;
        bool logtofile = false;
    };

    static int  StartProxy(Config);
    static bool StopProxy(int);

    static std::string Version();

    static void SetSqlHost(std::string);
};


