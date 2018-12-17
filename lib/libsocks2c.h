#pragma once

#include <string>

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )   
#else
	#ifdef _WIN32
	#define OS_Dll_API   __declspec( dllimport )   
	#else 
	#define OS_Dll_API
	#endif
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

    static void AsyncRunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);
	
	static void StopClient();

    static void AsyncRunServer(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void AsyncRunServerMt(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void StopServer();


    static void RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

	/*
	 *	  @Thread Safe
	 *	  BUT, the impl doesn't use mutex nor atomic variable
	 *	  so it might return weired value which you'll need to drop
	 *	  
	 *	  if not compile with ENABLE_TRAFFIC_COUNT, it always will return 0
	 */
	static uint64_t GetUpstreamTraffic();
	static uint64_t GetDownstreamTraffic();

};


