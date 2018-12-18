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

	/*
	 * @Thread Safe
	 *
	 * @Return server id, it's the port actually
	 * 		   0 if there is another server running at that port
	 */
    static int AsyncRunServer(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    /*
	 * @Thread Safe
	 *
	 * Stop call is asynchronous and it only stops TCP/UDP acceptor, sessions will die as time goes by
	 *
	 * @Return true if the inner asyncstop is called
	 * 		   false if server not exist or you call StopServer() before
	 */
    static bool StopServer(int id);

	/*
	 * @Thread Safe
	 *
	 * Need to call StopServer() before clear, or you can never clear it
	 *
	 * @Return true if the server is deleted
	 * 		   false if there are some time pending
	 */
	static bool ClearServer(int id);




	static void AsyncRunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);
	static bool StopClient(int id);
	static bool ClearClient(int id);

	static void RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

	/*
	 *	  @Thread Safe
	 *
	 *	  if not compile with ENABLE_TRAFFIC_COUNT, it always will return 0
	 */
	static uint64_t GetUpstreamTraffic();
	static uint64_t GetDownstreamTraffic();

};


