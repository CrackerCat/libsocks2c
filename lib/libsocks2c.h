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
    static int AsyncRunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    /*
	 * @Thread Safe
	 *
	 * Stop call is asynchronous and it only stops TCP/UDP acceptor, sessions will expire later
	 *
	 * @Return true if the inner asyncstop is called
	 * 		   false if server not exist or you call StopServer() before
	 */
	static bool StopProxy(int id);

	/*
	 * @Thread Safe
	 *
	 * Clear the proxy server and release the memory
	 *
	 * Call StopServer() before clear, or you can never clear it
	 *
	 * @Return true if the server is deleted
	 * 		   false if there are some pending session
	 */
	static bool ClearProxy(int id);

	/*
	 * @Thread Safe
	 *
	 * Manage the proxy instance by the system, do not Stop or Clear proxy once you call AutoManage
	 *
	 */
	static void AutoManage(int id);

	static void RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);


};


