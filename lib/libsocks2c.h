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

    /*
     * @Thread Safe
     *
     * @Return server id, it's the port actually
     * 		   0 if there is another server running at that port
     */
    static int AsyncRunServer(std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);
    static int AsyncRunClient(std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);


    static bool PauseClient(int id);
    static bool RestartClient(int id);

    static bool RetargetProxyServer(int id, std::string ip, uint16_t port);


    /*
	 * @Thread Safe
	 *
	 * Stop call is asynchronous and it only stops TCP/UDP acceptor, sessions will expire later
	 *
	 * @Return true if the inner asyncstop is called
	 * 		   false if server not exist or you call StopServer() before
	 */
    static bool StopProxy(int id);


    static void RunClientWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string socks5_ip, uint16_t socks5_port, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static void RunServerWithExternContext(boost::asio::io_context &io_context, std::string proxyKey, std::string server_ip, uint16_t server_port, uint64_t timeout = 0);

    static std::string GetLibVersion();
};


