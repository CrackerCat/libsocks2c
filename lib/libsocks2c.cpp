#include "libsocks2c.h"

#include "../src/app/app.h"

#ifdef BUILD_SERVER_LIB
#include "../src/factory/server_factory.h"
#include "server_proxymap.h"
#endif

#if BUILD_CLIENT_LIB
#include "../src/factory/client_factory.h"
#include "client_proxymap.h"
#endif

#include "../src/protocol/basic_protocol/protocol_def.h"

#include <boost/asio/io_context.hpp>


int LibSocks2c::StartProxy(Config config)
{

    App::Init(config.logtofile);
#ifdef BUILD_SERVER_LIB
    //run server
    if (config.isServer)
    {
        if (ServerProxyMap<Protocol>::GetInstance()->IsProxyExist(config.server_port)) return 0;

        auto handle = ServerFactory::CreateServerProxy<Protocol>(
                config.proxyKey,
                config.server_ip,
                config.server_port,
                config.server_uout_port,
                config.udp_over_utcp,
                config.timeout,
                config.uid);

        auto res = ServerProxyMap<Protocol>::GetInstance()->Insert(config.server_port, handle);

        if (!res) return -1;

        return config.server_port;
    }
#endif

    #ifdef BUILD_CLIENT_LIB
    //run client
    if (ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(config.socks5_port) || config.isServer) return 0;
    auto handle = ClientFactory::CreateClientProxy<Protocol>(config);

    auto res = ClientProxyMap<Protocol>::GetInstance()->Insert(config.socks5_port, handle);

    if (res) return -1;

    return config.socks5_port;
#endif
    return -1;
}


bool LibSocks2c::StopProxy(int id, bool isServer)
{
    if (isServer)
    {
#ifdef BUILD_SERVER_LIB
        if (!ServerProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;
        return ServerProxyMap<Protocol>::GetInstance()->StopProxy(id);
    }else
    {
#elif BUILD_CLIENT_LIB
        if (!ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;
        return ClientProxyMap<Protocol>::GetInstance()->StopProxy(id);
#endif
    }
    return false;
}

void LibSocks2c::StartProxyWithContext(Config config, boost::asio::io_context &io_context)
{

}

#include "../src/utils/sqlhost.h"

void LibSocks2c::SetSqlHost(std::string host)
{
    sql_host = host;
}

#include "../src/info/version.h"
#include "../src/info/encryption_info.h"
std::string LibSocks2c::Version()
{
	return version + " [" + ENCRYPTION_METHOD + "]";
}

