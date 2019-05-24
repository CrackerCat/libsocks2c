#include "libsocks2c.h"

#include "client_proxymap.h"
#include "../src/app/app.h"
#include "../src/factory/client_factory.h"
#include "../src/protocol/basic_protocol/protocol_def.h"

#include <boost/asio/io_context.hpp>


int LibSocks2c::StartProxy(Config config)
{

    App::Init(config.logtofile);

    //run client
    if (ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(config.socks5_port) || config.isServer) return 0;
    auto handle = ClientFactory::CreateClientProxy<Protocol>(config);

    auto res = ClientProxyMap<Protocol>::GetInstance()->Insert(config.socks5_port, handle);

    if (res) return -1;

    return config.socks5_port;

}


bool LibSocks2c::StopProxy(int id, bool isServer)
{
    if (!ClientProxyMap<Protocol>::GetInstance()->IsProxyExist(id)) return false;
    return ClientProxyMap<Protocol>::GetInstance()->StopProxy(id);
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

