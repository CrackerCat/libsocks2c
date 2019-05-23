#include "libsocks2c-server.h"
#include "libsocks2c.h"

#ifdef __cplusplus
extern "C" {
#endif

void socks2c_setsqlhost(char* host)
{
    LibSocks2c::SetSqlHost(host);
}


int socks2c_start(long uid, const char* key, uint16_t port)
{
    LibSocks2c::Config config;
    config.uid = uid;
    config.isServer = true;
    config.server_ip = "::0";
    config.server_port = port;
    config.proxyKey = key;
    config.timeout = 0;
    LibSocks2c::StartProxy(config);
	return port;
}

int socks2c_start_raw(long uid, const char* key, unsigned short port, char* raw_ip, unsigned short raw_port, char* ifname)
{
    LibSocks2c::Config config;
    config.uid = uid;
    config.isServer = true;

    config.server_ip = "::0";
    config.server_port = port;

	config.local_uout_ifname = std::string(ifname);
    config.local_uout_ip = std::string(raw_ip);
    config.server_uout_port = raw_port;
    config.udp_over_utcp = true;
    config.proxyKey = key;
    config.timeout = 0;
    LibSocks2c::StartProxy(config);
	return port;
}

void socks2c_stop(uint16_t instance_id)
{
    LibSocks2c::StopProxy(instance_id, true);
}

#ifdef __cplusplus
}
#endif