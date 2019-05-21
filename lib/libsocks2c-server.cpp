#include "libsocks2c-server.h"
#include "libsocks2c.h"

#ifdef __cplusplus
extern "C" {
#endif

void socks2c_setsqlhost(char* host)
{
    LibSocks2c::SetSqlHost(host);
}
 void test()
 {

 }

int socks2c_start(int64_t uid, const char* key, uint16_t udp_port)
{
    LibSocks2c::Config config;
    config.uid = uid;
    config.isServer = true;
    config.server_ip = "::0";
    config.server_port = udp_port;
    config.proxyKey = key;
    config.timeout = 0;
    LibSocks2c::StartProxy(config);
}

int socks2c_start_raw(long uid, const char* key, unsigned short udp_port, char* raw_ip, unsigned short raw_port, char* ifname)
{
    LibSocks2c::Config config;
    config.uid = uid;
    config.isServer = true;
    config.server_ip = "::0";
    config.server_port = udp_port;
    config.local_uout_ip = std::string(raw_ip);
    config.local_uout_port = raw_port;
    config.udp_over_utcp = true;
    config.proxyKey = key;
    config.timeout = 0;
    LibSocks2c::StartProxy(config);
}

void socks2c_stop(uint16_t instance_id)
{
    LibSocks2c::StopProxy(instance_id, true);
}

#ifdef __cplusplus
}
#endif