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

int socks2c_start(int64_t uid, const char* key, uint16_t port)
{
    LibSocks2c::Config config;
    config.uid = uid;
    config.isServer = true;
    config.server_ip = "::0";
    config.server_port = port;
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