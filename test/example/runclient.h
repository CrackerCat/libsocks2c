#pragma once

#include "../../lib/libsocks2c.h"
#include <unistd.h>

void test()
{
    /*
     * Run Client setting socks5 port at ::0:5555
     *            setting server host 127.0.0.1:2222
     *            proxy password "12345678"
     */

    LibSocks2c::Config config;
    config.isServer = false;
    config.proxyKey = "12345678";
    config.server_ip = "9.108.59.115";
    config.server_port = 443;
    config.socks5_ip = "0.0.0.0";
    config.socks5_port = 5555;
    config.timeout = 0;
    config.resolve_dns = false;

    LibSocks2c::StartProxy(config);

    getchar();

}