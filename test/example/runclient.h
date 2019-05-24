#pragma once

#include "../../lib/libsocks2c.h"

void test()
{
    /*
     * Run Client setting socks5 port at ::0:5555
     *            setting server host 127.0.0.1:2222
     *            proxy password "12345678"
     */

    LibSocks2c::Config config;
    config.proxyKey = "12345678";
    //config.server_ip = "112.74.160.183";
    config.server_ip = "192.168.1.102";
    config.server_port = 3000;
	config.server_uout_port = 3001;

    config.socks5_ip = "0.0.0.0";
    config.socks5_port = 1080;

    //config.local_uout_ip = "192.168.1.104";
    config.local_uout_ifname = "en0";
    config.dnsuout = true;

    config.resolve_dns = false;
    config.udp_over_utcp = true;

    config.logtofile = false;

    auto res = LibSocks2c::StartProxy(config);

    getchar();

    LibSocks2c::StopProxy(res);
    getchar();

}