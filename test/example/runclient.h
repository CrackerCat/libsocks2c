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
    auto id = LibSocks2c::AsyncRunClient("12345678", "::0", 5555, "192.168.1.147", 2222);

    sleep(5);

    LibSocks2c::StopProxy(5555);

    sleep(5222);


}