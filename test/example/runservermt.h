#pragma once
#include "../../lib/libsocks2c.h"

void test()
{
    /*
     * Run Server at port ::0:2222 with password "12345678"
     */
    LibSocks2c::AsyncRunServer("12345678", "::0", 2222);

    /*
     * Run Server at port ::0:2222 with password "12345678" setting timeout 300s for acceptors
     */
    //LibSocks2c::AsyncRunServer("12345678", "::0", 2222, 300);

    getchar();
}