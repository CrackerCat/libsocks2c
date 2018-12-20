#pragma once
#include "../lib/libsocks2c.h"

#include <unistd.h>

void test()
{

    LibSocks2c::AsyncRunServer("12345678", "::0", 2222, 3);
    sleep(5);
    printf("stoping\n");
    LibSocks2c::StopProxy(2222);

    printf("auto manage");
    LibSocks2c::AutoManage(2222);

    sleep(1);
    LibSocks2c::AsyncRunServer("12345678", "::0", 2223, 3);

    LibSocks2c::AutoManage(2223);
    sleep(5);

    LibSocks2c::StopProxy(2223);

    sleep(2211212);

    int j = 0;

}