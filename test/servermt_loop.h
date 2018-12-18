#pragma once
#include "../lib/libsocks2c.h"

#include <unistd.h>

void test()
{

    for (int i = 0; i < 3000; ++i) {
        LibSocks2c::AsyncRunServer("12345678", "::0", 2222 + i, 2);
        sleep(1);
        printf("stoping\n");
        LibSocks2c::StopServer(2222 + i);
        LibSocks2c::StopServer(2222 + i);
        LibSocks2c::StopServer(2222 + i);
        LibSocks2c::StopServer(2222 + i);
        printf("clearing\n");
        sleep(2);
        auto res = LibSocks2c::ClearServer(2222 + i);

        while (!res)
        {
            printf("clear failed retry\n");
            fflush(stdout);
            sleep(1);
            res = LibSocks2c::ClearServer(2222 + i);
        }
        int j = 0;
    }


}