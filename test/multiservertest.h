#pragma once

#include "../lib/libsocks2c.h"

#ifdef _WIN32
#include <Windows.h>
#define sleep(x) Sleep(x)
#endif

void test()
{
	while (true)
	{
		printf("enter to start\n");
		getchar();
		LibSocks2c::AsyncRunServer("12345678", "::0", 2222, 3000);		sleep(1000);
		printf("enter to stop\n");
		getchar();
		LibSocks2c::StopServer();
		sleep(1000);
	}
	

	sleep(30000);

}