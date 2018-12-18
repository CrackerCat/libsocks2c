#pragma once

#include "../lib/libsocks2c.h"

#ifdef _WIN32
#include <Windows.h>
#define sleep(x) Sleep(x)
#else
#include <unistd.h>
#endif

void test()
{
	while (true)
	{
		printf("enter to start\n");
		fflush(stdout);
		getchar();
		LibSocks2c::AsyncRunServer("12345678", "::0", 2222, 3000);
		printf("enter to stop\n");
		fflush(stdout);
		getchar();
		LibSocks2c::StopServer();
	}
	


}