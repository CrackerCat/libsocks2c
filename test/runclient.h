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
		LibSocks2c::AsyncRunClient("12345678", "::0", 5555, "45.32.62.18", 2222, 300);
		sleep(1000);
		printf("enter to stop\n");
		getchar();
		LibSocks2c::StopClient();
		sleep(1000);
	}
	
	

}