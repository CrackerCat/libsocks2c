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
		getchar();
		LibSocks2c::AsyncRunClient("12345678", "::0", 5555, "119.129.130.93", 2222, 300);
		printf("enter to stop\n");
		getchar();
		LibSocks2c::StopClient();
	}
	
	

}