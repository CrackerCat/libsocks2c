#pragma once

#include "../lib/libsocks2c.h"

void test()
{

    LibSocks2c::RunClientMt("12345678", "0.0.0.0", 5555, "45.32.62.168", 2222);



}