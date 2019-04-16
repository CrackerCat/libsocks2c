#pragma once

#include <string>

const std::string v = "2.1.3";

#ifdef UDP_OVER_UTCP
const std::string version = "libsocks2c " + v + " with UOUT";
#else 
const std::string version = "libsocks2c " + v + " without UOUT";
#endif // UDP_OVER_UTCP
