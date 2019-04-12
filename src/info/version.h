#pragma once

#include <string>
#ifdef UDP_OVER_UTCP
const std::string version = "libsocks2c 2.1.0 with UOUT";
#else 
const std::string version = "libsocks2c 2.1.0 without UOUT";
#endif // UDP_OVER_UTCP
