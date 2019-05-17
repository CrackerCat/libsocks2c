#pragma once

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )
#else
#define OS_Dll_API
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include <cstdint>

OS_Dll_API void socks2c_setsqlhost(char* host);

OS_Dll_API int  socks2c_start(int64_t uid, const char* key, uint16_t port);

OS_Dll_API void socks2c_stop(uint16_t instance_id);

#ifdef __cplusplus
}
#endif

