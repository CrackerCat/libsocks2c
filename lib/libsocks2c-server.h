#pragma once

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )
#else
#define OS_Dll_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

OS_Dll_API void socks2c_setsqlhost(char* host);

OS_Dll_API int  socks2c_start(long uid, const char* key, unsigned short port);

OS_Dll_API void socks2c_stop(unsigned short instance_id);
OS_Dll_API void test();

#ifdef __cplusplus
}
#endif

