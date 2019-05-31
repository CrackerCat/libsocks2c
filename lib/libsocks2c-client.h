#pragma once

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )
#else
#define OS_Dll_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

	OS_Dll_API void socks2c_setsocks5(const char* socks5_ip, const char* socks5_port);

	OS_Dll_API int  socks2c_start(const char* key, const char* server_ip, const char* server_port, int local_dns);
	OS_Dll_API int  socks2c_start_raw(const char* key, const char* server_ip, const char* server_port, const char* server_uout_port, const char* ifname, int local_dns, int dns_uout);

	OS_Dll_API void socks2c_stop(unsigned short instance_id);

#ifdef __cplusplus
}
#endif
