#pragma once

#if defined(BUILD_DLL) && defined(_WIN32)
#define OS_Dll_API   __declspec( dllexport )
#else
#define OS_Dll_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

	OS_Dll_API void socks2c_setsocks5(const char* socks5_ip, unsigned short socks5_port);

	OS_Dll_API int  socks2c_start(const char* key, const char* server_ip, unsigned short server_port, bool local_dns);
	OS_Dll_API int  socks2c_start_raw(const char* key, const char* server_ip, unsigned short server_port, unsigned short server_uout_port, bool local_dns, char* ifname, bool dns_uout);

	OS_Dll_API void socks2c_stop(unsigned short instance_id);

#ifdef __cplusplus
}
#endif
