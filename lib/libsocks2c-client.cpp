#include "libsocks2c-client.h"
#include "libsocks2c.h"
static std::string s5_ip = "127.0.0.1";
static unsigned short s5_port = 1080;
#ifdef __cplusplus
extern "C" {
#endif

	void socks2c_setsocks5(const char* socks5_ip, unsigned short socks5_port)
	{
		
	}


	int socks2c_start(const char* key, const char* server_ip, unsigned short server_port, bool local_dns)
	{
		LibSocks2c::Config config;
		config.proxyKey = key;
		config.server_ip = server_ip;
		config.server_port = server_port;
		config.socks5_ip = s5_ip;
		config.socks5_port = s5_port;
		config.resolve_dns = local_dns;
		config.udp_over_utcp = false;
		LibSocks2c::StartProxy(config);
		return s5_port;
	}

	int socks2c_start_raw(const char* key, const char* server_ip, unsigned short server_port, unsigned short server_uout_port, bool local_dns, char* ifname, bool dns_uout)
	{
		LibSocks2c::Config config;
		config.proxyKey = key;
		config.server_ip = server_ip;
		config.server_port = server_port;
		config.socks5_ip = s5_ip;
		config.socks5_port = s5_port;
		config.resolve_dns = local_dns;

		config.udp_over_utcp = true;
		config.server_uout_port = server_uout_port;
		config.local_uout_ifname = ifname;
		config.dnsuout = dns_uout;

		LibSocks2c::StartProxy(config);
		return s5_port;
	}

	void socks2c_stop(uint16_t instance_id)
	{
		LibSocks2c::StopProxy(instance_id);
	}

#ifdef __cplusplus
}
#endif