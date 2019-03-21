#include "interface_helper.h"
#include <algorithm>

#ifdef __APPLE__
#include "../../../utils/system/system_exec.h"
std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "route -n get default | grep 'interface' | awk '{print $2}'";
    auto res = ExecAndGetRes(default_if_str.c_str());
    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());
    return res;
}
std::string InterfaceHelper::GetDefaultNetIp()
{
    std::string default_ip_str = "ipconfig getifaddr ";
    default_ip_str += GetDefaultInterface();
    auto res = ExecAndGetRes(default_ip_str.c_str());
    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());
    return res;
}
#elif __linux__

#include "../../../utils/system/system_exec.h"
std::string InterfaceHelper::GetDefaultInterface()
{
    const std::string default_if_str = "ip route | awk '/default/ { print $5 }'";
    auto res = ExecAndGetRes(default_if_str.c_str());
    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());
    return res;
}
std::string InterfaceHelper::GetDefaultNetIp()
{
    const std::string default_if_str = "ip route | awk '/default/ { print $9 }'";
    auto res = ExecAndGetRes(default_if_str.c_str());

    res.erase(std::remove(res.begin(), res.end(), '\n'), res.end());

    return res;
}
#elif _WIN32

#include <string>
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")

std::string InterfaceHelper::GetDefaultInterface() { return ""; }

std::string InterfaceHelper::GetDefaultNetIp()  //»ñÈ¡Íø¹Ø
{
	std::string ip;

	std::string local_gateway;
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			return "";
		}
		if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
		{
			pAdapter = pAdapterInfo;
			while (pAdapter)
			{
				local_gateway = pAdapter->GatewayList.IpAddress.String;
				//printf("%s --> %s ip: %s \n", pAdapter->AdapterName, pAdapter->GatewayList.IpAddress.String, pAdapter->IpAddressList.IpAddress.String);
				if (local_gateway != ("") && local_gateway != ("0.0.0.0") && local_gateway != ("255.255.255.255"))
				{
					ip = pAdapter->IpAddressList.IpAddress.String;
					break;
				}
				pAdapter = pAdapter->Next;
			}
		}
		if (pAdapterInfo)
			free(pAdapterInfo);
	}
	return ip;
}

#endif
