#pragma once
#include <tins/ip.h>
int CalTcpChecksum(Tins::IP ip_including_tcp, unsigned char* ip_data_with_tcp);
