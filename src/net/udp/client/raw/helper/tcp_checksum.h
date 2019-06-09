#pragma once
#include <tins/pdu.h>
int CalTcpChecksum(Tins::PDU& ip_including_tcp, unsigned char* ip_data_with_tcp);
