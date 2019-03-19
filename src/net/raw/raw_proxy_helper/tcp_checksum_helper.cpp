#include "tcp_checksum_helper.h"
#include <tins/tcp.h>
#ifdef _WIN32
#include <WinSock2.h>
#endif // _WIN32

#include "../unix_hdr/ip.h"
#include "../unix_hdr/tcp.h"

struct psd_header
{
    char mbz = 0x00; // 0x00;
    unsigned char ptcl; //protocol type
    unsigned short tcpl; //TCP length
    in_addr saddr; //src_addr
    in_addr daddr; //dst_addr
};

inline u_short getChecksum(unsigned short* addr, size_t count)
{
    psd_header* psd_hdr = (psd_header*)addr;
    tcphdr* tcp_hdr = (tcphdr*)(psd_hdr + 1);
    tcp_hdr->th_sum = 0;
    size_t sum = 0;
    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }
    if (count > 0) {
        char left_over[2] = { 0 };
        left_over[0] = *addr;
        sum += *(unsigned short*)left_over;
    }

    while (sum >> 16){
        size_t r1 = sum >> 16;
        size_t r2 = sum & 0x0000ffff;
        sum = (sum & 0x0000ffff) + (sum >> 16);
    }

    return ~sum;
}

int CalTcpChecksum(Tins::IP ip_including_tcp, unsigned char* ip_data_with_tcp)
{
    Tins::TCP* tins_tcp = ip_including_tcp.find_pdu<Tins::TCP>();
    if (tins_tcp == nullptr) return 0;

    auto payload_size = tins_tcp->inner_pdu() ? tins_tcp->inner_pdu()->size() : 0;
    auto tcp_calchecksum_total_len = sizeof(psd_header) + tins_tcp->header_size() + payload_size;

    auto ip_header = (ip*)ip_data_with_tcp;

    auto tcp_header = (tcphdr*)(ip_data_with_tcp + ip_including_tcp.header_size());

    auto tcp_psd_header = (psd_header *)&ip_header->ip_ttl;
    tcp_psd_header->mbz = 0x00;
    tcp_psd_header->tcpl = htons(payload_size + tins_tcp->header_size());

    auto paddle_len = tcp_calchecksum_total_len % 2;

    if (paddle_len != 0)
    {
        *((char*)(tcp_psd_header) + tcp_calchecksum_total_len) = 0x00;
    }
    unsigned short tcp_checksum = getChecksum((unsigned short*)tcp_psd_header, tcp_calchecksum_total_len + paddle_len);

    tcp_header->th_sum = tcp_checksum;

    return tcp_checksum;
}
