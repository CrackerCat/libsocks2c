#include "tcp_checksum_helper.h"
#include <tins/utils/checksum_utils.h>

struct tcp_header
{
    unsigned short tcp_sprt;
    unsigned short tcp_dprt;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_res:4;
    unsigned char tcp_off:4;
    unsigned char tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_csum;
    unsigned short tcp_urp;
};

struct pseudoTcpHeader
{
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned char zero;//always zero
    unsigned char protocol;// = 6;//for tcp
    unsigned short tcp_len;
    struct tcp_header tcph;
};

int CalChecksum(void* tcp_hdr, int tcp_data_size_including_tcp_hdr)
{

}
