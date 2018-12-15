#pragma once


/*

 From SOCKS Protocol Version 5
 https://www.ietf.org/rfc/rfc1928.txt

 */
#include <string>
#include <vector>


namespace socks5 {


    using std::vector;


    enum SOCKS5_CMD_TYPE : char
    {

        CONNECT = 0x01,
        BIND = 0x02,
        UDP_ASSOCIATE = 0x03

    };

    enum SOCKS5_ATYP_TYPE : char
    {

        IPV4 = 0x01,
        DOMAINNAME = 0x03,
        IPV6 = 0x04

    };

    struct METHOD_REQ
    {

        char VER = 0x05;
        char NMETHOD = 0x01;
        char METHODS;

    };

    // Always return NO AUTHENTICATION REQUIRED
    struct METHOD_REPLY
    {

        char VER = 0x05;
        char METHOD = 0x00;

    };

    //NO AUTHENTICATION REQUIRED
    static const vector<char> DEFAULT_METHOD_REPLY = {0x05,0x00};

    //Support IPv4 and Domain only
    struct SOCKS_REQ
    {

        char VER = 0x05;
        char CMD;
        char RSV = 0X00;
        char ATYP;
        //char[] variable length
        //short port

    };



    /*
     o  REP    Reply field:
     o  X'00' succeeded
     o  X'01' general SOCKS server failure
     o  X'02' connection not allowed by ruleset
     o  X'03' Network unreachable
     o  X'04' Host unreachable
     o  X'05' Connection refused
     o  X'06' TTL expired
     o  X'07' Command not supported
     o  X'08' Address type not supported
     o  X'09' to X'FF' unassigned
     */
    struct SOCKS_REPLY
    {

        char VER = 0x05;
        char REP = 0x00;
        char RSV = 0X00;
        char ATYP;
        //char[] BND.ADDR
        //short BND.PORT

    };

    // Always return successed
    static const vector<char> DEFAULT_SOCKS_REPLY = {0x05, 0x00, 0x00, 0x01 ,0x00 ,0x00 ,0x00, 0x00, 0x10,0x10};

    /*
        the specific ip:port is for testing
     */
    static unsigned char DEFAULT_UDP_REQ_REPLY[10] = {0x05, 0x00, 0x00, 0x01, 0x0A, 0xD3, 0x37, 0x02, 0x04, 0x38};


    struct UDP_RELAY_PACKET
    {

        short RSV = 0x00;
        char FRAG;
        char ATYP;
        //DST.ADDR
        //DST.PORT
        //DATA

    };



}






