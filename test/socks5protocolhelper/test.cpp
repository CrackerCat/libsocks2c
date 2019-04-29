#define BOOST_TEST_MODULE Socks5ProtocolHelper

#include <boost/test/included/unit_test.hpp>
#include <boost/lexical_cast.hpp>
#include "../../src/protocol/socks5/socks5_protocol_helper.h"


std::string ip_res;
uint16_t port_res;

BOOST_AUTO_TEST_CASE(first)
{
    printf("test www.google.com:53\n");
    unsigned char buff[] = {0x05, 0x01, 0x00, 0x03, 0x0E,
                   0x77, 0x77, 0x77, 0x2e,
                   0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
                   0x63, 0x6f, 0x6d,
                   0x00, 0x35};

    auto request = (socks5::SOCKS_REQ*)buff;

    BOOST_TEST(true == Socks5ProtocolHelper::parseDomainPortFromSocks5Request(request, ip_res, port_res));
    printf("res %s:%d\n",ip_res.c_str(), port_res);
}

BOOST_AUTO_TEST_CASE(second)
{
    printf("test www.google.com:443\n");
    unsigned char buff[] = {0x05, 0x01, 0x00, 0x03, 0x0E,
                   0x77, 0x77, 0x77, 0x2e,
                   0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
                   0x63, 0x6f, 0x6d,
                   0x01, 0xbb};

    auto request = (socks5::SOCKS_REQ*)buff;

    BOOST_TEST(true == Socks5ProtocolHelper::parseDomainPortFromSocks5Request(request, ip_res, port_res));
    printf("res %s:%d\n",ip_res.c_str(), port_res);
}

BOOST_AUTO_TEST_CASE(third)
{
    printf("test wwwgooglecom:443\n");
    unsigned char buff[] = {0x05, 0x01, 0x00, 0x03, 0x0c,
                            0x77, 0x77, 0x77,
                            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
                            0x63, 0x6f, 0x6d,
                            0x01, 0xbb};

    auto request = (socks5::SOCKS_REQ*)buff;

    BOOST_TEST(false == Socks5ProtocolHelper::parseDomainPortFromSocks5Request(request, ip_res, port_res));
    printf("res %s:%d\n",ip_res.c_str(), port_res);
}