#pragma once

#include "../../client_proxy_protocol.h"
#include "../../server_proxy_protocol.h"

#include "netunnel_protocol_helper.h"

#include "../../../utils/randomNumberGenerator.h"
#include "../../../utils/logger.h"

#include "userstatistic/statistic_helper.h"

#include <cstdint>
#include <string>

#define OBF_THRESHOLD 250
#define OBF_MINPADDLE 250
#define OBF_MAXPADDLE 800

#include "user_info.h"

struct netunnel_aes256gcmwithobf_header{

    unsigned char NONCE[12];
    unsigned char LEN_TAG[16];
    unsigned char PAYLOAD_TAG[16];
    uint32_t PAYLOAD_LENGTH;
    uint32_t PADDING_LENGTH;
    //data

    static constexpr int Size()
    {
        return sizeof(netunnel_aes256gcmwithobf_header);
    }

    unsigned char* GetDataOffsetPtr()
    {
        return NONCE + Size();
    }

};

namespace boost { namespace asio { class io_context; } }

struct netunnel_aes256gcmwithobf_Protocol : public ClientProxyProtocol<netunnel_aes256gcmwithobf_header>, public ServerProxyProtocol<netunnel_aes256gcmwithobf_header>
{

    // it's safe to use raw p here, cause io_context class will never desturct before protocol class
    netunnel_aes256gcmwithobf_Protocol(boost::asio::io_context* io = nullptr) : pio_context(io) {}

    ~netunnel_aes256gcmwithobf_Protocol()
    {
#ifdef BUILD_NETUNNEL_SERVER
        StatisticHelper::DumpTrafficIntoSql(pio_context, uid, upstream_traffic, downstream_traffic, this->src_ip, this->dst_ip_or_domain, this->ttype);
#endif
    }

    void SetUserID(int id)
    {
        this->uid = id;
    }

    uint64_t OnSocks5RequestSent(netunnel_aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }


    uint64_t OnPayloadReadFromLocal(netunnel_aes256gcmwithobf_header *header)
    {


        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }




    uint64_t OnPayloadHeaderReadFromRemote(netunnel_aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);

    }

    bool OnPayloadReadFromRemote(netunnel_aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }




    // We encrypt payload first , then encrypt the data len
    void encryptPayload(netunnel_aes256gcmwithobf_header *header)
    {

        this->downstream_traffic += header->PAYLOAD_LENGTH;

        uint64_t tag_len = 0;

        randombytes_buf(header->NONCE, sizeof(header->NONCE));

        netunnel_aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                             header->PAYLOAD_LENGTH, encryptedData, &tag_len, header->PAYLOAD_TAG);

        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }


    void addObfuscation(netunnel_aes256gcmwithobf_header *header)
    {

        if (header->PAYLOAD_LENGTH > OBF_THRESHOLD)
        {
            header->PADDING_LENGTH = 0;
            return;
        }

        // data needs obf

        auto paddle_len = RandomNumberGenerator::GetRandomIntegerBetween(OBF_MINPADDLE, OBF_MAXPADDLE);

        randombytes_buf(header->GetDataOffsetPtr() + header->PAYLOAD_LENGTH, paddle_len);

        header->PADDING_LENGTH = (uint32_t)paddle_len;


    }


    // return the original len of data + paddle
    uint32_t encryptHeaderLen(netunnel_aes256gcmwithobf_header *header)
    {

        uint32_t original_len = header->PADDING_LENGTH + header->PAYLOAD_LENGTH;

        unsigned char encrypted_length[8];
        uint64_t tag_len = 0;

        //randombytes_buf(header->NONCE, sizeof(header->NONCE));

        netunnel_aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, (unsigned char*)&header->PAYLOAD_LENGTH,
                                             sizeof(header->PAYLOAD_LENGTH) + sizeof(header->PADDING_LENGTH), encrypted_length, &tag_len, header->LEN_TAG);

        memcpy(&header->PAYLOAD_LENGTH, encrypted_length, 8);

        return original_len;

    }





    //  -----   SERVER PART -----

    uint64_t onSocks5RequestHeaderRead(netunnel_aes256gcmwithobf_header *header, std::string client_ip)
    {
        this->src_ip = client_ip;
        this->ttype = TrafficType::TCP;
        return decryptHeader(header);
    }

    void onSocks5IpParse(std::string&& ip)
    {
        this->dst_ip_or_domain = ip;
    }

    void onSocks5DomainParse(std::string&& domain)
    {
        this->dst_ip_or_domain = domain;
    }


    bool onSocks5RequestPayloadRead(netunnel_aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }


    uint64_t onPayloadHeaderReadFromLocal(netunnel_aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);
    }

    bool onPayloadReadFromLocal(netunnel_aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }


    uint64_t onPayloadReadFromRemote(netunnel_aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }




    uint64_t OnUdpPayloadReadFromClientLocal(netunnel_aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }



    uint64_t OnUdpPayloadReadFromClientRemote(netunnel_aes256gcmwithobf_header *header)
    {
        auto data_len = decryptHeader(header);
        if (data_len == 0) return 0;
        if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
        return 0;
    }



    uint64_t OnUdpPayloadReadFromServerLocal(netunnel_aes256gcmwithobf_header *header, std::string&& client_ip)
    {
        this->ttype = UDP;
        this->src_ip = client_ip;
        auto data_len = decryptHeader(header);
        if (data_len == 0) return 0;
		this->upstream_traffic += header->PAYLOAD_LENGTH;
        if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
        return 0;
    }



    uint64_t OnUdpPayloadReadFromServerRemote(netunnel_aes256gcmwithobf_header *header)
    {
		this->downstream_traffic += header->PAYLOAD_LENGTH;
        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();
    }


    inline uint64_t decryptHeader(netunnel_aes256gcmwithobf_header *header)
    {
        struct {
            uint32_t PAYLOAD_LENGTH;
            uint32_t PADDING_LENGTH;
        } len;


        bool res = netunnel_aes256gcmwithobf_Helper::decryptData(this->ProxyKey, header->NONCE,
                                                        (unsigned char *) &header->PAYLOAD_LENGTH,
                                                        sizeof(header->PAYLOAD_LENGTH) +
                                                        sizeof(header->PADDING_LENGTH), (unsigned char *) &len,
                                                        header->LEN_TAG);

        //LOG_DEBUG("decrypt data length = {}   total length = {} ", len.PAYLOAD_LENGTH, len.TOTAL_LENGTH)

        if (res) {
            memcpy(&header->PAYLOAD_LENGTH, &len, sizeof(len));
            this->upstream_traffic += header->PAYLOAD_LENGTH;
            return len.PAYLOAD_LENGTH + len.PADDING_LENGTH;
        }

        return 0;
    }


    inline bool decryptPayload(netunnel_aes256gcmwithobf_header *header)
    {

        bool res = netunnel_aes256gcmwithobf_Helper::decryptData(this->ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                                        header->PAYLOAD_LENGTH, decryptedData,
                                                        header->PAYLOAD_TAG);


        if (res)
        {
            memcpy(header->GetDataOffsetPtr(), decryptedData, header->PAYLOAD_LENGTH);
            return true;
        }

        return false;
    }

    // must keep a copy of key
    void SetKey(unsigned char key[32U]) {
        memcpy(ProxyKey, key, 32U);
    }

private:
    boost::asio::io_context* pio_context;

    unsigned char ProxyKey[32];

    unsigned char encryptedData[1536];
    unsigned char decryptedData[1536];

    size_t uid = 0;

    TrafficType ttype;

    std::string src_ip;
    std::string dst_ip_or_domain;
    size_t upstream_traffic = 0;
    size_t downstream_traffic = 0;
};


