#pragma once

#include "../../client_proxy_protocol.h"
#include "../../server_proxy_protocol.h"

#include "aes256gcmwithobf_helper.h"

#include "../../../utils/randomNumberGenerator.h"
#include "../../../utils/logger.h"

#include <cstdint>
#include <string>

#define OBF_THRESHOLD 250
#define OBF_MINPADDLE 250
#define OBF_MAXPADDLE 800


// Example protocol
/*
 * every protocol header should define
 * 1. int Size()
 *      return the sizeof the protocol header
 * 2. unsigned char* GetDataOffsetPtr()
 *      return the pointer pointing to the payload following the protocol header
 *
 * header should be pod
 */
struct aes256gcmwithobf_header {

    unsigned char NONCE[12];
    unsigned char LEN_TAG[16];
    unsigned char PAYLOAD_TAG[16];
    uint32_t PAYLOAD_LENGTH;
    uint32_t PADDING_LENGTH;

    static constexpr int Size()
    {
        return sizeof(aes256gcmwithobf_header);
    }

    unsigned char* GetDataOffsetPtr()
    {
        return NONCE + Size();
    }

};

namespace boost { namespace asio { class io_context; } }



/*
 * Protocol Implementation Here
 *
 * two member must be defined
 *   boost::asio::io_context* pio_context;
 *   unsigned char ProxyKey[32];
 *
 *  we add two buffer here cause the lib could'not en(de)crypt data inplace
 *
 */
struct aes256gcmwithobf_Protocol : public ClientProxyProtocol<aes256gcmwithobf_header>, public ServerProxyProtocol<aes256gcmwithobf_header>
{

    // Ctor template
    aes256gcmwithobf_Protocol(boost::asio::io_context* io = nullptr) : pio_context(io) {}


    /*
     * How we encrypt data
     * 1. encryptPayload
     * 2. (optional) addObfuscation
     * 3. encryptHeaderLen
     *
     */

    // encrypt the payload(the read data), not including padding
    // PAYLOAD_LENGTH is set before calling
    // we get PAYLOAD_TAG after encryption
    void encryptPayload(aes256gcmwithobf_header *header)
    {

        uint64_t tag_len = 0;

        // set NONCE random value
        randombytes_buf(header->NONCE, sizeof(header->NONCE));

        // encrypt data using this NONCE and preset key
        aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                             header->PAYLOAD_LENGTH, encryptedData, &tag_len, header->PAYLOAD_TAG);

        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }


    void addObfuscation(aes256gcmwithobf_header *header)
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


    // encrypt the protocol header
    // return the original len of data + paddle
    uint32_t encryptHeaderLen(aes256gcmwithobf_header *header)
    {

        uint32_t original_len = header->PADDING_LENGTH + header->PAYLOAD_LENGTH;

        unsigned char encrypted_length[8];
        uint64_t tag_len = 0;

        //randombytes_buf(header->NONCE, sizeof(header->NONCE));

        aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, (unsigned char*)&header->PAYLOAD_LENGTH,
                                             sizeof(header->PAYLOAD_LENGTH) + sizeof(header->PADDING_LENGTH), encrypted_length, &tag_len, header->LEN_TAG);

        memcpy(&header->PAYLOAD_LENGTH, encrypted_length, 8);

        return original_len;

    }





    uint64_t OnSocks5RequestSent(aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }


    uint64_t OnPayloadReadFromLocal(aes256gcmwithobf_header *header)
    {


        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }




    uint64_t OnPayloadHeaderReadFromRemote(aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);

    }

    bool OnPayloadReadFromRemote(aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }
















    //  -----   SERVER PART -----

    uint64_t onSocks5RequestHeaderRead(aes256gcmwithobf_header *header, std::string client_ip)
    {
        return decryptHeader(header);
    }


    bool onSocks5RequestPayloadRead(aes256gcmwithobf_header *header) {
        return decryptPayload(header);
    }


    uint64_t onPayloadHeaderReadFromLocal(aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);
    }

    bool onPayloadReadFromLocal(aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }


    uint64_t onPayloadReadFromRemote(aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }




    uint64_t OnUdpPayloadReadFromClientLocal(aes256gcmwithobf_header *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }



    uint64_t OnUdpPayloadReadFromClientRemote(aes256gcmwithobf_header *header)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }



    uint64_t OnUdpPayloadReadFromServerLocal(aes256gcmwithobf_header *header, std::string client_ip)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }



    uint64_t OnUdpPayloadReadFromServerRemote(aes256gcmwithobf_header *header)
    {
        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();
    }


    inline uint64_t decryptHeader(aes256gcmwithobf_header *header)
    {
        struct {
            uint32_t PAYLOAD_LENGTH;
            uint32_t PADDING_LENGTH;
        } len;


        bool res = aes256gcmwithobf_Helper::decryptData(this->ProxyKey, header->NONCE,
                                                               (unsigned char *) &header->PAYLOAD_LENGTH,
                                                               sizeof(header->PAYLOAD_LENGTH) +
                                                               sizeof(header->PADDING_LENGTH), (unsigned char *) &len,
                                                               header->LEN_TAG);

        //LOG_DEBUG("decrypt data length = {}   total length = {} ", len.PAYLOAD_LENGTH, len.TOTAL_LENGTH)

        if (res) {
            memcpy(&header->PAYLOAD_LENGTH, &len, sizeof(len));
            return len.PAYLOAD_LENGTH + len.PADDING_LENGTH;
        }

        return 0;
    }


    inline bool decryptPayload(aes256gcmwithobf_header *header)
    {

        bool res = aes256gcmwithobf_Helper::decryptData(this->ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
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


};


