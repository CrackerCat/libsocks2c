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



struct aes256gcmwithobf_Header{

    unsigned char NONCE[12];
    unsigned char LEN_TAG[16];
    unsigned char PAYLOAD_TAG[16];
    uint32_t PAYLOAD_LENGTH;
    uint32_t PADDING_LENGTH;
    //data

    static constexpr int Size()
    {
        return sizeof(aes256gcmwithobf_Header);
    }

    unsigned char* GetDataOffsetPtr()
    {
        return NONCE + Size();
    }

};


struct aes256gcmwithobf_Protocol : virtual public ClientProxyProtocol<aes256gcmwithobf_Header>, virtual public ServerProxyProtocol<aes256gcmwithobf_Header>
{


    virtual uint64_t OnSocks5RequestSent(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }


    virtual uint64_t OnPayloadReadFromLocal(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {


        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }




    virtual uint64_t OnPayloadHeaderReadFromRemote(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header);

    }

    virtual bool OnPayloadReadFromRemote(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }




    // We encrypt payload first , then encrypt the data len
    inline void encryptPayload(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {

        uint64_t tag_len = 0;

        randombytes_buf(header->NONCE, sizeof(header->NONCE));

        aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                                    header->PAYLOAD_LENGTH, encryptedData, &tag_len, header->PAYLOAD_TAG);

        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }


    inline void addObfuscation(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
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
    inline uint32_t encryptHeaderLen(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
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





    //  -----   SERVER PART -----

    virtual uint64_t onSocks5RequestHeaderRead(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header) {
        return decryptHeader(header);
    }


    virtual bool onSocks5RequestPayloadRead(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header) {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadHeaderReadFromLocal(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header);
    }

    virtual bool onPayloadReadFromLocal(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadReadFromRemote(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }




    virtual uint64_t OnUdpPayloadReadFromClientLocal(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }



    virtual uint64_t OnUdpPayloadReadFromClientRemote(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }



    virtual uint64_t OnUdpPayloadReadFromServerLocal(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }



    virtual uint64_t OnUdpPayloadReadFromServerRemote(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
    {
        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();
    }


    inline uint64_t decryptHeader(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
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


    inline bool decryptPayload(typename IProxyProtocol<aes256gcmwithobf_Header>::ProtocolHeader *header)
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
    virtual void SetKey(unsigned char key[32U]) {
        memcpy(ProxyKey, key, 32U);
    }


private:

    unsigned char ProxyKey[32];

    unsigned char encryptedData[1536];
	unsigned char decryptedData[1536];


};


