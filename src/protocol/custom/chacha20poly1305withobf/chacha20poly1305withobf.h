#pragma once

#include "../../client_proxy_protocol.h"
#include "../../server_proxy_protocol.h"

#include "chacha20poly1305withobf_helper.h"

#include "../../../utils/randomNumberGenerator.h"
#include "../../../utils/logger.h"

#include <cstdint>
#include <string>

#define OBF_THRESHOLD 250
#define OBF_MINPADDLE 250
#define OBF_MAXPADDLE 800



struct chacha20poly1305withobf_Header{

    unsigned char NONCE[8];
    unsigned char LEN_TAG[16];
    unsigned char PAYLOAD_TAG[16];
    uint32_t PAYLOAD_LENGTH;
    uint32_t PADDLE_LENGTH;
    //data

    static constexpr int Size()
    {
        return sizeof(chacha20poly1305withobf_Header);
    }

    unsigned char* GetDataOffsetPtr()
    {
        return NONCE + Size();
    }

};


struct chacha20poly1305withobf_Protocol : virtual public ClientProxyProtocol<chacha20poly1305withobf_Header>, virtual public ServerProxyProtocol<chacha20poly1305withobf_Header>
{


    virtual uint64_t OnSocks5RequestSent(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }


    virtual uint64_t OnPayloadReadFromLocal(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {


        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }




    virtual uint64_t OnPayloadHeaderReadFromRemote(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header);

    }

    virtual bool OnPayloadReadFromRemote(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }

    inline void encryptPayload(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {


        uint64_t tag_len = 0;

        randombytes_buf(header->NONCE, sizeof(header->NONCE));

        chacha20poly1305withobf_Helper::encryptData(ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                                    header->PAYLOAD_LENGTH, encryptedData, &tag_len, header->PAYLOAD_TAG);

        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }


    inline void addObfuscation(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {

        if (header->PAYLOAD_LENGTH > OBF_THRESHOLD)
        {
            header->PADDLE_LENGTH = 0;
            return;
        }

        // data needs obf

        auto paddle_len = RandomNumberGenerator::GetRandomIntegerBetween(OBF_MINPADDLE, OBF_MAXPADDLE);

        randombytes_buf(header->GetDataOffsetPtr() + header->PAYLOAD_LENGTH, paddle_len);

        header->PADDLE_LENGTH = (uint32_t)paddle_len;


    }


    // return the original len of data + paddle
    inline uint32_t encryptHeaderLen(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {

        uint32_t original_len = header->PADDLE_LENGTH + header->PAYLOAD_LENGTH;

        unsigned char encrypted_length[8];
        uint64_t tag_len = 0;

        //randombytes_buf(header->NONCE, sizeof(header->NONCE));

        chacha20poly1305withobf_Helper::encryptData(ProxyKey, header->NONCE, (unsigned char*)&header->PAYLOAD_LENGTH,
                                                    sizeof(header->PAYLOAD_LENGTH) + sizeof(header->PADDLE_LENGTH), encrypted_length, &tag_len, header->LEN_TAG);

        memcpy(&header->PAYLOAD_LENGTH, encrypted_length, 8);

        return original_len;

    }





    //  -----   SERVER PART -----

    virtual uint64_t onSocks5RequestHeaderRead(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header) {
        return decryptHeader(header);
    }


    virtual bool onSocks5RequestPayloadRead(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header) {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadHeaderReadFromLocal(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header);
    }

    virtual bool onPayloadReadFromLocal(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadReadFromRemote(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }

	virtual uint64_t OnUdpPayloadReadFromClientLocal(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
	{

		encryptPayload(header);
		addObfuscation(header);
		uint32_t data_length = encryptHeaderLen(header);

		return data_length + header->Size();

	}



	virtual uint64_t OnUdpPayloadReadFromClientRemote(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
	{
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
	}



	virtual uint64_t OnUdpPayloadReadFromServerLocal(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
	{
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
	}



	virtual uint64_t OnUdpPayloadReadFromServerRemote(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
	{
		encryptPayload(header);
		addObfuscation(header);
		uint32_t data_length = encryptHeaderLen(header);

		return data_length + header->Size();
	}




    inline uint64_t decryptHeader(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {
        struct {
            uint32_t PAYLOAD_LENGTH;
            uint32_t PADDLE_LENGTH;
        } len;


        bool res = chacha20poly1305withobf_Helper::decryptData(ProxyKey, header->NONCE,
                                                               (unsigned char *) &header->PAYLOAD_LENGTH,
                                                               sizeof(header->PAYLOAD_LENGTH) +
                                                               sizeof(header->PADDLE_LENGTH), (unsigned char *) &len,
                                                               header->LEN_TAG);

        //LOG_DEBUG("decrypt data length = {}   total length = {} ", len.PAYLOAD_LENGTH, len.TOTAL_LENGTH)

        if (res) {
            memcpy(&header->PAYLOAD_LENGTH, &len, sizeof(len));
            return len.PAYLOAD_LENGTH + len.PADDLE_LENGTH;
        }

        return 0;
    }


    inline bool decryptPayload(typename IProxyProtocol<chacha20poly1305withobf_Header>::ProtocolHeader *header)
    {

        bool res = chacha20poly1305withobf_Helper::decryptData(ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
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


