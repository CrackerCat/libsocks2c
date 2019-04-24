#pragma once

#include "../../basic_protocol/client_proxy_protocol.h"
#include "../../basic_protocol/server_proxy_protocol.h"

#include "chacha20_helper.h"

#include <cstdint>
#include <string>

#include "../../../utils/randomNumberGenerator.h"
#include "../../../utils/logger.h"
#include "../../../net/bufferdef.h"

#define OBF_THRESHOLD 250
#define OBF_MINPADDLE 250
#define OBF_MAXPADDLE 800



struct chacha20_Header{

    unsigned char NONCE[8];
    uint32_t PAYLOAD_LENGTH;
    uint32_t PADDING_LENGTH;
    //data


    static constexpr uint32_t Size()
    {
        return sizeof(chacha20_Header);
    }

    unsigned char* GetDataOffsetPtr()
    {
        return NONCE + Size();
    }
};


struct chacha20_Protocol : virtual public ClientProxyProtocol<chacha20_Header>, virtual public ServerProxyProtocol<chacha20_Header>
{


    virtual uint64_t OnSocks5RequestSent(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }


    virtual uint64_t OnPayloadReadFromLocal(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {


        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();

    }




    virtual uint64_t OnPayloadHeaderReadFromRemote(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header, true);

    }

    virtual bool OnPayloadReadFromRemote(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }




    // We encrypt payload first , then encrypt the data len
    inline void encryptPayload(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {


        randombytes_buf(header->NONCE, sizeof(header->NONCE));

        chacha20_Helper::encryptData(ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                             header->PAYLOAD_LENGTH, encryptedData);

        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }


    inline void addObfuscation(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
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
    inline uint32_t encryptHeaderLen(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {

        uint32_t original_len = header->PADDING_LENGTH + header->PAYLOAD_LENGTH;

        unsigned char encrypted_length[8];

        chacha20_Helper::encryptData(ProxyKey, header->NONCE, (unsigned char*)&header->PAYLOAD_LENGTH,
                                             sizeof(header->PAYLOAD_LENGTH) + sizeof(header->PADDING_LENGTH), encrypted_length);

        memcpy(&header->PAYLOAD_LENGTH, encrypted_length, 8);

        return original_len;

    }





    //  -----   SERVER PART -----

    virtual uint64_t onSocks5RequestHeaderRead(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header) {
        return decryptHeader(header, true);
    }


    virtual bool onSocks5RequestPayloadRead(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header) {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadHeaderReadFromLocal(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {
        return decryptHeader(header, true);
    }

    virtual bool onPayloadReadFromLocal(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {
        return decryptPayload(header);
    }


    virtual uint64_t onPayloadReadFromRemote(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {

        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();

    }

	virtual uint64_t OnUdpPayloadReadFromClientLocal(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
	{

		encryptPayload(header);
		addObfuscation(header);
		uint32_t data_length = encryptHeaderLen(header);

		return data_length + header->Size();

	}



	virtual uint64_t OnUdpPayloadReadFromClientRemote(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
	{
		auto data_len = decryptHeader(header, false);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
	}



	virtual uint64_t OnUdpPayloadReadFromServerLocal(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
	{
		auto data_len = decryptHeader(header, false);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
	}



	virtual uint64_t OnUdpPayloadReadFromServerRemote(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
	{
		encryptPayload(header);
		addObfuscation(header);
		uint32_t data_length = encryptHeaderLen(header);

		return data_length + header->Size();
	}



    inline uint64_t decryptHeader(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header, bool isTcpData)
    {
        struct {
            uint32_t PAYLOAD_LENGTH;
            uint32_t PADDING_LENGTH;
        } len;


        chacha20_Helper::decryptData(ProxyKey, header->NONCE,
                                                        (unsigned char *) &header->PAYLOAD_LENGTH,
                                                        sizeof(header->PAYLOAD_LENGTH) +
                                                        sizeof(header->PADDING_LENGTH), (unsigned char *) &len);

        //LOG_DEBUG("decrypt data length = {}   total length = {} ", len.PAYLOAD_LENGTH, len.TOTAL_LENGTH)

		memcpy(&header->PAYLOAD_LENGTH, &len, sizeof(len));

		if (isTcpData)
		{
			if ((len.PAYLOAD_LENGTH + len.PADDING_LENGTH) > (TCP_BUFFER_SIZE - chacha20_Header::Size())) return 0;
		}
		else
		{
			if ((len.PAYLOAD_LENGTH + len.PADDING_LENGTH) > (UDP_BUFFER_SIZE - chacha20_Header::Size())) return 0;
		}

		return len.PAYLOAD_LENGTH + len.PADDING_LENGTH;

    }


    inline bool decryptPayload(typename IProxyProtocol<chacha20_Header>::ProtocolHeader *header)
    {

        bool res = chacha20_Helper::decryptData(ProxyKey, header->NONCE, header->GetDataOffsetPtr(),
                                                        header->PAYLOAD_LENGTH, decryptedData);


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

    unsigned char encryptedData[2048];
	unsigned char decryptedData[2048];


};



