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
 * header should be a pod
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
 * Protocol Implementation
 *
 * 2 members must be defined
 *   boost::asio::io_context* pio_context;
 *   unsigned char ProxyKey[32];
 *
 * 13 member functions must be defined, half of them are nearly the same
 *
 *   incluing 1 Ctor
 *           4 for client tcp
 *           5 for server tcp
 *           2 for client udp
 *           2 for server udp
 *
 * you can leave server part definition blank if you are building client only and vice versa
 * but you need a server anyway :)
 *
 * we add two buffer here cause the lib could'not en(de)crypt data inplace, this won't be a bottleneck
 *
 * tips: never use shared_ptr if you want to allocate buffer which will cause great performance loss, use unique_ptr instead
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

        // copy back cause it can't encrypt inplace
        memcpy(header->GetDataOffsetPtr(), encryptedData, header->PAYLOAD_LENGTH);

    }

    // add padding at the tail of payload
    void addObfuscation(aes256gcmwithobf_header *header)
    {
        if (header->PAYLOAD_LENGTH > OBF_THRESHOLD)
        {
            header->PADDING_LENGTH = 0;
            return;
        }

        auto paddle_len = RandomNumberGenerator::GetRandomIntegerBetween(OBF_MINPADDLE, OBF_MAXPADDLE);

        randombytes_buf(header->GetDataOffsetPtr() + header->PAYLOAD_LENGTH, paddle_len);

        header->PADDING_LENGTH = (uint32_t)paddle_len;
    }


    // encrypt the protocol header
    // we need to encrypt PAYLOAD_LENGTH && PADDING_LENGTH only cause TAG and NONCE are random values
    // return the (total data len)
    uint32_t encryptHeaderLen(aes256gcmwithobf_header *header)
    {
        uint32_t original_len = header->PADDING_LENGTH + header->PAYLOAD_LENGTH;

        unsigned char encrypted_length[8];
        uint64_t tag_len = 0;

        aes256gcmwithobf_Helper::encryptData(this->ProxyKey, header->NONCE, (unsigned char*)&header->PAYLOAD_LENGTH,
                                             sizeof(header->PAYLOAD_LENGTH) + sizeof(header->PADDING_LENGTH), encrypted_length, &tag_len, header->LEN_TAG);

        memcpy(&header->PAYLOAD_LENGTH, encrypted_length, 8);

        return original_len;
    }


    //  -----   CLIENT PART TCP   -----

    // invoked when the client sending the socks5 request to remote
    // for each connection, OnSocks5RequestSent will only call once
    // return the total length of data to be send
    uint64_t OnSocks5RequestSent(aes256gcmwithobf_header *header)
    {
        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();
    }


    // invoked when the client read data from local and trying to sending it to remote
    // for each connection, OnPayloadReadFromLocal may be called multiple times
    // return the total length of data to be send
    uint64_t OnPayloadReadFromLocal(aes256gcmwithobf_header *header)
    {
        encryptPayload(header);
        addObfuscation(header);

        uint32_t len = encryptHeaderLen(header);

        return len + header->Size();
    }


    /*
     * How we read data from remote
     *  1. read header, get len of the following data
     *  2. read len bytes real data
     */

    // invoked when the client read header from remote
    // return the total length of the following data
    // return 0 if decrypt err
    uint64_t OnPayloadHeaderReadFromRemote(aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);
    }


    // invoked when the client read real data from remote
    // return true if decrypt success,
    // we don't need to return length cause we already know in the last OnPayloadHeaderReadFromRemote return
    // return false if decrypt err
    bool OnPayloadReadFromRemote(aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }


    //  -----   SERVER PART TCP   -----

    // the same as client side,
    uint64_t onSocks5RequestHeaderRead(aes256gcmwithobf_header *header, std::string client_ip)
    {
        return decryptHeader(header);
    }


    // the same as client side
    bool onSocks5RequestPayloadRead(aes256gcmwithobf_header *header) {
        return decryptPayload(header);
    }


    // the same as client side
    uint64_t onPayloadHeaderReadFromLocal(aes256gcmwithobf_header *header)
    {
        return decryptHeader(header);
    }


    // the same as client side
    bool onPayloadReadFromLocal(aes256gcmwithobf_header *header)
    {
        return decryptPayload(header);
    }


    // the same as client side
    uint64_t onPayloadReadFromRemote(aes256gcmwithobf_header *header)
    {
        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();
    }


    //  -----   CLIENT PART UDP   -----

    // invoked when the client read real data from local
    // the same as client side
    uint64_t OnUdpPayloadReadFromClientLocal(aes256gcmwithobf_header *header)
    {
        encryptPayload(header);
        addObfuscation(header);
        uint32_t data_length = encryptHeaderLen(header);

        return data_length + header->Size();
    }


    // invoked when the client read real data from local
    // return the length of real data
    // return 0 if decrypt err
    uint64_t OnUdpPayloadReadFromClientRemote(aes256gcmwithobf_header *header)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }


    //  -----   SERVER PART UDP   -----

    // invoked when the server read real data from local
    // return the length of real data
    // return 0 if decrypt err
    uint64_t OnUdpPayloadReadFromServerLocal(aes256gcmwithobf_header *header, std::string client_ip)
    {
		auto data_len = decryptHeader(header);
		if (data_len == 0) return 0;
		if (decryptPayload(header)) return header->PAYLOAD_LENGTH;
		return 0;
    }


    // invoked when the server read real data from remote
    // return the total length of data to be send
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

    void SetKey(unsigned char key[32U]) {
        memcpy(ProxyKey, key, 32U);
    }

private:

    boost::asio::io_context* pio_context;

    unsigned char ProxyKey[32];

    unsigned char encryptedData[1536];
	unsigned char decryptedData[1536];

};


