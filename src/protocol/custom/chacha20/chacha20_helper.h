#pragma once

#include <sodium.h>

#define IN
#define OUT
class chacha20_Helper {

public:



    /*
     *  -- crypto_stream_chacha20_KEYBYTES 32U
     *  -- crypto_stream_chacha20_NONCEBYTES 8U
     */
    static void encryptData(unsigned char key[crypto_aead_aes256gcm_KEYBYTES], unsigned char nonce[crypto_stream_chacha20_NONCEBYTES],
                            IN unsigned char *original_data, IN uint64_t original_data_length, OUT unsigned char *encrypted_data)
    {


        crypto_stream_chacha20_xor(encrypted_data,original_data,original_data_length,nonce,key);


    }




    /*
     *  -- crypto_stream_chacha20_KEYBYTES 32U
     *  -- crypto_stream_chacha20_NONCEBYTES 8U
     */
    static bool decryptData(unsigned char key[crypto_aead_aes256gcm_KEYBYTES], unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES],
                            IN unsigned char *encrypted_data, IN uint64_t encrypted_data_length, OUT unsigned char *decrypted_data)
    {

        crypto_stream_chacha20_xor(decrypted_data,encrypted_data,encrypted_data_length,nonce,key);


        return true;

    }





};


