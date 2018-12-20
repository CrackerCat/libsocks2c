#pragma once

#ifdef PROTOCOL_AES256GCM
#include "custom/aes256gcmwithobf/aes256gcmwithobf.h"
#elif  PROTOCOL_CHACHA20POLY1305
#include "custom/chacha20poly1305withobf/chacha20poly1305withobf.h"
#define Protocol chacha20poly1305withobf_Protocol
#elif  PROTOCOL_CHACHA20
#include "custom/chacha20/chacha20.h"
#define Protocol chacha20_Protocol
#endif