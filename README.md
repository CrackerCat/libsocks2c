# libsocks2c is a socks5 proxy with multithread

##Build macro:

1. **LOG_DEBUG_DETAIL**     more detail log
2. **DISABLE_DEBUG_LOG**    disable all debug log
3. **UDP_DEBUG_DETAIL**     enable tcp log
3. **TCP_DEBUG_DETAIL**     enable udp log
4. **MULTITHREAD_IO**       will enable multithread support both server and client proxy

###Encryption: 
There are three enctyption methods avaliable

1. **PROTOCOL_CHACHA20**
2. **PROTOCOL_CHACHA20POLY1305**
3. **PROTOCOL_AES256GCM**

define one before build

---
***The following libraries are required***
1. spdlog 1.3.1
2. libsodium 1.0.17
3. libboost_coroutine 
4. libboost_context 
5. libboost_regex 
6. libboost_system 
