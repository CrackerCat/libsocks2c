# libsocks2c is a multithreaded socks5 proxy

#Macro:

1. **LOG_DEBUG_DETAIL**     more detail log
2. **DISABLE_DEBUG_LOG**    disable all debug log
3. **UDP_DEBUG_DETAIL**     enable tcp log
3. **TCP_DEBUG_DETAIL**     enable udp log
4. **MULTITHREAD_IO**       will enable multithread support both server and client proxy
5. **BUILD_DLL**			export dll on win32
6. **UDP_OVER_UTCP**        build with utcp support
---

#Encryption:

There are three enctyption methods avaliable

1. **PROTOCOL_CHACHA20**
2. **PROTOCOL_CHACHA20POLY1305**
3. **PROTOCOL_AES256GCM**

define one before build

---
***UDP over uTCP***

proxy udp over unordered tcp connection

support list:

| Platform | Server | Client |
| ------ | ------ | ------ |
| OSX | ✔ | ✔ |
| Linux | ✔ | ✔ |
| Win64 | ✘ | ✔ |
| Win32 | ✘ | ✘ |

---
***The following libraries are required***
1. spdlog 1.3.1
2. libsodium 1.0.17
3. libboost_coroutine 
4. libboost_context 
5. libboost_regex 
6. libboost_system

if UDP_OVER_UTCP is defined,
on Linux || OSX you also need
1. libtins v4.2 
2. libpcap 1.9.0

on Win64 you need 
1. libtins v4.2 
2. WpdPack 4.1.2
