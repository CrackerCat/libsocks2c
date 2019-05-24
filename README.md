# libsocks2c is a multithreaded socks5 proxy

***Macro***

1. **LOG_DEBUG_DETAIL**     more detail log
2. **DISABLE_DEBUG_LOG**    disable all debug log
3. **UDP_DEBUG_DETAIL**     enable tcp log
3. **TCP_DEBUG_DETAIL**     enable udp log
4. **MULTITHREAD_IO**       will enable multithread support both server and client proxy
5. **BUILD_DLL**			export dll on win32
---

***bUild***
1. by adding option -DENABLE_UOUT=ON, udp over utcp feature will be enabled and it requires some extra libraries

   on Linux or OSX, libtins, libpcap are required
   on Windows, wpcap, WinDivert, tins are required

   check the following list for support info

2. when building lib for mobile platform, you need to add -DBUILD_MOBILE_LIB=ON

   UOUT is not support on mobile platform

---
***Encryption:***

We implement AES256GCM as encryption method


---
***UDP over uTCP***

proxy udp over unordered tcp connection

support list:

| Platform | Server | Client |
| ------ | ------ | ------ |
| OSX | ✘ | ✔ |
| Linux | ✔ | ✔ |
| Win64 | ✘ | ✔ |
| Win32 | ✘ | ✔ |

---
***The following libraries are required***
1. spdlog 1.3.1
2. libsodium 1.0.17
3. libboost_coroutine 1.70.0
4. libboost_context
5. libboost_regex
6. libboost_system

if UDP_OVER_UTCP is defined,
on Linux || OSX you also need
1. libtins v4.2 
2. libpcap 1.9.0
3. libboost_filesystem 1.70.0

on Win64 you need 
1. libtins v4.2 
2. WpdPack 4.1.2
3. WinDivert-1.4.3-A