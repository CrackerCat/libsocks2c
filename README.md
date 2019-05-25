# libsocks2c is a multithreaded socks5 proxy lib building client

***Macro***

1. **LOG_DEBUG_DETAIL**     more detail log
2. **DISABLE_DEBUG_LOG**    disable all debug log
3. **UDP_DEBUG_DETAIL**     enable tcp log
3. **TCP_DEBUG_DETAIL**     enable udp log
4. **MULTITHREAD_IO**       enable multithread support
5. **BUILD_DLL**			export dll, by default only static lib is compiled
---

***bUild***
1. by adding option ```-DENABLE_UOUT=ON```, udp over utcp feature will be enabled and it requires some extra libraries

   on Linux or OSX, ```libtins```, ```libpcap``` are required \
   on Windows, ```wpcap```, ```WinDivert```, ```tins``` are required

   check the following list for support info

2. when building lib for mobile platform, you need to add ```-DBUILD_MOBILE_LIB=ON```

   <b>UOUT is not support on mobile platform</b>

---
***Encryption:***

the encryption method ```AES-256-GCM``` provided by libsodium

---
***UDP over uTCP***

proxy udp over unordered tcp connection

what it basically does is wrapping your udp packet with tcp header and send it via a tcp connection which doesn't have retransmission and initiative congestion control

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


#### Startup Config
1. ```udp_over_utcp``` enable <b>UDP over uTCP</b> feature, the udp packet will be proxy via unordered tcp connection.

2. ```local_uout_ifname``` On <b>Linux or Mac</b> you have to specified the name of default network interface for sending packet. 

3. ```local_uout_ip``` if it is set to "" or left blank, it would try to fetch the ip of default network interface on startup, if it retrives the wrong ip, the uout connection would be unable to establish, you might set an ip to override. 

4. ```server_uout_port``` the <b>Port</b> for uout connection. 

5. ```dnsuout``` whether to proxy <b>dns packet</b> via utcp, it just simply check if the dst port is 53, we are not doing any packet inspection

#### Misc

1. ```resolve_dns``` if set true, it will resolve dns locally instead of sending domain proxy request, udp proxy doesn't support domain resolve

1. ```logtofile``` set true to write log to file at the current directory