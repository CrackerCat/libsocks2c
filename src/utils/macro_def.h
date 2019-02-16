#pragma once
#ifdef _WIN32
#define likely(x)
#define unlikely(x)
#else
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#endif