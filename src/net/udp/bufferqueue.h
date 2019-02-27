#pragma once

#ifdef MULTITHREAD_IO
    #ifdef __linux__
    #include "normal_queue.h"
    #else
    #include "lockfree_queue.h"
    #endif
#else
#include "normal_queue.h"
#endif