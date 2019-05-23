#pragma once

#ifdef MULTITHREAD_IO
    #if defined(__linux__) || defined(ENABLE_UOUT)
    // on linux
    // we don't need lockfree queue cause -
    // local_socket_ && remote_socket_ share the same context
    //
    // same if we enable ENABLE_UOUT, which runs in single thread
    #include "normal_queue.h"
    #else
    // on mac || win32
    // packet enqueue in local_socket_'s context
    // but it will be dequeue in remote_socket_'s context
    #include "lockfree_queue.h"
    #endif
#else // if running in single thread, we don't need thread safe queue
#include "normal_queue.h"
#endif