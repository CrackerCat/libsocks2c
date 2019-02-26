#pragma once

#ifdef MULTITHREAD_IO
#include "lockfree_queue"
#else
#include "normal_queue.h"
#endif