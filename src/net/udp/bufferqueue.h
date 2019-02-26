#pragma once

#ifdef MULTITHREAD_IO
#include "lockfree_queue.h"
#else
#include "normal_queue.h"
#endif