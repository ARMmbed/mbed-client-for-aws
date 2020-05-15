#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort_Thread"

extern "C" {
#include "iot_threads.h"
}

bool Iot_CreateDetachedThread( IotThreadRoutine_t threadRoutine,
                               void * pArgument,
                               int32_t priority,
                               size_t stackSize ) {
    auto thread = new Thread {
        osPriorityLow,
        (stackSize==0)? MBED_CONF_RTOS_THREAD_STACK_SIZE : stackSize,
        nullptr,
        "detachable thread"
    };
    thread->start([=] {
        tr_debug("entering detachable thread");
        threadRoutine(pArgument);
        tr_debug("exiting detatchable thread");
        delete thread;
    });

    return true;
}
