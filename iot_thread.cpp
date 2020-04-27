#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort_Thread"

extern "C" {
#include "iot_threads.h"
}

struct DetachableThread {
    Thread thread;
    IotThreadRoutine_t routine;
    void *argument;
};

static void run_and_suicide(void *arg) {
    auto me = static_cast<DetachableThread*>(arg);
    tr_debug("entering detachable thread");
    me->routine(me->argument);
    tr_debug("exiting detatchable thread");
    delete me;
}

bool Iot_CreateDetachedThread( IotThreadRoutine_t threadRoutine,
                               void * pArgument,
                               int32_t priority,
                               size_t stackSize ) {
    auto t = new DetachableThread {
        {
            osPriorityLow, (stackSize==0)? MBED_CONF_RTOS_THREAD_STACK_SIZE : stackSize, nullptr, "detachable thread" 
        }, threadRoutine, pArgument
    };
    if (t == NULL) {
        return false;
    }
    t->thread.start({run_and_suicide, t});
    return true;
}
