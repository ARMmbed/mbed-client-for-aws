#include "platform/Callback.h"
#include "rtos/Thread.h"

#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort_Thread"

extern "C" {
#include "iot_threads.h"
}

/**
 * Detached thread with context and arguments
 *
 * @note This class should only be created dynamically! It calls `delete this`
 */
class AWSDetachedThread
{
public:

    AWSDetachedThread(IotThreadRoutine_t routine, void * arg,
            int32_t priority, size_t stack_size) : _routine(routine),
            _arg(arg),
            _thread(osPriorityLow,
                   (stack_size == 0)? MBED_CONF_RTOS_THREAD_STACK_SIZE : stack_size,
                    nullptr, "detachable thread") {
    }

    void start(void) {
        _thread.start(mbed::callback(this, &AWSDetachedThread::thread_main));
    }

protected:

    /**
     * Main for this AWSDetachedThread
     */
    void thread_main(void) {
        tr_debug("entering detachable thread");
        _routine(_arg);
        tr_debug("exiting detatchable thread");
        delete this;
    }

protected:

    IotThreadRoutine_t _routine;
    void * _arg;

    rtos::Thread _thread;
};

bool Iot_CreateDetachedThread( IotThreadRoutine_t threadRoutine,
                               void * pArgument,
                               int32_t priority,
                               size_t stackSize ) {
    auto thread = new AWSDetachedThread(threadRoutine, pArgument, priority, stackSize);
    thread->start();

    return true;
}
