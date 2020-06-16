#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSClock"

extern "C" {
#include "iot_clock.h"
#include "iot_threads.h"
}

struct SystemTimer {
    Thread  thread;
    void (*routine)(void*);
    void *routineArgument;
    uint32_t first_period;
    uint32_t period;

    void thread_routine() {
        ThisThread::sleep_for(first_period);
        while (true) {
            routine(routineArgument);
            if (period == 0) { break; }
            ThisThread::sleep_for(period);
        }
        tr_debug("closing thread");
    }
};

uint64_t IotClock_GetTimeMs(void) {
    return rtos::Kernel::get_ms_count();
}

bool IotClock_GetTimestring(char * pBuffer, size_t bufferSize, size_t * pTimestringLength) {
    auto now = time(NULL);
    auto length = strftime(pBuffer, bufferSize, "%d %b %Y %H:%M", localtime(&now));
    if (pTimestringLength != NULL) {
        *pTimestringLength = length;
    }
    return (bufferSize >= length);
}

bool IotClock_TimerCreate(IotTimer_t * pNewTimer, IotThreadRoutine_t expirationRoutine, void * pArgument ) {
    *pNewTimer = new SystemTimer { { osPriorityNormal, OS_STACK_SIZE, nullptr, "AwsPortTimer" }, expirationRoutine, pArgument, 0, false };
    return true;
}

bool IotClock_TimerArm(IotTimer_t * pTimer, uint32_t relativeTimeoutMs, uint32_t periodMs) {

    auto timer = *pTimer;
    timer->first_period = relativeTimeoutMs;
    timer->period = periodMs;
    if (timer->thread.get_state() == Thread::State::Deleted) {
        timer->thread.start({timer, &SystemTimer::thread_routine});
    }

    return true;
}

void IotClock_TimerDestroy(IotTimer_t * pTimer) {
    delete *pTimer;
    *pTimer = nullptr;
}
