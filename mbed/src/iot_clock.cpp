/*
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSClock"

extern "C"
{
#include "iot_clock.h"
}

struct SystemTimer {
    Event<void(void *)> event;
    void *argument;
};

uint64_t IotClock_GetTimeMs(void)
{
    return Kernel::Clock::now().time_since_epoch().count();
}

bool IotClock_GetTimestring(char *pBuffer, size_t bufferSize, size_t *pTimestringLength)
{
    auto now = time(NULL);
    auto length = strftime(pBuffer, bufferSize, "%d %b %Y %H:%M", localtime(&now));
    if (pTimestringLength != NULL) {
        *pTimestringLength = length;
    }
    return (bufferSize >= length);
}

bool IotClock_TimerCreate(IotTimer_t *pNewTimer, IotThreadRoutine_t expirationRoutine, void *pArgument)
{
    // Use the shared event queue
    *pNewTimer = new SystemTimer{{mbed_event_queue(), expirationRoutine}, pArgument};

    if (*pNewTimer == NULL) {
        tr_error("Timer create failed.");
        return false;
    }

    return true;
}

bool IotClock_TimerArm(IotTimer_t *pTimer, uint32_t relativeTimeoutMs, uint32_t periodMs)
{
    auto timer = *pTimer;
    if (timer == NULL) {
        return false;
    }

    // Set initial delay
    timer->event.delay(std::chrono::milliseconds(relativeTimeoutMs));

    // Set period
    if (periodMs > 0) {
        timer->event.period(std::chrono::milliseconds(periodMs));
    } else {
        // API to disable the periodic call does not exist. Setting to the initial value (-1).
        timer->event.period(std::chrono::milliseconds(-1));
    }

    auto ret = timer->event.post(timer->argument);
    if (ret == 0) {
        tr_error("Post event failed, probably out of memory.");
        return false;
    }

    return true;
}

void IotClock_TimerDestroy(IotTimer_t *pTimer)
{
    auto timer = *pTimer;
    timer->event.cancel();
    delete timer;
}