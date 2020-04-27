#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort"

extern "C" {
#include "iot_threads.h"
}

struct SystemSemaphore {
    Semaphore   sem;
    volatile uint16_t count;
};

bool IotSemaphore_Create(IotSemaphore_t * pNewSemaphore, uint32_t initialValue, uint32_t maxValue ) {
    if (initialValue > UINT16_MAX) {
        tr_error("Sem: initial value out of range 0 <= %lu <= UINT16_MAX", initialValue);
        return false;
    }
    if (maxValue > UINT16_MAX) {
        tr_error("Sem: max value out of range 0 <= %lu <= UINT16_MAX", maxValue);
        return false;
    }
    auto sys_sem = new SystemSemaphore { {(uint16_t)initialValue, (uint16_t)maxValue}, (uint16_t)initialValue};
    if (sys_sem == NULL) {
        tr_error("Sem: Allocation failure");
        return false;
    }
    
    *pNewSemaphore = sys_sem;
    return true;
}

uint32_t IotSemaphore_GetCount(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    return core_util_atomic_load_u16(&sys_sem->count);
}
void IotSemaphore_Wait(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    sys_sem->sem.acquire();
    core_util_atomic_decr_u16(&sys_sem->count, 1);
}
bool IotSemaphore_TimedWait(IotSemaphore_t * pSemaphore, uint32_t timeoutMs)
{
    auto sys_sem = *pSemaphore;
    auto res = sys_sem->sem.try_acquire_for(timeoutMs);
    if (res) {
        core_util_atomic_decr_u16(&sys_sem->count, 1);
    }
    return res;
}
void IotSemaphore_Post(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    core_util_atomic_incr_u16(&sys_sem->count, 1);
    sys_sem->sem.release();
}

void IotSemaphore_Destroy(IotSemaphore_t * pSemaphore) {
    delete *pSemaphore;
    *pSemaphore = nullptr;
}
