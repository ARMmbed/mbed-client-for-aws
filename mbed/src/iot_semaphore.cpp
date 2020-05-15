#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort"

extern "C" {
#include "iot_threads.h"
}

struct SystemSemaphore {
    osSemaphoreId_t   m_id;
    mbed_rtos_storage_semaphore_t m_obj;

    SystemSemaphore(uint32_t initial, uint32_t max) {
        osSemaphoreAttr_t attr = { 0 };
        attr.cb_mem = &m_obj;
        attr.cb_size = sizeof(m_obj);

        m_id = osSemaphoreNew(max, initial, &attr);
        assert(m_id != nullptr);
    }

    ~SystemSemaphore() {
        osSemaphoreDelete(m_id);
    }
};

bool IotSemaphore_Create(IotSemaphore_t * pNewSemaphore, uint32_t initialValue, uint32_t maxValue ) {
    *pNewSemaphore = new SystemSemaphore { initialValue, maxValue };
    return true;
}

uint32_t IotSemaphore_GetCount(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    return osSemaphoreGetCount(sys_sem->m_id);
}
void IotSemaphore_Wait(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    osSemaphoreAcquire(sys_sem->m_id, osWaitForever);
}
bool IotSemaphore_TimedWait(IotSemaphore_t * pSemaphore, uint32_t timeoutMs)
{
    auto sys_sem = *pSemaphore;
    return osSemaphoreAcquire(sys_sem->m_id, timeoutMs) == osOK;
}
void IotSemaphore_Post(IotSemaphore_t * pSemaphore)
{
    auto sys_sem = *pSemaphore;
    osSemaphoreRelease(sys_sem->m_id);
}

void IotSemaphore_Destroy(IotSemaphore_t * pSemaphore) {
    delete *pSemaphore;
    *pSemaphore = nullptr;
}
