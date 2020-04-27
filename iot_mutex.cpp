#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort"

extern "C" {
#include "iot_threads.h"
}

struct SystemMutex {
    Mutex       mutex;
    bool        recursive;
    volatile uint32_t depth; // we probably want an atomic bool of some sort here.
};

bool IotMutex_Create(IotMutex_t *pNewMutex, bool recursive) {
    auto sys_mut = new SystemMutex { {}, recursive, 0 };
    if (sys_mut == nullptr) {
        return false;
    }
    *pNewMutex = sys_mut;
    return true;
}
void IotMutex_Lock(IotMutex_t *pMutex) {
    auto sys_mut = *pMutex;
    sys_mut->mutex.lock();
    if (sys_mut->recursive) {
        sys_mut->depth += 1;
    }
}
bool IotMutex_TryLock(IotMutex_t *pMutex) {
    auto sys_mut = *pMutex;
    auto res = sys_mut->mutex.trylock();
    if (res) {
        if (sys_mut->recursive) {
            sys_mut->depth += 1;
        }
    }
    return res;
}
void IotMutex_Unlock(IotMutex_t *pMutex) {
    auto sys_mut = *pMutex;
    if (sys_mut->recursive) {
        assert(sys_mut->depth >= 1);
        sys_mut->depth -= 1;
    }
    sys_mut->mutex.unlock();
}
void IotMutex_Destroy(IotMutex_t * pMutex) {
    delete *pMutex;
    *pMutex = nullptr;
}
