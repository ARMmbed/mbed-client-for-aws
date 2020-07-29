/*
 * Copyright (c) 2020 Arm Limited
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort"

extern "C" {
#include "iot_threads.h"
}

struct SystemMutex {
    Mutex       mutex;
    bool        recursive;

    void check_recursiveness() {
        if (!recursive && mutex.get_owner() == ThisThread::get_id()) {
            error("locking a non recusive mutex.");
        }
    }
};

bool IotMutex_Create(IotMutex_t *pNewMutex, bool recursive) {
    *pNewMutex = new SystemMutex { {}, recursive };
    return true;
}
void IotMutex_Lock(IotMutex_t *pMutex) {
    auto sys_mut = *pMutex;
    sys_mut->check_recursiveness();
    sys_mut->mutex.lock();
}
bool IotMutex_TryLock(IotMutex_t *pMutex) {
    auto sys_mut = *pMutex;
    auto res = sys_mut->mutex.trylock();
    if (res) {
        sys_mut->check_recursiveness();
    }
    return res;
}
void IotMutex_Unlock(IotMutex_t *pMutex) {
    (*pMutex)->mutex.unlock();
}
void IotMutex_Destroy(IotMutex_t * pMutex) {
    delete *pMutex;
    *pMutex = nullptr;
}
