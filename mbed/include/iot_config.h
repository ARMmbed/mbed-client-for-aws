/*
 * Copyright (C) 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* This file contains configuration settings for the demos. */

#ifndef IOT_CONFIG_H_
#define IOT_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Enable asserts in the libraries. */
#define IOT_CONTAINERS_ENABLE_ASSERTS           ( 1 )
#define IOT_MQTT_ENABLE_ASSERTS                 ( 1 )
#define IOT_SERIALIZER_ENABLE_ASSERTS           ( 1 )
#define IOT_TASKPOOL_ENABLE_ASSERTS             ( 1 )
#define AWS_IOT_DEFENDER_ENABLE_ASSERTS         ( 1 )
#define AWS_IOT_JOBS_ENABLE_ASSERTS             ( 1 )
#define AWS_IOT_SHADOW_ENABLE_ASSERTS           ( 1 )

/* Default assert and memory allocation functions. */
#include <assert.h>
#include <stdlib.h>

#define Iot_DefaultAssert    assert
#define Iot_DefaultMalloc    malloc
#define Iot_DefaultFree      free

#ifdef IotLogging_Puts
    void IotLogging_Puts(const char *);
#endif

/* The build system will choose the appropriate system types file for the platform
 * layer based on the host operating system. */
#include "iot_platform_types_mbed_os.h"

#ifdef __cplusplus
#include "iot_network.h"
}

namespace aws {
    const IotNetworkInterface_t *get_iot_network_interface();
}
#endif

#endif /* ifndef IOT_CONFIG_H_ */
