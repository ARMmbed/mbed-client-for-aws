# Copyright (c) 2020 ARM Limited. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

add_library(mbed-client-for-aws INTERFACE)

target_include_directories(mbed-client-for-aws
    INTERFACE
        .
        mbed/include
        tinycbor/src
        aws-iot-device-sdk-embedded-c/ports/common/include/atomic
        aws-iot-device-sdk-embedded-c/ports/common/include
        aws-iot-device-sdk-embedded-c/libraries/aws/common/include
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/include/types
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/include
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/private
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/include/types
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/include
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/private
        aws-iot-device-sdk-embedded-c/libraries
        aws-iot-device-sdk-embedded-c/libraries/platform
        aws-iot-device-sdk-embedded-c/libraries/standard/common/include
        aws-iot-device-sdk-embedded-c/libraries/standard/common/include/types
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/private
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/include
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/include/types
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/private
        aws-iot-device-sdk-embedded-c/libraries/standard/serializer/include
)

target_sources(mbed-client-for-aws
    INTERFACE
        mbed/src/iot_thread.cpp
        mbed/src/iot_semaphore.cpp
        mbed/src/iot_network.cpp
        mbed/src/iot_mutex.cpp
        mbed/src/iot_clock.cpp
        tinycbor/src/cborencoder.c
        tinycbor/src/cborvalidation.c
        tinycbor/src/cborpretty.c
        tinycbor/src/cborparser_dup_string.c
        tinycbor/src/cborparser.c
        tinycbor/src/cborerrorstrings.c
        tinycbor/src/cborencoder_close_container_checked.c
        aws-iot-device-sdk-embedded-c/libraries/aws/common/src/aws_iot_validate.c
        aws-iot-device-sdk-embedded-c/libraries/aws/common/src/aws_iot_subscription.c
        aws-iot-device-sdk-embedded-c/libraries/aws/common/src/aws_iot_parser.c
        aws-iot-device-sdk-embedded-c/libraries/aws/common/src/aws_iot_operation.c
        aws-iot-device-sdk-embedded-c/libraries/aws/common/src/aws_iot_doc_parser.c
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/aws_iot_jobs_api.c
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/aws_iot_jobs_subscription.c
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/aws_iot_jobs_static_memory.c
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/aws_iot_jobs_serialize.c
        aws-iot-device-sdk-embedded-c/libraries/aws/jobs/src/aws_iot_jobs_operation.c
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/aws_iot_shadow_subscription.c
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/aws_iot_shadow_static_memory.c
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/aws_iot_shadow_parser.c
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/aws_iot_shadow_operation.c
        aws-iot-device-sdk-embedded-c/libraries/aws/shadow/src/aws_iot_shadow_api.c
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/iot_init.c
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/iot_taskpool_static_memory.c
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/iot_taskpool.c
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/iot_static_memory_common.c
        aws-iot-device-sdk-embedded-c/libraries/standard/common/src/iot_logging.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_serialize.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_operation.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_network.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_lightweight_api.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_helper.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_api.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_validate.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_subscription.c
        aws-iot-device-sdk-embedded-c/libraries/standard/mqtt/src/iot_mqtt_static_memory.c
        aws-iot-device-sdk-embedded-c/libraries/standard/serializer/src/cbor/iot_serializer_tinycbor_decoder.c
        aws-iot-device-sdk-embedded-c/libraries/standard/serializer/src/cbor/iot_serializer_tinycbor_encoder.c
        aws-iot-device-sdk-embedded-c/libraries/standard/serializer/src/iot_serializer_static_memory.c
)

