# Copyright (c) 2021 Nantis GmbH.
# Copyright (c) 2021 Arm Limited.
# SPDX-License-Identifier: Apache-2.0

# coreMQTT
include(coreMQTT/mqttFilePaths.cmake)

add_library(coreMQTT INTERFACE)

target_include_directories(coreMQTT
    INTERFACE
        ${MQTT_INCLUDE_PUBLIC_DIRS}
        source/config
)

target_sources(coreMQTT
    INTERFACE
        ${MQTT_SOURCES}
        ${MQTT_SERIALIZER_SOURCES}
)

# Device-Shadow-for-AWS-IoT-embedded-sdk
include(Device-Shadow-for-AWS-IoT-embedded-sdk/shadowFilePaths.cmake)

add_library(Device-Shadow-for-AWS-IoT-embedded-sdk INTERFACE)

target_include_directories(Device-Shadow-for-AWS-IoT-embedded-sdk
    INTERFACE
        ${SHADOW_INCLUDE_PUBLIC_DIRS}
        source/config
)

target_sources(Device-Shadow-for-AWS-IoT-embedded-sdk
    INTERFACE
        ${SHADOW_SOURCES}
)

# coreJSON
include(coreJSON/jsonFilePaths.cmake)

add_library(coreJSON INTERFACE)

target_include_directories(coreJSON
    INTERFACE
        ${JSON_INCLUDE_PUBLIC_DIRS}
        source/config
)

target_sources(coreJSON
    INTERFACE
        ${JSON_SOURCES}
)

# mbed-client-for-aws

add_library(mbed-client-for-aws INTERFACE)

target_include_directories(mbed-client-for-aws
    INTERFACE
        include
        include/AWSClient
)

target_sources(mbed-client-for-aws
    INTERFACE
        source/AWSClient.cpp
)

target_link_libraries(mbed-client-for-aws
    INTERFACE
        coreMQTT
        coreJSON
        Device-Shadow-for-AWS-IoT-embedded-sdk
        mbed-os
        mbed-netsocket
)
