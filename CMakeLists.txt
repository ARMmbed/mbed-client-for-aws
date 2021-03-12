# Copyright (c) 2021 Nantis GmbH.
# Copyright (c) 2021 Arm Limited.
# SPDX-License-Identifier: Apache-2.0

# coreMQTT
include(coreMQTT/mqttFilePaths.cmake)

add_library(coreMQTT
    ${MQTT_SOURCES}
    ${MQTT_SERIALIZER_SOURCES} 
)
            
target_include_directories(coreMQTT PUBLIC 
    ${MQTT_INCLUDE_PUBLIC_DIRS} 
    config 
)

target_link_libraries(coreMQTT
    mbed-core
)

# shadow
include(shadow/shadowFilePaths.cmake)

add_library(shadow
    ${SHADOW_SOURCES} 
)

target_include_directories(shadow PUBLIC 
    ${SHADOW_INCLUDE_PUBLIC_DIRS} 
    config
)

target_link_libraries(shadow
    mbed-core
)

# coreJSON
include(coreJSON/jsonFilePaths.cmake)

add_library(coreJSON
    ${JSON_SOURCES}
)

target_include_directories(coreJSON PUBLIC 
    ${JSON_INCLUDE_PUBLIC_DIRS} 
    config
)

target_link_libraries(coreJSON
    mbed-core
)
