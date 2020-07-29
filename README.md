# AWS Mbed OS SDK port library

This library provides the port of the AWS IoT SDK for Mbed OS. It can be used to connect devices running Mbed OS to the AWS IoT Core service over MQTT.

An example demonstrating the use of this library has been provided as part of the official Mbed OS examples [here](https://github.com/ARMmbed/mbed-os-example-aws.git).

## Summary:

1. This library depends on:
   1. AWS IoT device embedded-C SDK available [here](https://github.com/aws/aws-iot-device-sdk-embedded-C).
   1. tinycbor library available [here](https://github.com/intel/tinycbor.git\#755f9ef932f9830a63a712fd2ac971d838b131f1).
1. This SDK port follows the steps listed in AWS' developer guide found [here](https://docs.aws.amazon.com/freertos/latest/lib-ref/c-sdk/main/guide_developer.html).
1. The "Config header" and the "Platform Types" requirements can be found in the library under [`mbed/include/`](./mbed/include)
1. The "Platform layer" port can be found under [`mbed/src/`](./mbed/src) . As a minimum, a system clock, mutex, semaphore, network implementation and an optional thread implementation are required. More details on this are provided [here](https://docs.aws.amazon.com/freertos/latest/lib-ref/c-sdk/platform/index.html#platform). The thread implementation is optional and needed for synchronization between threads while using traces for debug messages.

## Note on the IoT Defender service

For now, the [IoT Defender](https://docs.aws.amazon.com/iot/latest/developerguide/device-defender.html) service is disabled in this port library. If you need to enable it for your project:

* Open [.mbedignore](./.mbedignore) and change

   ```diff
   -aws-iot-device-sdk-embedded-c/libraries/aws/defender/*
   +aws-iot-device-sdk-embedded-c/libraries/aws/defender/test/*
   ```

* Implement `IotClock_SleepMs`, `IotSemaphore_TryWait` and `IotMetrics_GetTcpConnections` in your application, as the Defender module depends on them. For their API requirements, search for them in the source code of [aws-iot-device-sdk-embedded-c](https://github.com/aws/aws-iot-device-sdk-embedded-C)

## Related Links

* [Mbed OS Stats API](https://os.mbed.com/docs/latest/apis/mbed-statistics.html).
* [Mbed OS Configuration](https://os.mbed.com/docs/latest/reference/configuration.html).
* [Mbed OS Serial Communication](https://os.mbed.com/docs/latest/tutorials/serial-communication.html).
* [Mbed OS bare metal](https://os.mbed.com/docs/mbed-os/latest/reference/mbed-os-bare-metal.html).
* [Mbed boards](https://os.mbed.com/platforms/).
* [AWS IoT Core](https://aws.amazon.com/fr/iot-core/)
* [AWS IoT Core - Embedded C SDK](https://github.com/aws/aws-iot-device-sdk-embedded-C/tree/v4_beta)

### License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license.

This project contains code from other projects. The original license text is included in those source files. They must comply with our license guide.
