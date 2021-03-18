# Mbed client for AWS IoT Core

## Summary

This is an Mbed client for AWS IoT Core, based on implementation contributed by Nantis GmbH ([Nantis-GmbH/mbed-aws-client](https://github.com/Nantis-GmbH/mbed-aws-client)). It depends on [coreMQTT](https://github.com/FreeRTOS/coreMQTT), [coreJSON](https://github.com/FreeRTOS/coreJSON) and [AWS IoT Device Shadow library](https://github.com/aws/Device-Shadow-for-AWS-IoT-embedded-sdk). It can be used to connect devices running Mbed OS to the Azure IoT Hub service, send and receive MQTT messages and work with [the Device Shadow service](https://docs.aws.amazon.com/iot/latest/developerguide/iot-device-shadows.html).

**Note:** This client is _not_ compatible with the old client prior to [5f422c9](https://github.com/ARMmbed/mbed-client-for-aws/commit/5f422c9449e5882855b84a26fb55fcc40edb5e6a). Existing users of the old client can continue to fetch that hash, but we strongly recommend migration to the new client.

To use this library, an Mbed OS application needs to

* connect to a network interface with Internet access
* get the singleton instance of the client: `AWSClient::getInstance()`
* call `init()`, `connect()` with required parameters including cloud credentials, message handler and network interface
* call `processResponses()` periodically, e.g. using a thread
* either: interact with an MQTT topic directly using `subscribe()`, `publish()`
* or: use the Device Shadow API: `downloadShadowDocument()`, `getShadowDesiredValue()`, `publishShadowReportedValue()`

Configurations of this library are listed in [`mbed_lib.json`](./mbed_lib.json) and can be overriden by an application's `mbed_app.json`.

An example demonstrating the use of this library has been provided as part of the official Mbed OS examples [here](https://github.com/ARMmbed/mbed-os-example-for-aws).

## Related links
* [AWS IoT Core](https://aws.amazon.com/iot-core/)
* [Mbed boards](https://os.mbed.com/platforms/)
* [Mbed OS Configuration](https://os.mbed.com/docs/latest/reference/configuration.html).
* [Mbed OS Serial Communication](https://os.mbed.com/docs/latest/tutorials/serial-communication.html).

## License and contributions

The software is provided under Apache-2.0 license. Contributions to this project are accepted under the same license.

The following projects from Amazon (under MIT license) are externally fetched by the build tool:
  * [coreMQTT](https://github.com/FreeRTOS/coreMQTT)
  * [coreJSON](https://github.com/FreeRTOS/coreJSON)
  * [AWS IoT Device Shadow library](https://github.com/aws/Device-Shadow-for-AWS-IoT-embedded-sdk)
