/*
 * Copyright (c) 2021 Nantis GmbH
 * Copyright (c) 2021 Arm Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef AWS_CLIENT_H
#define AWS_CLIENT_H

#include "netsocket/TLSSocket.h"
#include "platform/Callback.h"

extern "C"
{
#include "core_mqtt.h"
#include "core_json.h" // Expose return value enumeration
}

// Undef trace group from AWS SDK logging
#undef TRACE_GROUP

/**
 * @brief Network context declaration.
 *
 * Required by coreMQTT.
 *
 */
struct NetworkContext {
    /**
     * @brief TLS socket underlying the MQTT connection.
     *
     */
    TLSSocket socket;
};

/**
 * @brief AWS IoT client.
 *
 * Currently not thread safe as TLSSocket is not protected.
 *
 */
class AWSClient {
public:
    /**
     * @brief TLS credentials container.
     */
    struct TLSCredentials_t {
        /**
         * @brief Client certificate
         */
        const char *clientCrt;
        /**
         * @brief Buffer size of clientCrt
         */
        size_t clientCrtLen;

        /**
         * @brief Client key
         */
        const char *clientKey;
        /**
         * @brief Buffer size of clientKey
         */
        size_t clientKeyLen;

        /**
         * @brief Main Root CA
         */
        const char *rootCrtMain;
        /**
         * @brief Buffer size of rootCrtMain
         */
        size_t rootCrtMainLen;

        /**
         * @brief Backup Root CA
         */
        const char *rootCrtBackup;
        /**
         * @brief Buffer size of rootCrtBackup
         */
        size_t rootCrtBackupLen;
    };

    /**
     * @brief Get the singleton instance.
     *
     * @return AWSClient instance
     */
    static AWSClient &getInstance()
    {
        static AWSClient instance;
        return instance;
    }

    /**
     * @brief Delete copy constructor and assignment.
     * For singleton pattern.
     */
    AWSClient(AWSClient const &) = delete;
    void operator=(AWSClient const &) = delete;

    /**
     * @brief Initialize the client.
     *
     * Sets the subscription callback.
     * Initializes the SDK.
     * Parses the root CAs and stores them.
     *
     * @param subCallback Subscription callback (topic, payload).
     * @param creds Credentials containing the root CA.
     * @return MBED_SUCCESS on success.
     */
    int init(mbed::Callback<void(std::string, std::string)> subCallback,
             const TLSCredentials_t &creds);

    /**
     * @brief Establish the MQTT connection.
     *
     * Creates a new TLSSocket.
     * Sets endpoint, credentials and timeout of the TLS socket.
     * Opens the socket.
     * Gets the IP address of the AWS endpoint.
     * Connects the socket to the endpoint.
     * Establishes the MQTT connection.
     *
     * @param net The underlying network interface for the socket.
     * @param creds Credentials for TLS.
     * @param hostname AWS IoT endpoint.
     * @param clientID MQTT client ID. Should be same as the thing name.
     * @return MBED_SUCCESS on success.
     */
    int connect(NetworkInterface *net,
                const TLSCredentials_t &creds,
                const std::string hostname,
                const std::string clientID);

    /**
     * @brief Check if the MQTT client is connected.
     *
     * Returns the connectStatus member of the MQTT context.
     *
     * @return true if connected, false if not connected
     */
    bool isConnected();

    /**
     * @brief Disonnect from the MQTT server.
     *
     * Closes the TLS socket.
     *
     * @return MBED_SUCCESS on success.
     */
    int disconnect();

    /**
     * @brief Returns the MQTT context.
     *
     * @return MQTT context.
     */
    MQTTContext_t getMQTTContext();

    /**
     * @brief Returns the thing name.
     *
     * @return Thing name.
     */
    std::string getThingName();

    /**
     * @brief Subscribes to a topic filter.
     *
     * TODO char array variant would be more efficient in some cases
     *
     * @param topicFilter Topic filter.
     * @param qos QoS.
     * @return MBED_SUCCESS on success.
     */
    int subscribe(const std::string topicFilter, const MQTTQoS qos = MQTTQoS0);

    /**
     * @brief Unsubscribes from a topic filter.
     *
     * @param topicFilter Topic filter.
     * @return MBED_SUCCESS on success.
     */
    int unsubscribe(const std::string topicFilter);

    /**
     * @brief Publishes to a topic.
     *
     * @param topic Topic to publish to.
     * @param msg Message to publish.
     * @param qos QoS.
     * @return MBED_SUCCESS on success.
     */
    int publish(const std::string topic, const std::string msg, const MQTTQoS qos = MQTTQoS0);

    /**
     * @brief Processes all of the pending incoming messages.
     *
     * Also handles keepalive.
     * This must be called periodically by the application.
     * Triggers application callback for received subscriptions.
     *
     * @return MBED_SUCCESS on success.
     */
    int processResponses();

    /**
     * @brief Retrieves the device shadow document.
     *
     * The retrieved document is written to the shadowGetResponse member.
     *
     * @return MBED_SUCCESS on success.
     */
    int downloadShadowDocument();

    /**
     * @brief Extracts the desired value of the given key from the retrieved device shadow document.
     *
     * downloadShadowDocument() should be called before this.
     *
     * Tip: use stoi() to convert the value to integer in case an integer is expected.
     *
     * @param key Key of value to retrieve.
     * @param value Desired value extracted from the shadow.
     * @return MBED_SUCCESS on success.
     */
    int getShadowDesiredValue(std::string key, std::string &value);

    /**
     * @brief Publishes an update to the device shadow.
     *
     * @param updateDocument Update document to be published.
     * @return MBED_SUCCESS on success.
     */
    int updateShadowDocument(std::string updateDocument);

    /**
     * @brief Publishes the reported value of the given key to the device shadow.
     *
     * Constructs the update document and calls updateShadowDocument().
     *
     * @param key Key of the value to publish.
     * @param value String to publish. Quotation marks will be added automatically.
     * @return MBED_SUCCESS on success.
     */
    int publishShadowReportedValue(std::string key, std::string value);

    /**
     * @brief Publishes the reported value of the given key to the device shadow.
     *
     * Constructs the update document and calls updateShadowDocument().
     *
     * @param key Key of value to publish.
     * @param value Integer value to publish.
     * @return MBED_SUCCESS on success.
     */
    int publishShadowReportedValue(std::string key, int value);

private:
    /**
     * @brief Construct a new AWSClient object
     */
    AWSClient() {}

    /**
     * @brief MQTT context to store after initialization.
     */
    MQTTContext_t mqttContext;

    /**
     * @brief Network context provided to the SDK.
     */
    NetworkContext_t networkContext;

    /**
     * @brief Network buffer provided to the SDK.
     *
     */
    uint8_t mqttBuffer[MBED_CONF_AWS_CLIENT_BUFFER_SIZE];

    /**
     * @brief Storage for the parsed root certificate.
     */
    mbedtls_x509_crt rootCA;

    /**
     * @brief Response received flag.
     * Used to process all responses at one call until no more remains.
     */
    bool isResponseReceived;

    /**
     * @brief Application callback for subscription events.
     */
    mbed::Callback<void(std::string, std::string)> subCallback;

    /**
     * @brief Static callback to provide to the SDK.
     * Calls the application callback when a response is received
     * for one of our subscriptions.
     * Interface defined by SDK.
     */
    static void eventCallbackStatic(MQTTContext_t *pMqttContext,
                                    MQTTPacketInfo_t *pPacketInfo,
                                    MQTTDeserializedInfo_t *pDeserializedInfo);

    /**
     * @brief Thing name.
     *
     * Should be the same as the MQTT client ID.
     *
     * TODO check memory safety of this (string vs char array)
     */
    std::string thingName;

    bool shadowGetAccepted;

    bool shadowUpdateAccepted;

    /**
     * @brief Buffer for the shadow get response.
     *
     * Gets written by the downloadShadowDocument() function.
     *
     */
    char shadowGetResponse[MBED_CONF_AWS_CLIENT_SHADOW_GET_RESPONSE_MAX_SIZE];
};

#endif /* AWS_CLIENT_H */
