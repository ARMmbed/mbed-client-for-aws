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

#include "AWSClient.h"
#include "mbed_trace.h"
#include "mbed_error.h"

extern "C"
{
#include "shadow.h"
}

// Undef trace group from AWS SDK logging
#undef TRACE_GROUP
#define TRACE_GROUP "AWSClient"

using namespace std;
using namespace mbed;

/**
 * @brief Network send port function.
 *
 * Interface defined by SDK.
 */
static int32_t Mbed_Send(NetworkContext_t *pNetworkContext, const void *pBuffer, size_t bytesToSend)
{
    auto ret = pNetworkContext->socket.send(pBuffer, bytesToSend);

    return ret;
}

/**
 * @brief Network receive port function.
 *
 * Interface defined by SDK.
 */
static int32_t Mbed_Recv(NetworkContext_t *pNetworkContext, void *pBuffer, size_t bytesToRecv)
{
    auto ret = pNetworkContext->socket.recv(pBuffer, bytesToRecv);

    if (ret == NSAPI_ERROR_WOULD_BLOCK) {
        // Timed out without reading any bytes
        ret = 0;
    }

    // Bytes received
    return ret;
}

/**
 * @brief Time port function.
 *
 * Interface defined by SDK.
 */
static uint32_t Mbed_GetTimeMs(void)
{
    return rtos::Kernel::Clock::now().time_since_epoch().count();
}

void AWSClient::eventCallbackStatic(MQTTContext_t *pMqttContext,
                                    MQTTPacketInfo_t *pPacketInfo,
                                    MQTTDeserializedInfo_t *pDeserializedInfo)
{
    // TODO error handling

    MBED_ASSERT(pMqttContext != NULL);
    MBED_ASSERT(pPacketInfo != NULL);

    auto &awsClient = AWSClient::getInstance();

    // Set response received flag to true,
    // so that processResponses() can request for more.
    awsClient.isResponseReceived = true;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if ((pPacketInfo->type & 0xF0U) == MQTT_PACKET_TYPE_PUBLISH) {
        MBED_ASSERT(pDeserializedInfo->pPublishInfo != NULL);
        MQTTPublishInfo_t *pPublishInfo = pDeserializedInfo->pPublishInfo;

        /* Let the Device Shadow library tell us whether this is a device shadow message. */
        ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
        const char *pThingName = NULL;
        uint16_t thingNameLength = 0U;

        if (SHADOW_SUCCESS == Shadow_MatchTopic(pPublishInfo->pTopicName,
                                                pPublishInfo->topicNameLength,
                                                &messageType,
                                                &pThingName,
                                                &thingNameLength)) {
            switch (messageType) {
                case ShadowMessageTypeGetAccepted:
                    tr_info("/get/accepted json payload: %.*s", pPublishInfo->payloadLength, (const char *)pPublishInfo->pPayload);
                    awsClient.shadowGetAccepted = true;
                    // Buffer should be large enough to contain the response.
                    MBED_ASSERT(pPublishInfo->payloadLength < sizeof(awsClient.shadowGetResponse));
                    // Safely store the get response, truncate if necessary.
                    snprintf(awsClient.shadowGetResponse, sizeof(awsClient.shadowGetResponse), "%.*s", pPublishInfo->payloadLength, (const char *)pPublishInfo->pPayload);
                    break;

                case ShadowMessageTypeGetRejected:
                    tr_warn("/get/rejected json payload: %.*s", pPublishInfo->payloadLength, (const char *)pPublishInfo->pPayload);
                    awsClient.shadowGetAccepted = false;
                    break;

                case ShadowMessageTypeUpdateAccepted:
                    tr_info("/update/accepted json payload: %.*s", pPublishInfo->payloadLength, (const char *)pPublishInfo->pPayload);
                    awsClient.shadowUpdateAccepted = true;
                    break;

                case ShadowMessageTypeUpdateRejected:
                    tr_warn("/update/rejected json payload: %.*s", pPublishInfo->payloadLength, (const char *)pPublishInfo->pPayload);
                    awsClient.shadowUpdateAccepted = false;
                    break;

                default:
                    tr_warn("Received unexpected shadow message");
                    break;
            }
        }
        // Not a shadow topic, forward to the callback
        else {
            awsClient.subCallback(string(pPublishInfo->pTopicName,
                                         pPublishInfo->topicNameLength),
                                  string((char *)pPublishInfo->pPayload,
                                         pPublishInfo->payloadLength));
        }
    } else {
        /* Handle other packets. */
        switch (pPacketInfo->type) {
            case MQTT_PACKET_TYPE_PUBACK:
                tr_info("PUBACK");
                break;

            case MQTT_PACKET_TYPE_PUBCOMP:
                tr_info("PUBCOMP");
                break;

            case MQTT_PACKET_TYPE_SUBACK:
                tr_info("PUBACK");
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                tr_info("UNSUBACK");
                break;

            case MQTT_PACKET_TYPE_PUBREC:
                tr_info("PUBREC");
                break;

            case MQTT_PACKET_TYPE_PUBREL:
                tr_info("PUBREL");
                break;

            case MQTT_PACKET_TYPE_PINGRESP:
                tr_info("PINGRESP");
                break;

            /* Any other packet type is invalid. */
            default:
                tr_error("Unknown packet type received:(%02x)",
                         pPacketInfo->type);
        }
    }
}

int AWSClient::init(Callback<void(string, string)> subCallback,
                    const TLSCredentials_t &creds)
{
    // Set subscription callback
    this->subCallback = subCallback;

    // Fill in TransportInterface send and receive function pointers
    TransportInterface_t transport;
    transport.pNetworkContext = &networkContext;
    transport.send = Mbed_Send;
    transport.recv = Mbed_Recv;

    // Set buffer members
    MQTTFixedBuffer_t networkBuffer;
    networkBuffer.pBuffer = mqttBuffer;
    networkBuffer.size = sizeof(mqttBuffer);

    // Initialize MQTT
    auto status = MQTT_Init(&mqttContext,
                            &transport,
                            Mbed_GetTimeMs,
                            AWSClient::eventCallbackStatic,
                            &networkBuffer);
    if (status != MQTTSuccess) {
        tr_error("MQTT init error: %d", status);
        return status;
    }

    // Create own Root CA chain, since DER encoded certificates cannot be joined as strings
    mbedtls_x509_crt_init(&rootCA);

    // Set main root certificate
    auto ret = mbedtls_x509_crt_parse(&rootCA,
                                      reinterpret_cast<const unsigned char *>(creds.rootCrtMain),
                                      creds.rootCrtMainLen);
    if (ret != MBED_SUCCESS) {
        tr_error("parse main root CA failed with %d", ret);
        return ret;
    }

    if (creds.rootCrtBackup) {
        // Set backup root certificate
        ret = mbedtls_x509_crt_parse(&rootCA,
                                     reinterpret_cast<const unsigned char *>(creds.rootCrtBackup),
                                     creds.rootCrtBackupLen);
        if (ret != MBED_SUCCESS) {
            tr_warn("parse backup root CA failed with %d", ret);
            // This is not fatal, continue without backup root certificate
        }
    }

    return MBED_SUCCESS;
}

int AWSClient::connect(NetworkInterface *net,
                       const TLSCredentials_t &creds,
                       const string hostname,
                       const string clientID)
{
    if (net == NULL) {
        tr_error("No network interface provided.");
        return MBED_ERROR_INVALID_ARGUMENT;
    }

    // Create a new socket
    /* BSD sockets are not allowed to be reused.
     * Therefore a new socket must be created for each connection.
     * See discussion in https://github.com/ARMmbed/mbed-os/pull/8613 */
    networkContext.socket.~TLSSocket();
    new (&networkContext.socket) TLSSocket();

    // Set hostname
    networkContext.socket.set_hostname(hostname.c_str());

    // Set credentials
    networkContext.socket.set_client_cert_key(creds.clientCrt,
                                              creds.clientCrtLen,
                                              creds.clientKey,
                                              creds.clientKeyLen);

    // Set Root CA chain
    networkContext.socket.set_ca_chain(&rootCA);

    // Set socket timeout
    auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(MBED_CONF_AWS_CLIENT_SOCKET_TIMEOUT).count();
    networkContext.socket.set_timeout(timeout_ms);

    // Open socket with the provided network interface
    auto ret = networkContext.socket.open(net);
    if (ret != MBED_SUCCESS) {
        tr_error("Socket open error: %d", ret);
        return ret;
    }

    // Get IP address from DNS server
    SocketAddress addr;
    ret = net->gethostbyname(hostname.c_str(), &addr);
    if (ret != MBED_SUCCESS) {
        tr_error("gethostbyname error: %d", ret);
        return ret;
    }

    tr_debug("IP address: %s", addr.get_ip_address());

    // Set port
    addr.set_port(MBED_CONF_AWS_CLIENT_PORT);

    // Connect with TLS
    ret = networkContext.socket.connect(addr);
    if (ret == NSAPI_ERROR_IS_CONNECTED) {
        // This is not an error, received on reconnection.
        ret = MBED_SUCCESS;
    }
    if (ret != MBED_SUCCESS) {
        tr_error("Socket connect error: %d", ret);
        return ret;
    }

    // Assuming the client ID is the same as the thing name.
    thingName = clientID;

    MQTTConnectInfo_t connectInfo = {};
    connectInfo.pClientIdentifier = clientID.c_str();
    connectInfo.clientIdentifierLength = clientID.length();
    connectInfo.cleanSession = MBED_CONF_AWS_CLIENT_CLEAN_SESSION;
    connectInfo.keepAliveSeconds = std::chrono::duration_cast<std::chrono::seconds>(MBED_CONF_AWS_CLIENT_KEEPALIVE).count();

    MQTTStatus_t mqttStatus;
    bool sessionPresent;
    mqttStatus = MQTT_Connect(&mqttContext, &connectInfo, NULL, 0, &sessionPresent);
    if (mqttStatus != MQTTSuccess) {
        tr_error("MQTT connect error: %d", ret);
        return mqttStatus;
    }

    return MBED_SUCCESS;
}

bool AWSClient::isConnected()
{
    return mqttContext.connectStatus == MQTTConnected ? true : false;
}

int AWSClient::disconnect()
{
    auto status = MQTT_Disconnect(&mqttContext);
    if (status != MQTTSuccess) {
        tr_error("MQTT disconnect error: %d", status);
        return status;
    }
    auto ret = networkContext.socket.close();
    if (ret != MBED_SUCCESS) {
        tr_error("Socket close error: %d", ret);
        return ret;
    }

    return MBED_SUCCESS;
}

MQTTContext_t AWSClient::getMQTTContext()
{
    return mqttContext;
}

string AWSClient::getThingName()
{
    return thingName;
}

int AWSClient::subscribe(const string topicFilter, const MQTTQoS qos)
{
    // Currently only support single subscriptions
    MQTTSubscribeInfo_t subscribeList[1];
    subscribeList[0].qos = qos;
    subscribeList[0].pTopicFilter = topicFilter.c_str();
    subscribeList[0].topicFilterLength = topicFilter.length();

    auto packetId = MQTT_GetPacketId(&mqttContext);

    auto status = MQTT_Subscribe(&mqttContext, subscribeList, 1, packetId);
    if (status != MQTTSuccess) {
        tr_error("MQTT subscribe error: %d", status);
        return status;
    }

    // Call process loop once to receive the ACK
    status = MQTT_ProcessLoop(&mqttContext, 0);
    if (status != MQTTSuccess) {
        tr_error("MQTT ProcessLoop error: %d", status);
        return status;
    }

    return status;
}

int AWSClient::unsubscribe(const string topicFilter)
{
    // Currently only support single subscriptions
    MQTTSubscribeInfo_t unsubscribeList[1];
    unsubscribeList[0].pTopicFilter = topicFilter.c_str();
    unsubscribeList[0].topicFilterLength = topicFilter.length();

    auto packetId = MQTT_GetPacketId(&mqttContext);

    auto status = MQTT_Unsubscribe(&mqttContext, unsubscribeList, 1, packetId);
    if (status != MQTTSuccess) {
        tr_error("MQTT subscribe error: %d", status);
        return status;
    }

    // Call process loop once to receive the ACK
    status = MQTT_ProcessLoop(&mqttContext, 0);
    if (status != MQTTSuccess) {
        tr_error("MQTT ProcessLoop error: %d", status);
        return status;
    }

    return status;
}

int AWSClient::publish(const string topic, const string msg, const MQTTQoS qos)
{
    MQTTPublishInfo_t publishInfo = {};
    publishInfo.qos = qos;
    publishInfo.pTopicName = topic.c_str();
    publishInfo.topicNameLength = topic.length();
    publishInfo.pPayload = msg.c_str();
    publishInfo.payloadLength = msg.length();

    // TODO check for length limit

    // Packet ID is needed for QoS > 0.
    auto packetId = MQTT_GetPacketId(&mqttContext);

    auto status = MQTT_Publish(&mqttContext, &publishInfo, packetId);
    if (status != MQTTSuccess) {
        tr_error("MQTT publish error: %d", status);
        return status;
    }

    // TODO process response in case of QoS

    return status;
}

int AWSClient::processResponses()
{
    if (mqttContext.connectStatus == MQTTNotConnected) {
        tr_error("MQTT not connected");
        return ENOTCONN;
    }

    // Process all responses until no more remains
    do {
        // Set response received flag to false.
        // This will be set to true on response callback.
        isResponseReceived = false;

        // ProcessLoop is called with a timeout of 0,
        // which means that it will only wait for the socket timeout once.
        auto status = MQTT_ProcessLoop(&mqttContext, 0);
        if (status != MQTTSuccess) {
            tr_error("MQTT ProcessLoop error: %d", status);
            return status;
        }

    } while (isResponseReceived);

    return MBED_SUCCESS;
}

int AWSClient::getShadowDesiredValue(string key, string &value)
{
    // Construct JSON search key
    key = "state.desired." + key;

    char *val;
    size_t valLen;

    // Search for the key in the document
    auto ret = JSON_Search(shadowGetResponse, sizeof(shadowGetResponse),
                           key.c_str(), key.length(),
                           &val, &valLen);
    if (ret == JSONNotFound) {
        tr_info("JSON key %s not found", key.c_str());
        return ret;
    } else if (ret != JSONSuccess) {
        tr_error("JSON_Search error: %d", ret);
        return ret;
    }

    // Set the output string
    value = string(val, valLen);

    return MBED_SUCCESS;
}

int AWSClient::publishShadowReportedValue(string key, string value)
{
    // Construct update document
    string updateDocument = "{\"state\":{\"reported\":{\"" + key + "\":\"" + value + "\"}}}";

    // Publish update document
    auto ret = updateShadowDocument(updateDocument);
    if (ret != 0) {
        tr_error("updateShadowDocument error: %d", ret);
        return ret;
    }

    return MBED_SUCCESS;
}

int AWSClient::publishShadowReportedValue(string key, int value)
{
    // Construct update document
    string updateDocument = "{\"state\":{\"reported\":{\"" + key + "\":" + std::to_string(value) + "}}}";

    // Publish update document
    auto ret = updateShadowDocument(updateDocument);
    if (ret != 0) {
        tr_error("updateShadowDocument error: %d", ret);
        return ret;
    }

    return 0;
}

int AWSClient::downloadShadowDocument()
{
    static char getAcceptedTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t getAcceptedTopicLength = 0;
    static char getRejectedTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t getRejectedTopicLength = 0;
    static char getTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t getTopicLength = 0;

    // Reset get accepted flag
    shadowGetAccepted = false;

    // Construct get/accepted topic
    auto shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeGetAccepted,
                                              thingName.c_str(),
                                              thingName.length(),
                                              getAcceptedTopicBuffer,
                                              sizeof(getAcceptedTopicBuffer),
                                              &getAcceptedTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Construct get/rejected topic
    shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeGetRejected,
                                         thingName.c_str(),
                                         thingName.length(),
                                         getRejectedTopicBuffer,
                                         sizeof(getRejectedTopicBuffer),
                                         &getRejectedTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Construct get topic
    shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeGet,
                                         thingName.c_str(),
                                         thingName.length(),
                                         getTopicBuffer,
                                         sizeof(getTopicBuffer),
                                         &getTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Subscribe to get/accepted topic
    auto ret = subscribe(string(getAcceptedTopicBuffer, getAcceptedTopicLength));
    if (ret != 0) {
        tr_error("subscribe error: %d", ret);
        return ret;
    }

    // Subscribe to get/rejected topic
    ret = subscribe(string(getRejectedTopicBuffer, getRejectedTopicLength));
    if (ret != 0) {
        tr_error("subscribe error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Publish to update topic
    ret = publish(string(getTopicBuffer, getTopicLength), string());
    if (ret != 0) {
        tr_error("publish error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Wait for server response
    ret = MQTT_ProcessLoop(&mqttContext, 0);
    if (ret != MQTTSuccess) {
        tr_error("MQTT_ProcessLoop error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Check response
    if (!shadowGetAccepted) {
        tr_error("Shadow get request rejected.");
        ret = -1;
    }

unsubscribeAndReturn:

    // Unsubscribe from topics
    unsubscribe(string(getAcceptedTopicBuffer, getAcceptedTopicLength));
    unsubscribe(string(getRejectedTopicBuffer, getRejectedTopicLength));

    // Return result
    return ret;
}

int AWSClient::updateShadowDocument(string updateDocument)
{
    static char updateAcceptedTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t updateAcceptedTopicLength = 0;
    static char updateRejectedTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t updateRejectedTopicLength = 0;
    static char updateTopicBuffer[MBED_CONF_AWS_CLIENT_SHADOW_TOPIC_MAX_SIZE] = {0};
    uint16_t updateTopicLength = 0;

    // Reset update accepted flag
    shadowUpdateAccepted = false;

    // Construct update/accepted topic
    auto shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeUpdateAccepted,
                                              thingName.c_str(),
                                              thingName.length(),
                                              updateAcceptedTopicBuffer,
                                              sizeof(updateAcceptedTopicBuffer),
                                              &updateAcceptedTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Construct update/rejected topic
    shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeUpdateRejected,
                                         thingName.c_str(),
                                         thingName.length(),
                                         updateRejectedTopicBuffer,
                                         sizeof(updateRejectedTopicBuffer),
                                         &updateRejectedTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Construct update topic
    shadowStatus = Shadow_GetTopicString(ShadowTopicStringTypeUpdate,
                                         thingName.c_str(),
                                         thingName.length(),
                                         updateTopicBuffer,
                                         sizeof(updateTopicBuffer),
                                         &updateTopicLength);
    if (shadowStatus != SHADOW_SUCCESS) {
        tr_error("Shadow_GetTopicString error: %d", shadowStatus);
        return shadowStatus;
    }

    // Subscribe to update/accepted topic
    auto ret = subscribe(string(updateAcceptedTopicBuffer, updateAcceptedTopicLength));
    if (ret != 0) {
        tr_error("subscribe error: %d", ret);
        return ret;
    }

    // Subscribe to update/rejected topic
    ret = subscribe(string(updateRejectedTopicBuffer, updateRejectedTopicLength));
    if (ret != 0) {
        tr_error("subscribe error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Publish to update topic
    ret = publish(string(updateTopicBuffer, updateTopicLength), updateDocument);
    if (ret != 0) {
        tr_error("publish error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Wait for server response
    ret = MQTT_ProcessLoop(&mqttContext, 0);
    if (ret != MQTTSuccess) {
        tr_error("MQTT_ProcessLoop error: %d", ret);
        goto unsubscribeAndReturn;
    }

    // Check response
    if (!shadowUpdateAccepted) {
        tr_error("Shadow update request rejected.");
        ret = -1;
    }

unsubscribeAndReturn:

    // Unsubscribe from topics
    unsubscribe(string(updateAcceptedTopicBuffer, updateAcceptedTopicLength));
    unsubscribe(string(updateRejectedTopicBuffer, updateRejectedTopicLength));

    // Return result
    return ret;
}
