#include "mbed.h"
#include "mbed_trace.h"

#define TRACE_GROUP "AWSPort"

extern "C" {
#include "iot_config.h"
#include "iot_network.h"
#include "iot_error.h"
}

/* Private methods */
static IotNetworkError_t network_new(IotNetworkServerInfo_t pServerInfo,
                                     IotNetworkCredentials_t pCredentialInfo,
                                     IotNetworkConnection_t * pConnection);
static IotNetworkError_t network_set_receive_callback(IotNetworkConnection_t pConnection,
                                                      IotNetworkReceiveCallback_t receiveCallback,
                                                      void * pContext);
static IotNetworkError_t network_set_close_callback(IotNetworkConnection_t pConnection,
                                                    IotNetworkCloseCallback_t closeCallback,
                                                    void * pContext);
static size_t network_send(IotNetworkConnection_t pConnection,
                           const uint8_t * pMessage,
                           size_t messageLength);
static size_t network_recv(IotNetworkConnection_t pConnection,
                           uint8_t * pBuffer,
                           size_t bytesRequested);
static IotNetworkError_t network_close(IotNetworkConnection_t pConnection);
static IotNetworkError_t network_delete(IotNetworkConnection_t pConnection);

struct NetworkConnection {
    TLSSocket   socket;
    Thread      thread;
    Mutex       mtx;
    EventFlags  flags;

    enum class Flags: uint32_t {
        sigio = 1,
        termination = 2
    };

    void (*on_recv)(NetworkConnection*, void *);
    void *on_recv_ctx;
    void (*on_close)(NetworkConnection*, IotNetworkCloseReason, void *);
    void *on_close_ctx;

    void on_event() {
        flags.set((uint32_t)Flags::sigio);
    }

    void event_dispatcher_thread() {
        while (true) {
            auto flag_read = flags.wait_any((uint32_t)Flags::sigio | (uint32_t)Flags::termination);

            if (flag_read & (uint32_t)Flags::termination) {
                break;
            }

            this->mtx.lock();
            this->socket.set_blocking(false);
            auto result = this->socket.recv(nullptr, 0);
            this->socket.set_blocking(true);
            this->mtx.unlock();

            if (result == 0) {
                this->mtx.lock();
                auto cbk = this->on_recv;
                auto ctx = this->on_recv_ctx;
                this->mtx.unlock();
                // XXX: I don't think this really safe. cbk & ctx might be freed between the unlock
                // and this call
                if (cbk != NULL) {
                    cbk(this, ctx); 
                }
            } else if (result != NSAPI_ERROR_WOULD_BLOCK) {
                break;
            }
        }
        {
            this->mtx.lock();
            auto cbk = this->on_close;
            auto ctx = this->on_close_ctx;
            this->mtx.unlock();
            // XXX: I don't think this really safe. cbk & ctx might be freed between the unlock
            // and this call
            if (cbk != NULL) {
                cbk(this, IOT_NETWORK_UNKNOWN_CLOSED, ctx); 
            }
        }
        tr_info("exiting dispatcher thread.");
    }
};

static const IotNetworkInterface_t gc_network = {
    .create = network_new,
    .setReceiveCallback = network_set_receive_callback,
    .setCloseCallback = network_set_close_callback,
    .send = network_send,
    .receive = network_recv,
    .close = network_close,
    .destroy = network_delete
};

static IotNetworkError_t network_new(IotNetworkServerInfo_t pServerInfo,
                                     IotNetworkCredentials_t pCredentialInfo,
                                     IotNetworkConnection_t * pConnection) {
    IOT_FUNCTION_ENTRY( IotNetworkError_t, IOT_NETWORK_SUCCESS );

    auto net = NetworkInterface::get_default_instance();
    auto conn = new NetworkConnection { {}, {osPriorityNormal, OS_STACK_SIZE, nullptr, "awsNetworkSocket"} };
    nsapi_error_t res = NSAPI_ERROR_OK;

    IOT_SET_AND_GOTO_CLEANUP_IF_FALSE( IOT_NETWORK_FAILURE, net != NULL );
    IOT_SET_AND_GOTO_CLEANUP_IF_FALSE( IOT_NETWORK_NO_MEMORY, conn != NULL );

    res = conn->socket.open(net);
    IOT_SET_AND_GOTO_CLEANUP_IF_FALSE( IOT_NETWORK_FAILURE, res == NSAPI_ERROR_OK );

    conn->socket.set_hostname(pServerInfo.hostname);
    conn->socket.set_root_ca_cert(pCredentialInfo.rootCA);
    conn->socket.set_client_cert_key(pCredentialInfo.clientCrt,
                                pCredentialInfo.clientKey);

    /*
    // if port 443 alpn protocol is requested.
    if (443 == pNetwork->tlsConnectParams.DestinationPort) {
        auto ssl_config = conn->socket.get_ssl_config();
        static const char *alpnProtocols[] = {"x-amzn-mqtt-ca", NULL};
        if (0 != mbedtls_ssl_conf_alpn_protocols(ssl_config, alpnProtocols)) {
            tr_error("Failed to set alpn");
            delete socket;
            FUNC_EXIT_RC(SSL_CONNECTION_ERROR);
        }
    }
    */
 
    {
        SocketAddress addr;
        res = net->gethostbyname(pServerInfo.hostname, &addr);
        if (res != NSAPI_ERROR_OK) {
            tr_error("Error! DNS resolution for %s failed with %d", pServerInfo.hostname, res);
            IOT_SET_AND_GOTO_CLEANUP( IOT_NETWORK_FAILURE );
        }
        addr.set_port(pServerInfo.port);

        res = conn->socket.connect(addr);
        if (NSAPI_ERROR_OK != res) {
            tr_error("failed to connect with : %d", res);
            IOT_SET_AND_GOTO_CLEANUP( IOT_NETWORK_FAILURE );
        }
    }

    IOT_FUNCTION_CLEANUP_BEGIN();
    if ((res != NSAPI_ERROR_OK) && (conn != NULL)) {
        delete conn;
    } else {
        conn->thread.start({conn, &NetworkConnection::event_dispatcher_thread});
        *pConnection = conn; 
    }
    IOT_FUNCTION_CLEANUP_END();
}

static IotNetworkError_t network_set_receive_callback(IotNetworkConnection_t pConnection,
                                                      IotNetworkReceiveCallback_t receiveCallback,
                                                      void * pContext) {
    pConnection->mtx.lock();
    pConnection->on_recv_ctx = pContext;
    pConnection->on_recv = receiveCallback;
    pConnection->socket.sigio({ pConnection, &NetworkConnection::on_event });
    pConnection->mtx.unlock();
    return IOT_NETWORK_SUCCESS; 
}
static IotNetworkError_t network_set_close_callback(IotNetworkConnection_t pConnection,
                                                    IotNetworkCloseCallback_t closeCallback,
                                                    void * pContext){
    pConnection->mtx.lock();
    pConnection->on_close_ctx = pContext;
    pConnection->on_close = closeCallback;
    pConnection->socket.sigio({ pConnection, &NetworkConnection::on_event });
    pConnection->mtx.unlock();
    return IOT_NETWORK_SUCCESS; 
}
static size_t network_send(IotNetworkConnection_t pConnection,
                           const uint8_t * pMessage,
                           size_t messageLength){
    pConnection->mtx.lock();
    auto res = pConnection->socket.send(pMessage, messageLength);
    pConnection->mtx.unlock();
    if (res < 0) {
        tr_error("failed to send data with %d", res);
        return 0;
    }
    
    return (size_t)res;
}
static size_t network_recv(IotNetworkConnection_t pConnection,
                           uint8_t * pBuffer,
                           size_t bytesRequested){
    assert(bytesRequested < INT32_MAX);

    pConnection->mtx.lock();
    pConnection->socket.set_blocking(false);
    auto res = pConnection->socket.recv(pBuffer, bytesRequested);
    pConnection->socket.set_blocking(true);
    pConnection->mtx.unlock();

    if (res < 0) {
        tr_error("failed to recv data with %d", res);
        return 0;
    } else if (res != (int)bytesRequested) {
        tr_warning("Unexpected recv length (got %u, expected %u)", res, bytesRequested);
    }
    
    return (size_t)res;
}
static IotNetworkError_t network_close(IotNetworkConnection_t pConnection){
    if (pConnection != NULL) {
        pConnection->flags.set((uint32_t)NetworkConnection::Flags::termination);
        pConnection->thread.join();

        pConnection->mtx.lock();
        pConnection->socket.sigio(nullptr);
        pConnection->socket.close();
        pConnection->mtx.unlock();
    }

    return IOT_NETWORK_SUCCESS; 
}
static IotNetworkError_t network_delete(IotNetworkConnection_t pConnection){
    network_close(pConnection);
    delete pConnection;

    return IOT_NETWORK_SUCCESS; 
}


namespace aws {
const IotNetworkInterface_t *get_iot_network_interface() {
    return &gc_network;
}
}
