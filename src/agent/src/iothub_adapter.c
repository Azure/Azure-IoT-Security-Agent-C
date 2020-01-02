// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "iothub_adapter.h"

#include <stdlib.h>

#include "azure_c_shared_utility/threadapi.h"
#include "iothub_client_options.h"
#include "iothubtransportamqp.h"

#include "consts.h"
#include "local_config.h"
#include "logger.h"
#include "message_schema_consts.h"
#include "tasks/update_twin_task.h"
#include "agent_errors.h"

#ifdef USE_MQTT
#include "iothubtransportmqtt.h"
IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = MQTT_Protocol;
#endif
#ifdef USE_AMQP
#include "iothubtransportamqp.h"
IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol = AMQP_Protocol;
#endif

/**
 * @brief This function is called upon receiving confirmation of the delivery of the IoT Hub message
 *
 * @param   result                  The result of the callback
 * @param   userContextCallback     The user context for the callback.
 */
static void IoTHubAdapter_SendConfirmCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback);

/**
 * @brief This function is called upon receiving confirmation of setting up device twin reported properties
 *
 * @param   statusCode      The statusCode of the callback
 * @param   userContext     The user context for the callback.
 */
static void IoTHubAdapter_SetReportedConfirmCallback(int statusCode, void* userContext);

/**
 * @brief This function is called upon receiving updates about the status of the connection to IoT Hub.
 *
 * @param   result                  The result of the connection.
 * @param   reason                  The reason for this callback.
 * @param   userContextCallback     The user context for the callback.
 */
static void IoTHubAdapter_ConnectionStatusCallback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* userContextCallback);

/**
 * @brief This function is calles upon response to patch request send by the IoTHub services
 *
 * @param   updateState             The current update state of the twin.
 * @param   payload                 The updates of the twin configuration.
 * @param   size                    The size of the payload.
 * @param   userContextCallback     The user context for the callback.
 */
static void IoTHubAdapter_DeviceTwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload, size_t size, void* userContextCallback);

/**
 * @brief Initiate a new IoT hub module client internal state
 *
 * @param   iotHubAdapter       The adapter to initiate.
 * @param   twinUpdatesQueue    The queue which will contain all the twin updates
 *
 * @return true on success, false otherwise.
 */
static bool IoTHubAdapter_Init_Internal(IoTHubAdapter* iotHubAdapter, SyncQueue* twinUpdatesQueue);

/**
 * @brief Deinitialize the IoT hub module client internal state
 *
 * @param   iotHubAdapter   The adapter to deinitiate.
 */
static void IoTHubAdapter_Deinit_Internal(IoTHubAdapter* iotHubAdapter);

/**
 * @brief Re-initiate a new IoT hub module client
 *
 * @param   iotHubAdapter       The adapter to initiate.
 * @param   twinUpdatesQueue    The queue which will contain all the twin updates
 *
 * @return true on success, false otherwise.
 */
static bool IoTHubAdapter_Reinit(IoTHubAdapter* iotHubAdapter, SyncQueue* twinUpdatesQueue);

/**
 * @brief Send message a-sync to the hub (internal function).
 *
 * @param   iotHubAdapter   The adapter to send data with.
 * @param   data            The data to send.
 * @param   dataSize        The size of the data we want to send.
 *
 * @return true on success, false otherwise.
 */
static bool IoTHubAdapter_SendMessageAsync_Internal(IoTHubAdapter* iotHubAdapter, const void* data, size_t dataSize);

static LOCK_HANDLE iotHubAdapterLock = NULL;

bool IoTHubAdapter_Init(IoTHubAdapter* iotHubAdapter, SyncQueue* twinUpdatesQueue) {
    iotHubAdapterLock = Lock_Init();
    if (iotHubAdapterLock == NULL) {
        Logger_Error("Could not initialize IoTHubAdapter lock");
        return false;
    }

    if (Lock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not lock IoTHubAdapter lock");
        return false;
    }

    bool result = IoTHubAdapter_Init_Internal(iotHubAdapter, twinUpdatesQueue);

    if (Unlock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not unlock IoTHubAdapter lock");
        return false;
    }

    return result;
}

bool IoTHubAdapter_Init_Internal(IoTHubAdapter* iotHubAdapter, SyncQueue* twinUpdatesQueue) {
    bool success = true;
    memset(iotHubAdapter, 0, sizeof(*iotHubAdapter));

    iotHubAdapter->twinUpdatesQueue = twinUpdatesQueue;

    // Create the iothub handle here
    iotHubAdapter->moduleHandle = IoTHubModuleClient_CreateFromConnectionString(LocalConfiguration_GetConnectionString(), protocol);
    if (iotHubAdapter->moduleHandle == NULL) {
        success = false;
        goto cleanup;
    }

#ifdef USE_MQTT
    bool urlEncodeOn = true;
    if (IoTHubModuleClient_SetOption(iotHubAdapter->moduleHandle, OPTION_AUTO_URL_ENCODE_DECODE, &urlEncodeOn) != IOTHUB_CLIENT_OK) {
        success = false;
        goto cleanup;
    }
#endif

    bool logTraces = false;
    if (IoTHubModuleClient_SetOption(iotHubAdapter->moduleHandle, OPTION_LOG_TRACE, &logTraces) != IOTHUB_CLIENT_OK) {
        success = false;
        goto cleanup;
    }

    // Setting connection status callback to get indication of connection to iothub
    if (IoTHubModuleClient_SetConnectionStatusCallback(iotHubAdapter->moduleHandle, IoTHubAdapter_ConnectionStatusCallback, iotHubAdapter) != IOTHUB_CLIENT_OK) {
        success = false;
        goto cleanup;
    }

    if (IoTHubModuleClient_SetModuleTwinCallback(iotHubAdapter->moduleHandle, IoTHubAdapter_DeviceTwinCallback, iotHubAdapter) != IOTHUB_CLIENT_OK) {
        success = false;
        goto cleanup;
    }

    success = AgentTelemetryCounter_Init(&iotHubAdapter->messageCounter);
    if (!success){
        goto cleanup;
    }

    iotHubAdapter->hubInitiated = true;

cleanup:
    if (!success) {
        IoTHubAdapter_Deinit_Internal(iotHubAdapter);
    }

    return success;
}

void IoTHubAdapter_Deinit(IoTHubAdapter* iotHubAdapter) {
    if (iotHubAdapterLock == NULL || Lock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not lock IoTHubAdapter lock");
        return;
    }

    IoTHubAdapter_Deinit_Internal(iotHubAdapter);

    if (Unlock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not unlock IoTHubAdapter lock");
        return;
    }

    if (Lock_Deinit(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not de-initialize IotHubAdapter lock");
    }
    iotHubAdapterLock = NULL;
}

void IoTHubAdapter_Deinit_Internal(IoTHubAdapter* iotHubAdapter) {
    iotHubAdapter->hubInitiated = false;
    AgentTelemetryCounter_Deinit(&iotHubAdapter->messageCounter);

    if (iotHubAdapter->moduleHandle != NULL) {
        IoTHubModuleClient_Destroy(iotHubAdapter->moduleHandle);
    }
}

bool IoTHubAdapter_Reinit(IoTHubAdapter* iotHubAdapter, SyncQueue* twinUpdatesQueue) {
    IoTHubAdapter_Deinit_Internal(iotHubAdapter);
    if (!IoTHubAdapter_Init_Internal(iotHubAdapter, twinUpdatesQueue)) {
        Logger_Error("Could not initialize IoTHub adapter");
        return false;
    }

    if (!IoTHubAdapter_Connect(iotHubAdapter)) {
        Logger_Error("Could not connect to IoT Hub");
        return false;
    }

    return true;
}

bool IoTHubAdapter_ValidateAdapterConnectionStatus(IoTHubAdapter* adapter, bool* isPermanent) {
    *isPermanent = false;
    if (adapter->connected) {
        return true;
    }

    if (adapter->connectionStatusReason == IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL
            || adapter->connectionStatusReason == IOTHUB_CLIENT_CONNECTION_NO_NETWORK) {
        *isPermanent = true;
    }
    return false;
}

bool IoTHubAdapter_Connect(IoTHubAdapter* iotHubAdapter) {
    uint32_t timeout = LocalConfiguration_GetConnectionTimeout();
    uint32_t elapsedTime = 0;
    bool stop = false;
    while (!stop && elapsedTime < timeout) {
        bool isPermanent;
        bool isConnected = IoTHubAdapter_ValidateAdapterConnectionStatus(iotHubAdapter, &isPermanent);
        stop = (isConnected && iotHubAdapter->hasTwinConfiguration) || isPermanent;
        ThreadAPI_Sleep(100);
        elapsedTime += 100;
    }

    if (iotHubAdapter->connected && iotHubAdapter->hasTwinConfiguration) {
        return true;
    }

    if (iotHubAdapter->connected) {
        AgentErrors_LogError(ERROR_REMOTE_CONFIGURATION, SUBCODE_TIMEOUT, "Couldn't fetch remote configuration within timeout period");
    } else if (iotHubAdapter->connectionStatusReason == IOTHUB_CLIENT_CONNECTION_BAD_CREDENTIAL) {
        AgentErrors_LogError(ERROR_IOT_HUB_AUTHENTICATION, SUBCODE_UNAUTHORIZED, "Validate authentication configuration");
    } else if (iotHubAdapter->connectionStatusReason == IOTHUB_CLIENT_CONNECTION_NO_NETWORK) {
        AgentErrors_LogError(ERROR_IOT_HUB_AUTHENTICATION, SUBCODE_OTHER, "No network");
    } else {
        AgentErrors_LogError(ERROR_IOT_HUB_AUTHENTICATION, SUBCODE_OTHER, "Couldn't connect to iot hub within timeout period");
    }

    return false;
}

bool IoTHubAdapter_SendMessageAsync(IoTHubAdapter* iotHubAdapter, const void* data, size_t dataSize) {
    if (iotHubAdapterLock == NULL || Lock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Send message failed. Could not acquire lock");
        return false;
    }

    bool success = IoTHubAdapter_SendMessageAsync_Internal(iotHubAdapter, data, dataSize);

    if (Unlock(iotHubAdapterLock) != LOCK_OK) {
        Logger_Error("Could not unlock IoTHubAdapter lock");
        success = false;
    }

    return success;
}

static bool IoTHubAdapter_SendMessageAsync_Internal(IoTHubAdapter* iotHubAdapter, const void* data, size_t dataSize) {
    bool success = true;
    IOTHUB_MESSAGE_HANDLE messageHandle = NULL;

    if (!iotHubAdapter->hubInitiated) {
        Logger_Error("Cannot send message, hub not initiated");
        success = false;
        goto cleanup;
    }

    if (!iotHubAdapter->connected && LocalConfiguration_UseDps()) {
        if (!LocalConfiguration_TryRenewConnectionString()) {
            Logger_Error("Could not renew connection string");
            success = false;
            goto cleanup;
        }
        if (!IoTHubAdapter_Reinit(iotHubAdapter, iotHubAdapter->twinUpdatesQueue)) {
            Logger_Error("Could not re-initialize IoTHub adapter");
            success = false;
            goto cleanup;
        }
    }

    messageHandle = IoTHubMessage_CreateFromByteArray(data, dataSize);

    if (messageHandle == NULL) {
        Logger_Warning("Unable to create a new IoTHubMessage");
        success = false;
        goto cleanup;
    }

    if (IoTHubMessage_SetAsSecurityMessage(messageHandle) != IOTHUB_MESSAGE_OK) {
        Logger_Warning("Failed to set message as security message");
        success = false;
        goto cleanup;
    }

    if (IoTHubModuleClient_SendEventAsync(iotHubAdapter->moduleHandle, messageHandle, IoTHubAdapter_SendConfirmCallback, iotHubAdapter) != IOTHUB_CLIENT_OK) {
        Logger_Warning("Failed to hand over the message to IoTHubClient");
        success = false;
        goto cleanup;
    }

    if (dataSize < MESSAGE_BILLING_MULTIPLE){
        AgentTelemetryCounter_IncreaseBy(&iotHubAdapter->messageCounter, &iotHubAdapter->messageCounter.counter.messageCounter.smallMessages, 1);
    }
    AgentTelemetryCounter_IncreaseBy(&iotHubAdapter->messageCounter, &iotHubAdapter->messageCounter.counter.messageCounter.sentMessages, 1);
    Logger_Debug("IoTHubClient accepted the message for delivery");

cleanup:

    if (messageHandle != NULL) {
        IoTHubMessage_Destroy(messageHandle);
    }

    return success;
}

static void IoTHubAdapter_SendConfirmCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback) {
    if (userContextCallback == NULL) {
        Logger_Error("send_confirm_callback error in user context");
        return;
    }

    IoTHubAdapter* adapter = (IoTHubAdapter*)(userContextCallback);
    if (result != IOTHUB_CLIENT_CONFIRMATION_OK){
        AgentTelemetryCounter_IncreaseBy(&adapter->messageCounter, &adapter->messageCounter.counter.messageCounter.failedMessages, 1);
    }
}

static void IoTHubAdapter_ConnectionStatusCallback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* userContextCallback) {
    if (userContextCallback == NULL) {
        Logger_Error("connection_status_callback error in user context");
        return;
    }

    IoTHubAdapter* adapter = (IoTHubAdapter*)(userContextCallback);
    adapter->connectionStatusReason = reason;
    // This sample DOES NOT take into consideration network outages.
    if (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED && reason == IOTHUB_CLIENT_CONNECTION_OK) {
        adapter->connected = true;
        Logger_Information("The module client is connected to iothub");
    } else {
        if (adapter->connected)
            Logger_Information("The module client has been disconnected");
        adapter->connected = false;
    }
}

static void IoTHubAdapter_DeviceTwinCallback(DEVICE_TWIN_UPDATE_STATE updateState, const unsigned char* payload, size_t size, void* userContextCallback) {
    Logger_Debug("twin callback started");
    bool success = true;
    UpdateTwinTaskItem* twinTaskItem = NULL;
	IoTHubAdapter* adapter = NULL;

    if (size == 0) {
        success = false;
        goto cleanup;
    }

    if (userContextCallback == NULL) {
        Logger_Error("error in user context");
        success = false;
        goto cleanup;
    }

    adapter = (IoTHubAdapter*)(userContextCallback);

    UpdateTwinTask_InitUpdateTwinTaskItem(&twinTaskItem, payload, size, updateState == DEVICE_TWIN_UPDATE_COMPLETE);

    if (SyncQueue_PushBack(adapter->twinUpdatesQueue, twinTaskItem, sizeof(UpdateTwinTaskItem)) != QUEUE_OK) {
        Logger_Error("Bad allocation");
        //FIXME: how to handlebad allocation?
        success = false;
        goto cleanup;
    }

cleanup:
    if (!success) {
        if (twinTaskItem != NULL) {
            UpdateTwinTask_DeinitUpdateTwinTaskItem(&twinTaskItem);
        }
    } else {
        adapter->hasTwinConfiguration = true;
    }
}

bool IoTHubAdapter_SetReportedPropertiesAsync(IoTHubAdapter* iotHubAdapter, const void* reportedData, size_t dataSize) {
    bool success = true;

    if (reportedData == NULL)
    {
        Logger_Error("Invalid argument - byteArray is NULL");
        success = false;
        goto cleanup;
    }

    if (IoTHubModuleClient_SendReportedState(iotHubAdapter->moduleHandle, reportedData, dataSize, IoTHubAdapter_SetReportedConfirmCallback, NULL) != IOTHUB_CLIENT_OK) {
        Logger_Warning("failed to hand over the reported properties to IoTHubClient");
        success = false;
        goto cleanup;
    }

    Logger_Debug("IoTHubClient set reported properties");

cleanup:
    return success;
}

static void IoTHubAdapter_SetReportedConfirmCallback(int statusCode, void* userContext) {
    if (statusCode != 200) {
        Logger_Error("Couldn't set reproted properties");
    }
}