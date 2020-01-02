// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "collectors/connection_create_collector.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include "collectors/event_aggregator.h"
#include "collectors/linux/generic_audit_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "logger.h"
#include "message_schema_consts.h"
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/linux/audit/audit_search.h"
#include "utils.h"

#define AUDIT_CONNECTION_CREATION_MAX_BUFF 500U

static const char SUPPORTED_PROTOCOL_TCP[] = "tcp";

// connect, accept
static const char AUDIT_CONNECTION_CREATION_SYSCALL_CONNECT[] = "connect";
static const char AUDIT_CONNECTION_CREATION_SYSCALL_ACCEPT[] = "accept";
static const char* AUDIT_CONNECTION_CREATION_SYSCALLS[] = {
    AUDIT_CONNECTION_CREATION_SYSCALL_CONNECT,
    AUDIT_CONNECTION_CREATION_SYSCALL_ACCEPT
};
static uint32_t AUDIT_CONNECTION_CREATION_SYSCALLS_COUNT = sizeof(AUDIT_CONNECTION_CREATION_SYSCALLS) / sizeof(AUDIT_CONNECTION_CREATION_SYSCALLS[0]);
static const char AUDIT_CONNECTION_CREATION_CHECKPOINT_FILE[] = "/var/tmp/connectionCreationCheckpoint";

static const char AUDIT_CONNECTION_CREATION_EXECUTABLE[] = "exe";
static const char AUDIT_CONNECTION_CREATION_CMD[] = "proctitle";
static const char AUDIT_CONNECTION_CREATION_PROCESS_ID[] = "pid";
static const char AUDIT_CONNECTION_CREATION_USER_ID[] = "uid";
static const char AUDIT_CONNECTION_CREATION_SYSCALL[] = "syscall";
static const char AUDIT_CONNECTION_CREATION_REMOTE_SOCKET_ADDRESS[] = "saddr";

static const char IP_V4_FORMAT_STR[] = "%u.%u.%u.%u";
static const char IP_V6_FORMAT_STR[] = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x";

static EventAggregatorHandle aggregator = NULL;
static bool aggregatorInitialized = false;

typedef enum {
    CONNECTION_DIRECTION_OUTBOUND,
    CONNECTION_DIRECTION_INBOUND
} ConnectionDirection;

/**
 * @brief parses down address and port of the current record
 *
 * @param   auditSearch         The search audit.
 * @param   outputAddress       IP address of the current record.
 * @param   outputAddressSize   IP address buffer size of the current record.
 * @param   outputPort          Port of the current record.
 * @param   outputPortSize      Port size bufferof the current record.
 *
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ConnectionCreateEventCollector_GetRemoteInformation(AuditSearch* auditSearch, char* outputAddress, uint32_t outputAddressSize, char* outputPort, uint32_t outputPortSize);

/**
 * @brief Creates an event ready for aggregation
 *
 * @param   auditSearch         The search audit.
 * @param   aggregator          Handle to event aggregator
 *
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ConnectionCreationCollector_CreateEventForAggregation(AuditSearch* auditSearch, EventAggregatorHandle aggregator);

/**
 * @brief Parse the connection direction from an AuditSearch record.
 *
 * @param   auditSearch         The search audit.
 * @param   aggregator          Out param. The connection direction
 *
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ConnectionCreationCollector_GetDirection(AuditSearch* auditSearch, ConnectionDirection* direction);

EventCollectorResult ConnectionCreateEventCollector_GetRemoteInformation(AuditSearch* auditSearch, char* outputAddress, uint32_t outputAddressSize, char* outputPort, uint32_t outputPortSize) {
    if (outputAddressSize < AUDIT_CONNECTION_CREATION_MAX_BUFF || outputPortSize < AUDIT_CONNECTION_CREATION_MAX_BUFF) {
        Logger_Error("Received too small buffer for address initialization");
        return EVENT_COLLECTOR_EXCEPTION;
    }

    const char* auditStrValue = NULL;
    if (AuditSearch_ReadString(auditSearch, AUDIT_CONNECTION_CREATION_REMOTE_SOCKET_ADDRESS, &auditStrValue) != AUDIT_SEARCH_OK) {
        return EVENT_COLLECTOR_RECORD_HAS_ERRORS;
    }

    unsigned char saddrBytes[AUDIT_CONNECTION_CREATION_MAX_BUFF] = {0};
    uint32_t saddrSize = AUDIT_CONNECTION_CREATION_MAX_BUFF;
    if (Utils_HexStringToByteArray(auditStrValue, saddrBytes, &saddrSize) == false) {
        Logger_Error("Couldn't convert hex string to byte array");
        return EVENT_COLLECTOR_EXCEPTION;
    }

    uint8_t family = saddrBytes[0];
    if (family != AF_INET && family != AF_INET6 ) {
        return EVENT_COLLECTOR_RECORD_FILTERED;
    }

    uint16_t port = (saddrBytes[2] << 8) + saddrBytes[3];
    if (snprintf(outputPort, outputPortSize, "%u", port) <= 0) {
        return EVENT_COLLECTOR_EXCEPTION;
    }

    if (family == AF_INET ) {
        if (saddrSize < 8 || snprintf(outputAddress, outputAddressSize, IP_V4_FORMAT_STR, saddrBytes[4], saddrBytes[5], saddrBytes[6], saddrBytes[7]) <= 0) {
                return EVENT_COLLECTOR_EXCEPTION;
        }
     } else if (family == AF_INET6 ) {
        if (saddrSize < 24 || snprintf(outputAddress, outputAddressSize, IP_V6_FORMAT_STR,
                                                        saddrBytes[8], saddrBytes[9], saddrBytes[10], saddrBytes[11],
                                                        saddrBytes[12], saddrBytes[13], saddrBytes[14], saddrBytes[15],
                                                        saddrBytes[16], saddrBytes[17], saddrBytes[18], saddrBytes[19],
                                                        saddrBytes[20], saddrBytes[21], saddrBytes[22], saddrBytes[23]) != 39) {
            return EVENT_COLLECTOR_EXCEPTION;
        }
    }

    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ConnectionCreateEventCollector_GeneratePayload(AuditSearch* auditSearch, JsonObjectWriterHandle connectionCreationEventPayload) {
    const char* directionString = NULL;
    ConnectionDirection direction = CONNECTION_DIRECTION_OUTBOUND;
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    char remoteAddress[AUDIT_CONNECTION_CREATION_MAX_BUFF];
    char remotePort[AUDIT_CONNECTION_CREATION_MAX_BUFF];
    
    if (ConnectionCreationCollector_GetDirection(auditSearch, &direction) != EVENT_COLLECTOR_OK) {
        return EVENT_COLLECTOR_EXCEPTION;
    }

    if (direction == CONNECTION_DIRECTION_OUTBOUND) {
        directionString = CONNECTION_CREATION_DIRECTION_OUTBOUND_NAME;
    } else {
        directionString = CONNECTION_CREATION_DIRECTION_INBOUND_NAME;
    }

    result = ConnectionCreateEventCollector_GetRemoteInformation(auditSearch, remoteAddress, AUDIT_CONNECTION_CREATION_MAX_BUFF, remotePort, AUDIT_CONNECTION_CREATION_MAX_BUFF);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    if (JsonObjectWriter_WriteString(connectionCreationEventPayload, CONNECTION_CREATION_PROTOCOL_KEY, SUPPORTED_PROTOCOL_TCP) != JSON_WRITER_OK) {
        return EVENT_COLLECTOR_EXCEPTION;
    }

    if (JsonObjectWriter_WriteString(connectionCreationEventPayload, CONNECTION_CREATION_DIRECTION_KEY, directionString) != JSON_WRITER_OK) {
        return EVENT_COLLECTOR_RECORD_HAS_ERRORS;
    }

    if (JsonObjectWriter_WriteString(connectionCreationEventPayload, CONNECTION_CREATION_REMOTE_ADDRESS_KEY, remoteAddress) != JSON_WRITER_OK) {
        return EVENT_COLLECTOR_RECORD_HAS_ERRORS;
    }

    if (JsonObjectWriter_WriteString(connectionCreationEventPayload, CONNECTION_CREATION_REMOTE_PORT_KEY, remotePort) != JSON_WRITER_OK) {
        return EVENT_COLLECTOR_RECORD_HAS_ERRORS;
    }

    result = GenericAuditEvent_HandleInterpretStringValue(connectionCreationEventPayload, auditSearch, AUDIT_CONNECTION_CREATION_EXECUTABLE, CONNECTION_CREATION_EXECUTABLE_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    result = GenericAuditEvent_HandleInterpretStringValue(connectionCreationEventPayload, auditSearch, AUDIT_CONNECTION_CREATION_CMD, CONNECTION_CREATION_COMMAND_LINE_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    result = GenericAuditEvent_HandleIntValue(connectionCreationEventPayload, auditSearch, AUDIT_CONNECTION_CREATION_PROCESS_ID, CONNECTION_CREATION_PROCESS_ID_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    result = GenericAuditEvent_HandleStringValue(connectionCreationEventPayload, auditSearch, AUDIT_CONNECTION_CREATION_USER_ID, CONNECTION_CREATION_USER_ID_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ConnectionCreationCollector_CreateEventForAggregation(AuditSearch* auditSearch, EventAggregatorHandle aggregator) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle connectionCreateEventPayload = NULL;
    ConnectionDirection direction;

    if (JsonObjectWriter_Init(&connectionCreateEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = ConnectionCreateEventCollector_GeneratePayload(auditSearch, connectionCreateEventPayload);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (JsonObjectWriter_WriteInt(connectionCreateEventPayload, CONNECTION_CREATION_PROCESS_ID_KEY, 0) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (ConnectionCreationCollector_GetDirection(auditSearch, &direction) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_RECORD_HAS_ERRORS;
        goto cleanup;
    }

    if (direction == CONNECTION_DIRECTION_INBOUND) {
        if (JsonObjectWriter_WriteInt(connectionCreateEventPayload, CONNECTION_CREATION_REMOTE_PORT_KEY, 0) != JSON_WRITER_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
    }

    if (EventAggregator_AggregateEvent(aggregator, connectionCreateEventPayload) != EVENT_AGGREGATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
cleanup:

    if (connectionCreateEventPayload != NULL) {
        JsonObjectWriter_Deinit(connectionCreateEventPayload);
    }

    return result;
}


EventCollectorResult ConnectionCreateEventCollector_CreateSingleEvent(AuditSearch* auditSearch, SyncQueue* queue) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;

    JsonObjectWriterHandle connectionCreationEvent = NULL;
    JsonObjectWriterHandle connectionCreationEventPayload = NULL;
    JsonArrayWriterHandle payloads = NULL;
    char* output = NULL;

    if (JsonObjectWriter_Init(&connectionCreationEvent) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t eventTimeInSeconds = 0;
    if (AuditSearch_GetEventTime(auditSearch, &eventTimeInSeconds) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    time_t eventTime = (time_t)eventTimeInSeconds;

    if (GenericEvent_AddMetadataWithTimes(connectionCreationEvent, EVENT_TRIGGERED_CATEGORY, CONNECTION_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, CONNECTION_CREATION_PAYLOAD_SCHEMA_VERSION, &eventTime) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_Init(&connectionCreationEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = ConnectionCreateEventCollector_GeneratePayload(auditSearch, connectionCreationEventPayload);
    if (result == EVENT_COLLECTOR_RECORD_HAS_ERRORS) {
        goto cleanup;
    }
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (JsonArrayWriter_Init(&payloads) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonArrayWriter_AddObject(payloads, connectionCreationEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = GenericEvent_AddPayload(connectionCreationEvent, payloads);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    uint32_t outputSize = 0;
    if (JsonObjectWriter_Serialize(connectionCreationEvent, &output, &outputSize) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_OK;
        goto cleanup;
    }

    Logger_Debug("Generated single connection event:\n%s", output);

    QueueResultValues qResult = SyncQueue_PushBack(queue, output, outputSize);
    if (qResult == QUEUE_MAX_MEMORY_EXCEEDED) {
        result = EVENT_COLLECTOR_OUT_OF_MEM;
        goto cleanup;
    } else if (qResult != QUEUE_OK){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != EVENT_COLLECTOR_OK) {
        if (output != NULL) {
            free(output);
        }
    }

    if (connectionCreationEventPayload != NULL) {
        JsonObjectWriter_Deinit(connectionCreationEventPayload);
    }

    if (connectionCreationEvent != NULL) {
        JsonObjectWriter_Deinit(connectionCreationEvent);
    }

    if (payloads != NULL) {
        JsonArrayWriter_Deinit(payloads);
    }

    return result;
}

EventCollectorResult ConnectionCreateEventCollector_GetEvents(SyncQueue* queue) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    bool auditSearchInitialize = false;
    AuditSearch auditSearch;
    uint32_t recordsWithError = 0;
    uint32_t filteredRecords = 0;


    if (AuditSearch_InitMultipleSearchCriteria(&auditSearch, AUDIT_SEARCH_CRITERIA_SYSCALL, AUDIT_CONNECTION_CREATION_SYSCALLS, AUDIT_CONNECTION_CREATION_SYSCALLS_COUNT, AUDIT_CONNECTION_CREATION_CHECKPOINT_FILE) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    auditSearchInitialize = true;

    AuditSearchResultValues hasNextResult = AuditSearch_GetNext(&auditSearch);

    bool aggregaionEnabled = false;
    if (aggregatorInitialized == true && EventAggregator_IsAggregationEnabled(aggregator, &aggregaionEnabled) != EVENT_AGGREGATOR_OK) {
        Logger_Error("Couldn't fetch IsAggregationEnabled for event aggregator");
    }

    while (hasNextResult == AUDIT_SEARCH_HAS_MORE_DATA) {
        if (aggregaionEnabled == true) {
            result = ConnectionCreationCollector_CreateEventForAggregation(&auditSearch, aggregator);
        } else {
            result = ConnectionCreateEventCollector_CreateSingleEvent(&auditSearch, queue);
        }

        if (result == EVENT_COLLECTOR_EXCEPTION) {
            goto cleanup;
        } else if (result == EVENT_COLLECTOR_RECORD_HAS_ERRORS) {
            ++recordsWithError;
        } else if (result == EVENT_COLLECTOR_RECORD_FILTERED) {
            ++filteredRecords;
        }

        result = EVENT_COLLECTOR_OK;
        hasNextResult = AuditSearch_GetNext(&auditSearch);
    }

    if (hasNextResult != AUDIT_SEARCH_NO_MORE_DATA) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (aggregatorInitialized == true && EventAggregator_GetAggregatedEvents(aggregator, queue) != EVENT_AGGREGATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (auditSearchInitialize) {
        if (recordsWithError > 0) {
            Logger_Error("%d records had errors.", recordsWithError);
        }

        if (filteredRecords > 0) {
            Logger_Information("%d records were filtered.", filteredRecords);
        }

        if (result != EVENT_COLLECTOR_OK) {
            Logger_Information("Setting up checkpoint even though connection creation did not finish successfuly.");
        }

        if (AuditSearch_SetCheckpoint(&auditSearch) != AUDIT_SEARCH_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
        }
        AuditSearch_Deinit(&auditSearch);
    }

    return result;
}

EventCollectorResult ConnectionCreateEventCollector_Init() {
    AuditControl audit;
    bool auditInitiated = false;
    EventCollectorResult result = EVENT_COLLECTOR_OK;

    if (AuditControl_Init(&audit) != AUDIT_CONTROL_OK) {
        Logger_Error("Could not init audit control instace.");
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    auditInitiated = true;

    const char* connectionSyscalls[] = { AUDIT_CONTROL_TYPE_CONNECT, AUDIT_CONTROL_TYPE_ACCEPT };
    if (AuditControl_AddRule(&audit, connectionSyscalls, 2, AUDIT_CONTROL_ON_SUCCESS_FILTER) != AUDIT_CONTROL_OK) {
        Logger_Error("Could not set audit to collect connect / accept.");
    }

    EventAggregatorConfiguration aggregatorConfiguration;
    aggregatorConfiguration.event_name = CONNECTION_CREATION_NAME;
    aggregatorConfiguration.event_type = EVENT_TYPE_SECURITY_VALUE;
    aggregatorConfiguration.iotEventType = EVENT_TYPE_CONNECTION_CREATE;
    aggregatorConfiguration.payload_schema_version = CONNECTION_CREATION_PAYLOAD_SCHEMA_VERSION;

    if (EventAggregator_Init(&aggregator, &aggregatorConfiguration) != EVENT_AGGREGATOR_OK) {
        Logger_Error("Could not set initiate event aggregator");
    }
    aggregatorInitialized = true;

cleanup:
    if (auditInitiated) {
        AuditControl_Deinit(&audit);
    }

    return result;
}

void ConnectionCreateEventCollector_Deinit() {
    if (aggregatorInitialized) {
        EventAggregator_Deinit(aggregator);
        aggregator = NULL;
    }
}

EventCollectorResult ConnectionCreationCollector_GetDirection(AuditSearch* auditSearch, ConnectionDirection* direction) {
    const char* syscallName = NULL;
    if (auditSearch == NULL || direction == NULL) {
        return EVENT_COLLECTOR_EXCEPTION;
    }

    if (AuditSearch_InterpretString(auditSearch, AUDIT_CONNECTION_CREATION_SYSCALL, &syscallName) != AUDIT_SEARCH_OK) {
        return EVENT_COLLECTOR_EXCEPTION;
    }

    if (strcmp(syscallName, AUDIT_CONNECTION_CREATION_SYSCALL_CONNECT) == 0) {
        *direction = CONNECTION_DIRECTION_OUTBOUND;
    } else if (strcmp(syscallName, AUDIT_CONNECTION_CREATION_SYSCALL_ACCEPT) == 0) {
        *direction = CONNECTION_DIRECTION_INBOUND;
    } else {
        Logger_Error("different syscall than accept/connect, this shouldn't happen");
        return EVENT_COLLECTOR_EXCEPTION;
    }

    return EVENT_COLLECTOR_OK;
}
