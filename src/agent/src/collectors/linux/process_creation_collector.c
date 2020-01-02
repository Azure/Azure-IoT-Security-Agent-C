// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "collectors/process_creation_collector.h"

#include <libaudit.h>
#include <stdio.h>
#include <stdlib.h>

#include "collectors/event_aggregator.h"
#include "collectors/generic_event.h"
#include "collectors/linux/generic_audit_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "logger.h"
#include "message_schema_consts.h"
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/linux/audit/audit_search_record.h"
#include "os_utils/linux/audit/audit_search.h"
#include "twin_configuration_defs.h"
#include "utils.h"
#include "azure_c_shared_utility/map.h"


static const char AUDIT_PROCESS_CREATION_TYPE[] = "EXECVE";
static const char AUDIT_PROCESS_INTEGRITY_TYPE[] = "INTEGRITY_RULE";
static const char* AUDIT_PROCESS_CREATION_TYPES[] = {AUDIT_PROCESS_CREATION_TYPE, AUDIT_PROCESS_INTEGRITY_TYPE};
static uint32_t AUDIT_USER_CREATION_TYPES_COUNT = sizeof(AUDIT_PROCESS_CREATION_TYPES) / sizeof(AUDIT_PROCESS_CREATION_TYPES[0]);
static const char AUDIT_PROCESS_CREATION_CHECKPOINT_FILE[] = "/var/tmp/processCreationCheckpoint";
static const char AUDIT_PROCESS_CREATION_EXECUTEABLE[] = "exe";
static const char AUDIT_PROCESS_CREATION_EXECUTEABLE_HASH[] = "hash";
static const char AUDIT_PROCESS_CREATION_EXECUTEABLE_PATH[] = "file";
static const char AUDIT_PROCESS_CREATION_USER_ID[] = "uid";
static const char AUDIT_PROCESS_CREATION_PROCESS_ID[] = "pid";
static const char AUDIT_PROCESS_CREATION_PARENT_PROCESS_ID[] = "ppid";
static const int AUDIT_EXECVE_RECORD_TYPE = 1309; //FIXME: we need to see that in all linux distrothis is the same
static const char AUDIT_ARGC[] = "argc";

#define AUDIT_MAX_PARAM_LEN 10
static MAP_HANDLE executableHashMap = NULL;
static EventAggregatorHandle aggregator = NULL;
static bool aggregatorInitialized = false;

/**
 * @brief Resda the command line from the audit event and write it to the payload.
 * 
 * @param   auditSearch             The search instacne.
 * @param   processEventPayload     The event payload to write the command line to.
 * 
 * @return EVENT_COLLECTOR_OK on success or the coressponind error on failure.
 */
EventCollectorResult ProcessCreationCollector_ReadCommandLine(AuditSearch* auditSearch, JsonObjectWriterHandle processEventPayload);

/**
 * @brief Generates the payload for the process creation event.
 * 
 * @param   auditSearch             The search instacne.
 * @param   processEventPayload     The event writer of the current process creation event.
 * 
 * @return EVENT_COLLECTOR_OK on success or the coressponind error on failure.
 */
EventCollectorResult ProcessCreationCollector_GeneratePayload(AuditSearch* auditSearch, JsonObjectWriterHandle processEventPayload);

/**
 * @brief Generates a single process creation event and adds it to the queue.
 * 
 * @param   auditSearch     The search instacne.
 * @param   queue           The out queue of events.
 * 
 * @return EVENT_COLLECTOR_OK on success or the coressponind error on failure.
 */
EventCollectorResult ProcessCreationCollector_CreateSingleEvent(AuditSearch* auditSearch, SyncQueue* queue);

/**
 * @brief Creates an event ready for aggregation 
 * 
 * @param   auditSearch         The search audit.
 * @param   aggregator          Handle to event aggregator
 * 
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ProcessCreationCollector_CreateEventForAgrregation(AuditSearch* auditSearch, EventAggregatorHandle aggregator);

/**
 * @brief Populates the executables hash dictionary
 * 
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ProcessCreationCollector_PopulateExecutableHashMap();

/**
 * @brief Adds an entry to executable hash map. 
 *        In case that the key(executableName) exists it updates its value.
 * 
 * @param   auditSearch         The search audit.
 * 
 * @return EVENT_COLLECTOR_OK on success.
 */
EventCollectorResult ProcessCreationCollector_AddEntryToExecutableHashMap(AuditSearch* auditSearch);

EventCollectorResult ProcessCreationCollector_GetEvents(SyncQueue* queue) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    bool auditSearchInitialize = false;
    AuditSearch auditSearch;
    uint32_t recordsWithError = 0;

    if (AuditSearch_InitMultipleSearchCriteria(&auditSearch, AUDIT_SEARCH_CRITERIA_TYPE, AUDIT_PROCESS_CREATION_TYPES, AUDIT_USER_CREATION_TYPES_COUNT, AUDIT_PROCESS_CREATION_CHECKPOINT_FILE) != AUDIT_SEARCH_OK) {
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
            result = ProcessCreationCollector_CreateEventForAgrregation(&auditSearch, aggregator);
        } else {
            result = ProcessCreationCollector_CreateSingleEvent(&auditSearch, queue);
        }
        
        if (result == EVENT_COLLECTOR_RECORD_HAS_ERRORS) {
            ++recordsWithError;
            result = EVENT_COLLECTOR_OK;
        } else if (result == EVENT_COLLECTOR_OUT_OF_MEM){
            result = EVENT_COLLECTOR_OK;
        } else if (result != EVENT_COLLECTOR_OK) {
            goto cleanup;
        }
        
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

        if (result != EVENT_COLLECTOR_OK) {
            Logger_Information("Setting up checkpoint even though process creation run did not finish successfuly.");
        }

        if (AuditSearch_SetCheckpoint(&auditSearch) != AUDIT_SEARCH_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
        }
        AuditSearch_Deinit(&auditSearch);
    }

    return result;
}

EventCollectorResult ProcessCreationCollector_GeneratePayload(AuditSearch* auditSearch, JsonObjectWriterHandle processEventPayload) {
    
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    const char* hash = NULL;
    const char* executable = NULL;
    JsonObjectWriterHandle extraDetails = NULL;

    if (AuditSearch_InterpretString(auditSearch, AUDIT_PROCESS_CREATION_EXECUTEABLE, &executable) != AUDIT_SEARCH_OK){
        return EVENT_COLLECTOR_EXCEPTION;
    }
    if (JsonObjectWriter_WriteString(processEventPayload, PROCESS_CREATION_EXECUTABLE_KEY, executable) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = ProcessCreationCollector_ReadCommandLine(auditSearch, processEventPayload);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    result = GenericAuditEvent_HandleStringValue(processEventPayload, auditSearch, AUDIT_PROCESS_CREATION_USER_ID, PROCESS_CREATION_USER_ID_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }    

    result = GenericAuditEvent_HandleIntValue(processEventPayload, auditSearch, AUDIT_PROCESS_CREATION_PROCESS_ID, PROCESS_CREATION_PROCESS_ID_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }
    
    result = GenericAuditEvent_HandleIntValue(processEventPayload, auditSearch, AUDIT_PROCESS_CREATION_PARENT_PROCESS_ID, PROCESS_CREATION_PARENT_PROCESS_ID_KEY, false);
    if (result != EVENT_COLLECTOR_OK) {
        return result;
    }

    result = ProcessCreationCollector_AddEntryToExecutableHashMap(auditSearch);
    if (result != EVENT_COLLECTOR_OK){
        return result;
    }

    hash = Map_GetValueFromKey(executableHashMap, executable);
    hash = (hash != NULL) ? hash : "";
    if (JsonObjectWriter_Init(&extraDetails) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(extraDetails, PROCESS_CREATION_EXECUTABLE_HASH_KEY, hash) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteObject(processEventPayload, EXTRA_DETAILS_KEY, extraDetails) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (extraDetails != NULL) {
        JsonObjectWriter_Deinit(extraDetails);
    }    

    return result;
}

EventCollectorResult ProcessCreationCollector_CreateEventForAgrregation(AuditSearch* auditSearch, EventAggregatorHandle aggregator) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle processEventPayload = NULL;
    
    if (JsonObjectWriter_Init(&processEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = ProcessCreationCollector_GeneratePayload(auditSearch, processEventPayload);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (JsonObjectWriter_WriteInt(processEventPayload, PROCESS_CREATION_PROCESS_ID_KEY, 0) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteInt(processEventPayload, PROCESS_CREATION_PARENT_PROCESS_ID_KEY, 0) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (EventAggregator_AggregateEvent(aggregator, processEventPayload) != EVENT_AGGREGATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
cleanup:

    if (processEventPayload != NULL) {
        JsonObjectWriter_Deinit(processEventPayload);
    }

    return result;
}

EventCollectorResult ProcessCreationCollector_CreateSingleEvent(AuditSearch* auditSearch, SyncQueue* queue) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;

    JsonObjectWriterHandle processEvent = NULL;
    JsonObjectWriterHandle processEventPayload = NULL;
    JsonArrayWriterHandle payloads = NULL;
    char* output = NULL;
    
    if (JsonObjectWriter_Init(&processEvent) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t eventTimeInSeconds = 0;
    if (AuditSearch_GetEventTime(auditSearch, &eventTimeInSeconds) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_RECORD_HAS_ERRORS;
        goto cleanup;
    }
    time_t eventTime = (time_t)eventTimeInSeconds;
    
    if (GenericEvent_AddMetadataWithTimes(processEvent, EVENT_TRIGGERED_CATEGORY, PROCESS_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION, &eventTime) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_Init(&processEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = ProcessCreationCollector_GeneratePayload(auditSearch, processEventPayload);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }
    
    if (JsonArrayWriter_Init(&payloads) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonArrayWriter_AddObject(payloads, processEventPayload) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = GenericEvent_AddPayload(processEvent, payloads); 
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }
    
    uint32_t outputSize = 0;
    if (JsonObjectWriter_Serialize(processEvent, &output, &outputSize) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    
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

    if (processEventPayload != NULL) {
        JsonObjectWriter_Deinit(processEventPayload);
    }

    if (processEvent != NULL) {
        JsonObjectWriter_Deinit(processEvent);
    }

    if (payloads != NULL) {
        JsonArrayWriter_Deinit(payloads);
    }

    return result;
}

EventCollectorResult ProcessCreationCollector_ReadCommandLine(AuditSearch* auditSearch, JsonObjectWriterHandle processEventPayload) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    char* commandLineBuffer = NULL;
    if (AuditSearchRecord_Goto(auditSearch, AUDIT_EXECVE_RECORD_TYPE) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t maxLen = 0;
    if (AuditSearchRecord_MaxRecordLength(auditSearch, &maxLen) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    commandLineBuffer = malloc(maxLen);
    if (commandLineBuffer == NULL) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t currentBufferSize = maxLen;
    char* currentCommand = commandLineBuffer;

    char item[AUDIT_MAX_PARAM_LEN] = "";
    int argCount = 0;
    if (AuditSearchRecord_ReadInt(auditSearch, AUDIT_ARGC, &argCount) != AUDIT_SEARCH_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    for (uint32_t i = 0; i < argCount; ++i) {
        if (snprintf(item, sizeof(item), "a%d", i) < 0) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
        const char* currentArg = NULL;
        if (AuditSearchRecord_InterpretString(auditSearch, item, &currentArg) != AUDIT_SEARCH_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
        if (!Utils_ConcatenateToString(&currentCommand, &currentBufferSize, "%s%s", i > 0 ? " " : "", currentArg)) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
    }

    if (JsonObjectWriter_WriteString(processEventPayload, PROCESS_CREATION_COMMAND_LINE_KEY, commandLineBuffer) != JSON_WRITER_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
    }

cleanup:
    if (commandLineBuffer != NULL) {
        free(commandLineBuffer);
    }
    return result;
}

EventCollectorResult ProcessCreationCollector_PopulateExecutableHashMap() {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    executableHashMap = Map_Create(NULL);
    bool auditSearchInitialize = false;
    AuditSearch auditSearch;

    if (executableHashMap == NULL){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (AuditSearch_Init(&auditSearch, AUDIT_SEARCH_CRITERIA_TYPE, AUDIT_PROCESS_INTEGRITY_TYPE, NULL) != AUDIT_SEARCH_OK){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    auditSearchInitialize = true;

    AuditSearchResultValues hasNextResult = AuditSearch_GetNext(&auditSearch);
    while (hasNextResult == AUDIT_SEARCH_HAS_MORE_DATA) {
        result = ProcessCreationCollector_AddEntryToExecutableHashMap(&auditSearch);
        if (result != EVENT_COLLECTOR_OK) {
            goto cleanup;
        }
        hasNextResult = AuditSearch_GetNext(&auditSearch);
    }

cleanup:
    if (auditSearchInitialize){
        AuditSearch_Deinit(&auditSearch);
    }
    return result;

}

EventCollectorResult ProcessCreationCollector_AddEntryToExecutableHashMap(AuditSearch* auditSearch) {
    AuditSearchResultValues result = AUDIT_SEARCH_OK;
    const char* executable = NULL;
    const char* hash = NULL;

    result = AuditSearch_InterpretString(auditSearch, AUDIT_PROCESS_CREATION_EXECUTEABLE_HASH, &hash);
    if (result != AUDIT_SEARCH_OK && result != AUDIT_SEARCH_FIELD_DOES_NOT_EXIST) {
        return EVENT_COLLECTOR_EXCEPTION;
    }
    if (hash != NULL){
        char* Hash = NULL;
        // hash value starts with "\"sha1:" and ends with "\"" so we want to clean those characters
        if(!Utils_Substring(hash, &Hash, 6,1)){
            return EVENT_COLLECTOR_EXCEPTION;
        }
        result = AuditSearch_InterpretString(auditSearch, AUDIT_PROCESS_CREATION_EXECUTEABLE_PATH, &executable);
        if (result != AUDIT_SEARCH_OK && result != AUDIT_SEARCH_FIELD_DOES_NOT_EXIST) {
            return EVENT_COLLECTOR_EXCEPTION;
        }
        MAP_RESULT mapResult = Map_AddOrUpdate(executableHashMap, executable, Hash);
        if (mapResult != MAP_OK && mapResult != MAP_KEYEXISTS){
            result = EVENT_COLLECTOR_EXCEPTION;
        }
    }

    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ProcessCreationCollector_Init() {
    AuditControl audit;
    bool auditInitiated = false;
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    size_t count = 0;

    if (AuditControl_Init(&audit) != AUDIT_CONTROL_OK) {
        Logger_Error("Could not init audit control instace.");
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    auditInitiated = true;

    const char* processSyscalls[] = {AUDIT_CONTROL_TYPE_EXECVE, AUDIT_CONTROL_TYPE_EXECVEAT};

    if (AuditControl_AddRule(&audit, processSyscalls, 2, NULL) != AUDIT_CONTROL_OK) {
        Logger_Error("Could not set audit to collect execve.");
    }

    EventAggregatorConfiguration aggregatorConfiguration;
    aggregatorConfiguration.event_name = PROCESS_CREATION_NAME;
    aggregatorConfiguration.event_type = EVENT_TYPE_SECURITY_VALUE;
    aggregatorConfiguration.iotEventType = EVENT_TYPE_PROCESS_CREATE;
    aggregatorConfiguration.payload_schema_version = PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION;
    
    if (EventAggregator_Init(&aggregator, &aggregatorConfiguration) != EVENT_AGGREGATOR_OK) {
        Logger_Error("Could not set initiate event aggregator");
    }

    aggregatorInitialized = true;
    if(ProcessCreationCollector_PopulateExecutableHashMap() != EVENT_COLLECTOR_OK){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (!(Utils_GetMapSize(executableHashMap, &count))){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (count == 0){
        Logger_Error("Could not collect auditd integrity_rule events. It might happen if you haven't rebooted the machine after the agent installation.");
    }

cleanup:
    if (auditInitiated) {
        AuditControl_Deinit(&audit);
    }

    return result;
}

void ProcessCreationCollector_Deinit() {
    if (aggregatorInitialized) {
        EventAggregator_Deinit(aggregator);
        aggregator = NULL;
    }
    if (executableHashMap != NULL){
        Map_Destroy(executableHashMap);
    }
}