// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include "azure_c_shared_utility/singlylinkedlist.h"
#include "collectors/event_aggregator.h"
#include "internal/time_utils_consts.h"
#include "internal/time_utils.h"
#include "logger.h"
#include "message_schema_consts.h"
#include "utils.h"

typedef struct _AggregatedEventItem {

    JsonObjectWriterHandle json;
    uint32_t hitCount;

} AggregatedEventItem;

struct _EventAggregator  {
    TwinConfigurationEventType iotEventType;
    char* event_type;
    char* event_name;
    char* payload_schema_version;
    SINGLYLINKEDLIST_HANDLE aggregatedEvents;
    time_t lastAggregationTime;
};

static const char* HIT_COUNT_KEY = "HitCount";
static const char* START_TIME_LOCAL_KEY = "StartTimeLocal";
static const char* START_TIME_UTC_KEY = "StartTimeUtc";
static const char* END_TIME_LOCAL_KEY = "EndTimeLocal";
static const char* END_TIME_UTC_KEY = "EndTimeUtc";

typedef struct _EventAggregator EventAggregator;

/**
 * @brief Search for an event in the aggregated events list, search is based on payload equality
 * 
 * @param   list            Handle to the aggregated event list
 * @param   eventPayload    The payload to search
 * @param   outEvent        Out param, pointer to first match
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
AggregatedEventItem* EventAggregator_SearchEvent(SINGLYLINKEDLIST_HANDLE list, JsonObjectWriterHandle eventPayload);

/**
 * @brief Adds new event to the aggregated event list
 * 
 * @param   aggregator              Handle to the aggregator
 * @param   eventPayload            The new event payload
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
EventAggregatorResult EventAggregator_AddNewEvent(EventAggregatorHandle aggregator, JsonObjectWriterHandle eventPayload);

/**
 * @brief Adds aggregation metadata to the given payload
 * 
 * @param   payload                 writer to add the metadata to
 * @param   hitCount                payload hit count
 * @param   aggregationStartTime    aggregation start time
 * @param   aggregationEndTime      aggregation end time
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
EventAggregatorResult EventAggregator_AddAggregationMetadata(JsonObjectWriterHandle payload, uint32_t hitCount, time_t* aggregationStartTime, time_t* aggregationEndTime);

/**
 * @brief Creates a single aggregated event and push it to the queue
 * 
 * @param   aggregator              Handle to the aggregator
 * @param   eventData               A pointer to the event data (payload + hit count)
 * @param   queue                   The queue to push the new event to
 * @param   aggregationEndTime      aggregation end time
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
EventAggregatorResult EventAggregator_CreateSingleAggregatedEvent(EventAggregatorHandle aggregator, AggregatedEventItem* eventData, SyncQueue* queue, time_t* aggregationEndTime);

/**
 * @brief Creates aggregated events from all the events in the aggregator
 * 
 * @param   aggregator              Handle to the aggregator
 * @param   queue                   The queue to push the new event to
 * @param   aggregationEndTime      aggregation end time
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
EventAggregatorResult EventAggregator_CreateAggregatedEvents(EventAggregatorHandle aggregator, time_t* aggregationEndTime, SyncQueue* queue);

/**
 * @brief Clear all stroed events in the aggregator
 * 
 * @param   aggregator              Handle to the aggregator
 * 
 * @return EVENT_AGGREGATOR_OK on success or an error code upon failure
 */
EventAggregatorResult EventAggregator_ClearAggregatedEvents(EventAggregatorHandle aggregator);

/**
 * @brief Deinits list data item and deallocates its memory
 * 
 * @param   item              The item to deinit
 */
void AggregatedEventItem_Deinit(AggregatedEventItem* item);

EventAggregatorResult EventAggregator_Init(EventAggregatorHandle* aggregator, EventAggregatorConfiguration* configurtion) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    EventAggregatorHandle aggregatorObj = NULL;
    if (aggregator == NULL || configurtion == NULL || configurtion->event_name == NULL
        || configurtion->event_type == NULL || configurtion->payload_schema_version == NULL) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    aggregatorObj = malloc(sizeof(EventAggregator));
    if (aggregatorObj == NULL) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(aggregatorObj, 0, sizeof(EventAggregator));
    aggregatorObj->iotEventType = configurtion->iotEventType;
    aggregatorObj->lastAggregationTime = TimeUtils_GetCurrentTime();
    if (Utils_CreateStringCopy(&(aggregatorObj->event_name), configurtion->event_name) != true) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (Utils_CreateStringCopy(&aggregatorObj->payload_schema_version, configurtion->payload_schema_version) != true) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (Utils_CreateStringCopy(&aggregatorObj->event_type, configurtion->event_type) != true) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    aggregatorObj->aggregatedEvents = singlylinkedlist_create();
    if (aggregatorObj->aggregatedEvents == NULL) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    *aggregator = aggregatorObj;

cleanup:
    if (result != EVENT_AGGREGATOR_OK && aggregatorObj != NULL) {
        EventAggregator_Deinit(aggregatorObj);
    }

    return result;
}

void EventAggregator_Deinit(EventAggregatorHandle aggregator) {
    if (aggregator->event_type) {
        free(aggregator->event_type);
    }
    if (aggregator->payload_schema_version) {
        free(aggregator->payload_schema_version);
    }
    if (aggregator->event_name) {
        free(aggregator->event_name);
    }
    if (aggregator->aggregatedEvents){
        EventAggregator_ClearAggregatedEvents(aggregator);
        singlylinkedlist_destroy(aggregator->aggregatedEvents);
    }
        
    free(aggregator);
}

EventAggregatorResult EventAggregator_AggregateEvent(EventAggregatorHandle aggregator, JsonObjectWriterHandle eventPayload) {
    bool isEnabled = false;
    EventAggregatorResult result = EventAggregator_IsAggregationEnabled(aggregator, &isEnabled);
    if (result != EVENT_AGGREGATOR_OK){
        return result;
    }
    if (isEnabled == false) {
        return EVENT_AGGREGATOR_DISABLED;
    }
    
    AggregatedEventItem* eventDataItem = EventAggregator_SearchEvent(aggregator->aggregatedEvents, eventPayload); 
    if (eventDataItem == NULL) {
        result = EventAggregator_AddNewEvent(aggregator, eventPayload);
    } else {
        eventDataItem->hitCount += 1;
    }
    
    return result;
}

EventAggregatorResult EventAggregator_GetAggregatedEvents(EventAggregatorHandle aggregator, SyncQueue* queue) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    time_t now = TimeUtils_GetCurrentTime();

    bool isAggregationEnabled = false;
    result = EventAggregator_IsAggregationEnabled(aggregator, &isAggregationEnabled);
    if (result != EVENT_AGGREGATOR_OK) {
        goto cleanup;
    }

    uint32_t aggregationInterval;
    if (TwinConfigurationEventCollectors_GetAggregationInterval(aggregator->iotEventType, &aggregationInterval) != TWIN_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    
    bool isIntervalPassed = TimeUtils_GetTimeDiff(now, aggregator->lastAggregationTime) > aggregationInterval;

    if (isAggregationEnabled == false || isIntervalPassed == true) {
        result = EventAggregator_CreateAggregatedEvents(aggregator, &now, queue);
        aggregator->lastAggregationTime = now;
    }

cleanup:
    return result;
}

bool EventAggregator_MatchEvent(LIST_ITEM_HANDLE list_item, const void* match_context) {
    JsonObjectWriterHandle matchPayload = (JsonObjectWriterHandle)match_context;
    AggregatedEventItem* currentItem = (AggregatedEventItem*)singlylinkedlist_item_get_value(list_item);

    if (currentItem == NULL || match_context == NULL) {
        return false;
    } else {
        return JsonObjectWriter_Compare(currentItem->json, matchPayload);
    }    
}

AggregatedEventItem* EventAggregator_SearchEvent(SINGLYLINKEDLIST_HANDLE list, JsonObjectWriterHandle eventPayload) {
    LIST_ITEM_HANDLE listItem = singlylinkedlist_find(list, EventAggregator_MatchEvent, eventPayload);
    return listItem == NULL 
            ? NULL
            : (AggregatedEventItem*)singlylinkedlist_item_get_value(listItem);
}

EventAggregatorResult EventAggregator_AddNewEvent(EventAggregatorHandle aggregator, JsonObjectWriterHandle eventPayload) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    AggregatedEventItem* newItem = malloc(sizeof(AggregatedEventItem));
    if (newItem == NULL) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(newItem, 0, sizeof(AggregatedEventItem));
    newItem->hitCount = 1;
    if (JsonObjectWriter_Copy(&newItem->json, eventPayload) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    if (singlylinkedlist_add(aggregator->aggregatedEvents, newItem) == NULL) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != EVENT_AGGREGATOR_OK) {
        AggregatedEventItem_Deinit(newItem);
    }

    return result;
}

EventAggregatorResult EventAggregator_AddAggregationMetadata(JsonObjectWriterHandle payload, uint32_t hitCount, time_t* aggregationStartTime, time_t* aggregationEndTime) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    const uint32_t bufferSize = MAX_TIME_AS_STRING_LENGTH + 1;
    char timeString[bufferSize];
    JsonObjectWriterHandle metadata = NULL;
    bool payloadHasExtraDetails = false;

    if(JsonObjectWriter_StepIn(payload, EXTRA_DETAILS_KEY) != JSON_WRITER_OK){
        if (JsonObjectWriter_Init(&metadata) != JSON_WRITER_OK) {
            result = EVENT_AGGREGATOR_EXCEPTION;
            goto cleanup;
        }
    } else {
        payloadHasExtraDetails = true;
        metadata = payload;
    }
    
    if (JsonObjectWriter_WriteInt(metadata, HIT_COUNT_KEY, hitCount) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(timeString, 0, bufferSize);
    uint32_t currentSize = bufferSize;
    if (TimeUtils_GetTimeAsString(aggregationStartTime, timeString, &currentSize) == false) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(metadata, START_TIME_LOCAL_KEY, timeString) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(timeString, 0, bufferSize);
    currentSize = bufferSize;
    if (TimeUtils_GetLocalTimeAsUTCTimeAsString(aggregationStartTime, timeString, &currentSize) == false) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(metadata, START_TIME_UTC_KEY, timeString) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(timeString, 0, bufferSize);
    currentSize = bufferSize;
    if (TimeUtils_GetTimeAsString(aggregationEndTime, timeString, &currentSize) == false) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(metadata, END_TIME_LOCAL_KEY, timeString) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    memset(timeString, 0, bufferSize);
    currentSize = bufferSize;
    if (TimeUtils_GetLocalTimeAsUTCTimeAsString(aggregationEndTime, timeString, &currentSize) == false) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(metadata, END_TIME_UTC_KEY, timeString) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    if(!payloadHasExtraDetails){
        if (JsonObjectWriter_WriteObject(payload, EXTRA_DETAILS_KEY, metadata) != JSON_WRITER_OK) {
            result = EVENT_AGGREGATOR_EXCEPTION;
            goto cleanup;
        }
    }
cleanup:
    
    if (metadata != NULL && !payloadHasExtraDetails) {
        JsonObjectWriter_Deinit(metadata);
    }
    return result;
}

EventAggregatorResult EventAggregator_CreateSingleAggregatedEvent(EventAggregatorHandle aggregator, AggregatedEventItem* nodeData, SyncQueue* queue, time_t* aggregationEndTime) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    JsonObjectWriterHandle event = NULL;
    JsonArrayWriterHandle payloads = NULL;
    char* output = NULL;
    
    if (JsonObjectWriter_Init(&event) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
   
    if (GenericEvent_AddMetadata(event, EVENT_AGGREGATED_CATEGORY, aggregator->event_name, aggregator->event_type, aggregator->payload_schema_version) != EVENT_COLLECTOR_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    
    if (JsonArrayWriter_Init(&payloads) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    result = EventAggregator_AddAggregationMetadata(nodeData->json, nodeData->hitCount, &aggregator->lastAggregationTime, aggregationEndTime);
    if (result != EVENT_AGGREGATOR_OK){
        goto cleanup;
    }

    if (JsonArrayWriter_AddObject(payloads, nodeData->json) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

    if (GenericEvent_AddPayload(event, payloads) != EVENT_COLLECTOR_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    
    uint32_t outputSize = 0;
    if (JsonObjectWriter_Serialize(event, &output, &outputSize) != JSON_WRITER_OK) {
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }
    
    QueueResultValues qResult = SyncQueue_PushBack(queue, output, outputSize);
    if (qResult == QUEUE_MAX_MEMORY_EXCEEDED) {
        Logger_Warning("Memory limit exceeded, dropping event");
        result = EVENT_AGGREGATOR_OK;
        goto cleanup;
    } else if (qResult != QUEUE_OK){
        result = EVENT_AGGREGATOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != EVENT_AGGREGATOR_OK) {
        if (output != NULL) {
            free(output);
        }
    }

    if (payloads != NULL) {
        JsonArrayWriter_Deinit(payloads);
    }

    if (event != NULL) {
        JsonObjectWriter_Deinit(event);
    }

    return result;
}

void AggregatedEventItem_Deinit(AggregatedEventItem* item) {
    if (item != NULL) {
        if (item->json != NULL) {
            JsonObjectWriter_Deinit(item->json);
        }
        free(item);
    }
}

EventAggregatorResult EventAggregator_ClearAggregatedEvents(EventAggregatorHandle aggregator) {
    LIST_ITEM_HANDLE listItem = NULL;
    while ((listItem = singlylinkedlist_get_head_item(aggregator->aggregatedEvents)) != NULL)
    {
        AggregatedEventItem* dataItem = (AggregatedEventItem*)singlylinkedlist_item_get_value(listItem);
        AggregatedEventItem_Deinit(dataItem);
        singlylinkedlist_remove(aggregator->aggregatedEvents, listItem);
    }

    return EVENT_AGGREGATOR_OK;
}

EventAggregatorResult EventAggregator_CreateAggregatedEvents(EventAggregatorHandle aggregator, time_t* aggregationEndTime, SyncQueue* queue) {
    EventAggregatorResult result = EVENT_AGGREGATOR_OK;
    LIST_ITEM_HANDLE current = singlylinkedlist_get_head_item(aggregator->aggregatedEvents);

    while (current != NULL) {
        AggregatedEventItem* dataItem = (AggregatedEventItem*)singlylinkedlist_item_get_value(current);
        if (dataItem != NULL) {
            if (EventAggregator_CreateSingleAggregatedEvent(aggregator, dataItem, queue, aggregationEndTime) != EVENT_AGGREGATOR_OK) {
                result = EVENT_AGGREGATOR_EXCEPTION;
            }
        } else {
            result = EVENT_AGGREGATOR_EXCEPTION;
        }
        
        current = singlylinkedlist_get_next_item(current);        
    }

    if (EventAggregator_ClearAggregatedEvents(aggregator) != EVENT_AGGREGATOR_OK) {
        return EVENT_AGGREGATOR_EXCEPTION;
    }

    return result;
}

EventAggregatorResult EventAggregator_IsAggregationEnabled(EventAggregatorHandle aggregator, bool* isEnabled) {
    if (TwinConfigurationEventCollectors_GetAggregationEnabled(aggregator->iotEventType, isEnabled) != TWIN_OK) {
        return EVENT_AGGREGATOR_EXCEPTION;
    }

    return EVENT_AGGREGATOR_OK;
}
