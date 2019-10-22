// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "twin_configuration_event_collectors.h"

#include <stdbool.h>

#include "azure_c_shared_utility/lock.h"

#include "utils.h"
#include "internal/time_utils.h"
#include "internal/time_utils_consts.h"
#include "twin_configuration_utils.h"

static const char* PRIORITY_HIGH = "high";
static const char* PRIORITY_LOW = "low";
static const char* PRIORITY_OFF = "off";

static const TwinConfigurationEventPriority PROCESS_CREATE_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority LISTENING_PORTS_DEFAULT_PRIORITY = EVENT_PRIORITY_HIGH;
static const TwinConfigurationEventPriority SYSTEM_INFORMATION_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority LOCAL_USERS_DEFAULT_PRIORITY = EVENT_PRIORITY_HIGH;
static const TwinConfigurationEventPriority LOGIN_DEFAULT_PRIORITY = EVENT_PRIORITY_HIGH;
static const TwinConfigurationEventPriority CONNECTION_CREATE_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority FIREWALL_CONFIGURATION_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority BASELINE_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority DIAGNOSTIC_DEFAULT_PRIORITY = EVENT_PRIORITY_LOW;
static const TwinConfigurationEventPriority OPERATIONAL_EVENT_DEFAULT_PRIORITY = EVENT_PRIORITY_OPERATIONAL;

static const bool PROCESS_CREATE_AGGREGATION_ENABLED = true;
static const bool CONNECTION_CREATE_AGGREGATION_ENABLED = true;
static const uint32_t PROCESS_CREATE_AGGREGATION_INTERVAL = MILLISECONDS_IN_AN_HOUR;
static const uint32_t CONNECTION_CREATE_AGGREGATION_INTERVAL = MILLISECONDS_IN_AN_HOUR;

typedef struct _TwinConfigurationEventCollectors {
    TwinConfigurationEventPriority processCreatePriority;
    TwinConfigurationEventPriority listeningPortsPriority;
    TwinConfigurationEventPriority systemInformationPriority;
    TwinConfigurationEventPriority localUsersPriority;
    TwinConfigurationEventPriority loginPriority;
    TwinConfigurationEventPriority connectionCreatePriority;
    TwinConfigurationEventPriority firewallConfigurationPriority;
    TwinConfigurationEventPriority baselinePriority;
    TwinConfigurationEventPriority diagnostic;
    TwinConfigurationEventPriority operational;
    bool processCreateAggregationEnabled;
    bool connectionCreateAggregationEnabled;
    uint32_t processCreateAggregationInterval;
    uint32_t connectionCreateAggregationInterval;


    LOCK_HANDLE lock;
    bool isLocked;
} TwinConfigurationEventCollectors;

static TwinConfigurationEventCollectors eventPriorities;

/**
 * @brief Set the priorities of all the events.
 * 
 * @param   propertiesReader    The json reader of the preperties.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SetValues(JsonObjectReaderHandle propertiesReader);

/**
 * @brief Set a single event's priority.
 * 
 * @param   propertiesReader    The json reader of the preperties.
 * @param   key                 The event priority key in the json.
 * @param   priorityField       The field of the event priority.
 * @param   defaultValue        The dafult priority for this event.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleValues(JsonObjectReaderHandle propertiesReader, const char* key, TwinConfigurationEventPriority* priorityField, TwinConfigurationEventPriority defaultValue);

/**
 * @brief Set a single boolean value
 * 
 * @param   propertiesReader    The json reader of the preperties.
 * @param   key                 The event key in the json.
 * @param   field               The field of boolean type
 * @param   defaultValue        The dafult value for this field
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleBoolValue(JsonObjectReaderHandle propertiesReader, const char* key, bool* field, bool defaultValue);

/**
 * @brief Set a single uint32_t value
 * 
 * @param   propertiesReader    The json reader of the preperties.
 * @param   key                 The event key in the json.
 * @param   priorityField       The field of uint32_t type
 * @param   defaultValue        The dafult value for this field.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleUintTimeValue(JsonObjectReaderHandle propertiesReader, const char* key, uint32_t* field, uint32_t defaultValue);


/**
 * @brief returns the enum type representing this value.
 * 
 * @param   str         The str representation of the priority.
 * @param   priority    Out param. The enum representing the given priority.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_PriorityAsEnum(const char* str, TwinConfigurationEventPriority* priority);

/**
 * @brief returns the string value reprsenting this enum
 * 
 * @param   priority            the given enum priority
 * @param   priorityAsString    Out param. The string representing the given priority.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_PriorityEnumAsString(TwinConfigurationEventPriority priority, char const **  priorityAsString);
/**
 * @brief Returns the priority of the wanted event type.
 *          This function should be called only after the config lock is locked.
 * 
 * @param   eventType   The wanted event type.
 * @param   priority     Out param. The wanted priority.
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SafeGetPriority(TwinConfigurationEventType eventType, TwinConfigurationEventPriority* prioriy);

/**
 * @brief writes the current event priorities object
 * 
 * @param   prioritiesJson   json object writer handle
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfigurationEventCollectors_SafeGetPrioritiesJson(JsonObjectWriterHandle prioritiesJson);

TwinConfigurationResult TwinConfigurationEventCollectors_Init() {
    eventPriorities.isLocked = false;
    eventPriorities.lock = Lock_Init();
    if (eventPriorities.lock == NULL) {
        return TWIN_LOCK_EXCEPTION; 
    }

    eventPriorities.processCreatePriority = PROCESS_CREATE_DEFAULT_PRIORITY;
    eventPriorities.listeningPortsPriority = LISTENING_PORTS_DEFAULT_PRIORITY;
    eventPriorities.systemInformationPriority = SYSTEM_INFORMATION_DEFAULT_PRIORITY;
    eventPriorities.localUsersPriority = LOCAL_USERS_DEFAULT_PRIORITY;
    eventPriorities.loginPriority = LOGIN_DEFAULT_PRIORITY;
    eventPriorities.connectionCreatePriority = CONNECTION_CREATE_DEFAULT_PRIORITY;
    eventPriorities.firewallConfigurationPriority = FIREWALL_CONFIGURATION_DEFAULT_PRIORITY;
    eventPriorities.baselinePriority = BASELINE_DEFAULT_PRIORITY;
    eventPriorities.diagnostic = DIAGNOSTIC_DEFAULT_PRIORITY;
    eventPriorities.operational = OPERATIONAL_EVENT_DEFAULT_PRIORITY;
    eventPriorities.processCreateAggregationEnabled = PROCESS_CREATE_AGGREGATION_ENABLED;
    eventPriorities.processCreateAggregationInterval = PROCESS_CREATE_AGGREGATION_INTERVAL;
    eventPriorities.connectionCreateAggregationEnabled = CONNECTION_CREATE_AGGREGATION_ENABLED;
    eventPriorities.connectionCreateAggregationInterval = CONNECTION_CREATE_AGGREGATION_INTERVAL;

    return TWIN_OK;
}

void TwinConfigurationEventCollectors_Deinit() {
    if (eventPriorities.lock != NULL) {
        Lock_Deinit(eventPriorities.lock);
        eventPriorities.lock = NULL;
    }
}

bool TwinConfigurationEventCollectors_Lock() {
    if (eventPriorities.isLocked == true 
        || Lock(eventPriorities.lock) != LOCK_OK) {
        return false;
    }

    eventPriorities.isLocked = true;
    return true;
}

bool TwinConfigurationEventCollectors_Unlock() {
    if (eventPriorities.isLocked == true
        && Unlock(eventPriorities.lock) != LOCK_OK ) {
        return false;
    }

    eventPriorities.isLocked = false;
    return true;
}

TwinConfigurationResult TwinConfigurationEventCollectors_Update(JsonObjectReaderHandle propertiesReader) {
    TwinConfigurationResult returnValue = TWIN_OK;
    if (TwinConfigurationEventCollectors_Lock() == false) {
        returnValue = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    returnValue = TwinConfigurationEventCollectors_SetValues(propertiesReader);
    
cleanup:
    if (TwinConfigurationEventCollectors_Unlock() == false) {
        returnValue = TWIN_LOCK_EXCEPTION;
    }

    return returnValue;
}

TwinConfigurationResult TwinConfigurationEventCollectors_GetPriority(TwinConfigurationEventType eventType, TwinConfigurationEventPriority* prioriy) {
    TwinConfigurationResult result = TWIN_OK;
    if (TwinConfigurationEventCollectors_Lock() == false) {
        result = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SafeGetPriority(eventType, prioriy);
    
cleanup:
    if (TwinConfigurationEventCollectors_Unlock() == false) {
        result = TWIN_LOCK_EXCEPTION;
    }
    
    return result;
}

TwinConfigurationResult TwinConfigurationEventCollectors_GetAggregationEnabled(TwinConfigurationEventType eventType, bool* isEnabled) {
    TwinConfigurationResult result = TWIN_OK;
    if (TwinConfigurationEventCollectors_Lock() == false) {
        result = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    switch (eventType) {
        case EVENT_TYPE_PROCESS_CREATE:
            *isEnabled = eventPriorities.processCreateAggregationEnabled;
            break;
        case EVENT_TYPE_CONNECTION_CREATE:
            *isEnabled = eventPriorities.connectionCreateAggregationEnabled;
            break;
        default:
            return TWIN_EXCEPTION;
    }
    
cleanup:
    if (TwinConfigurationEventCollectors_Unlock() == false) {
        result = TWIN_LOCK_EXCEPTION;
    }
    
    return result;
}

TwinConfigurationResult TwinConfigurationEventCollectors_GetAggregationInterval(TwinConfigurationEventType eventType, uint32_t* interval) {
    TwinConfigurationResult result = TWIN_OK;
    if (TwinConfigurationEventCollectors_Lock() == false) {
        result = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    switch (eventType) {
        case EVENT_TYPE_PROCESS_CREATE:
            *interval = eventPriorities.processCreateAggregationInterval;
            break;
        case EVENT_TYPE_CONNECTION_CREATE:
            *interval = eventPriorities.connectionCreateAggregationInterval;
            break;
        default:
            return TWIN_EXCEPTION;
    }
    
cleanup:
    if (TwinConfigurationEventCollectors_Unlock() == false) {
        result = TWIN_LOCK_EXCEPTION;
    }
    
    return result;
}

TwinConfigurationResult  TwinConfigurationEventCollectors_GetPrioritiesJson(JsonObjectWriterHandle prioritiesJson){
    TwinConfigurationResult result = TWIN_OK;
    if (TwinConfigurationEventCollectors_Lock() == false) {
        result = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SafeGetPrioritiesJson(prioritiesJson);
    
cleanup:
    if (TwinConfigurationEventCollectors_Unlock() == false) {
        result = TWIN_LOCK_EXCEPTION;
    }
    
    return result;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_SetValues(JsonObjectReaderHandle propertiesReader) {
    TwinConfigurationResult result = TWIN_OK; 
    TwinConfigurationEventCollectors newPriorities = { 0 };

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, PROCESS_CREATE_PRIORITY_KEY, &(newPriorities.processCreatePriority), PROCESS_CREATE_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, LISTENING_PORTS_PRIORITY_KEY, &(newPriorities.listeningPortsPriority), LISTENING_PORTS_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, SYSTEM_INFORMATION_PRIORITY_KEY, &(newPriorities.systemInformationPriority), SYSTEM_INFORMATION_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, LOCAL_USERS_PRIORITY_KEY, &(newPriorities.localUsersPriority), LOCAL_USERS_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, LOGIN_PRIORITY_KEY, &(newPriorities.loginPriority), LOGIN_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, CONNECTION_CREATE_PRIORITY_KEY, &(newPriorities.connectionCreatePriority), CONNECTION_CREATE_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, FIREWALL_CONFIGURATION_PRIORITY_KEY, &(newPriorities.firewallConfigurationPriority), FIREWALL_CONFIGURATION_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, BASELINE_PRIORITY_KEY, &(newPriorities.baselinePriority), BASELINE_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, DIAGNOSTIC_PRIORITY_KEY, &(newPriorities.diagnostic), DIAGNOSTIC_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleValues(propertiesReader, OPERATIONAL_EVENT_KEY, &(newPriorities.operational), OPERATIONAL_EVENT_DEFAULT_PRIORITY);
    if (result != TWIN_OK) {
        goto cleanup;
    }
    //Operational events can be off/operational prio
    eventPriorities.operational = eventPriorities.operational == EVENT_PRIORITY_OFF ? EVENT_PRIORITY_OFF : EVENT_PRIORITY_OPERATIONAL;

    result = TwinConfigurationEventCollectors_SetSingleBoolValue(propertiesReader, PROCESS_CREATE_AGGREGATION_ENABLED_KEY, &(newPriorities.processCreateAggregationEnabled), PROCESS_CREATE_AGGREGATION_ENABLED);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleUintTimeValue(propertiesReader, PROCESS_CREATE_AGGREGATION_INTERVAL_KEY, &(newPriorities.processCreateAggregationInterval), PROCESS_CREATE_AGGREGATION_INTERVAL);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleBoolValue(propertiesReader, CONNECTION_CREATE_AGGREGATION_ENABLED_KEY, &(newPriorities.connectionCreateAggregationEnabled), CONNECTION_CREATE_AGGREGATION_ENABLED);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_SetSingleUintTimeValue(propertiesReader, CONNECTION_CREATE_AGGREGATION_INTERVAL_KEY, &(newPriorities.connectionCreateAggregationInterval), CONNECTION_CREATE_AGGREGATION_INTERVAL);
    if (result != TWIN_OK) {
        goto cleanup;
    }

cleanup:
    if (result == TWIN_OK){
        newPriorities.lock = eventPriorities.lock;
        newPriorities.isLocked = eventPriorities.isLocked;
        memcpy(&eventPriorities, &newPriorities, sizeof(TwinConfigurationEventCollectors));
    }
    
    return result;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleValues(JsonObjectReaderHandle propertiesReader, const char* key, TwinConfigurationEventPriority* priorityField, TwinConfigurationEventPriority defaultValue) {
    char* strValue = NULL;
    TwinConfigurationResult result = TwinConfigurationUtils_GetConfigurationStringValueFromJson(propertiesReader, key, &strValue);
    if (result == TWIN_CONF_NOT_EXIST) {
        *priorityField = defaultValue;
        return TWIN_OK;
    } else if (result != TWIN_OK) {
        return result;
    }
    
    TwinConfigurationEventPriority priority;
    result = TwinConfigurationEventCollectors_PriorityAsEnum(strValue, &priority);
    if (result != TWIN_OK) {
        return result;
    }
    *priorityField = priority;

    return TWIN_OK;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleBoolValue(JsonObjectReaderHandle propertiesReader, const char* key, bool* field, bool defaultValue) {
    TwinConfigurationResult result = TwinConfigurationUtils_GetConfigurationBoolValueFromJson(propertiesReader, key, field);
    if (result == TWIN_CONF_NOT_EXIST) {
        *field = defaultValue;
        result = TWIN_OK;
    }

    return result;
}


static TwinConfigurationResult TwinConfigurationEventCollectors_SetSingleUintTimeValue(JsonObjectReaderHandle propertiesReader, const char* key, uint32_t* field, uint32_t defaultValue) {
    TwinConfigurationResult result = TwinConfigurationUtils_GetConfigurationTimeValueFromJson(propertiesReader, key, field);
    if (result == TWIN_CONF_NOT_EXIST) {
        *field = defaultValue;
        result = TWIN_OK;
    }
    
    return result;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_PriorityAsEnum(const char* str, TwinConfigurationEventPriority* priority) {
    if (Utils_UnsafeAreStringsEqual(str, PRIORITY_HIGH, false)) {
        *priority = EVENT_PRIORITY_HIGH;
    } else if (Utils_UnsafeAreStringsEqual(str, PRIORITY_LOW, false )) {
        *priority = EVENT_PRIORITY_LOW;
    } else if (Utils_UnsafeAreStringsEqual(str, PRIORITY_OFF, false)) {
        *priority = EVENT_PRIORITY_OFF;
    } else {
        return TWIN_PARSE_EXCEPTION;
    }
    return TWIN_OK;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_PriorityEnumAsString(TwinConfigurationEventPriority priority, char const **  priorityAsString){
    *priorityAsString = NULL;
    if (priority == EVENT_PRIORITY_HIGH || priority == EVENT_PRIORITY_OPERATIONAL){
        *priorityAsString = PRIORITY_HIGH;
    } else if (priority == EVENT_PRIORITY_LOW){
        *priorityAsString = PRIORITY_LOW;
    } else if (priority == EVENT_PRIORITY_OFF){
        *priorityAsString = PRIORITY_OFF;
    } else {
        return TWIN_EXCEPTION;
    }
    return TWIN_OK;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_SafeGetPriority(TwinConfigurationEventType eventType, TwinConfigurationEventPriority* prioriy) {
    switch (eventType) {
        case EVENT_TYPE_PROCESS_CREATE:
            *prioriy = eventPriorities.processCreatePriority;
            break;
        case EVENT_TYPE_LISTENING_PORTS:
            *prioriy = eventPriorities.listeningPortsPriority;
            break;
        case EVENT_TYPE_SYSTEM_INFORMATION:
            *prioriy = eventPriorities.systemInformationPriority;
            break;
        case EVENT_TYPE_LOCAL_USERS:
            *prioriy = eventPriorities.localUsersPriority;
            break;
        case EVENT_TYPE_USER_LOGIN:
            *prioriy = eventPriorities.loginPriority;
            break;
        case EVENT_TYPE_CONNECTION_CREATE:
            *prioriy = eventPriorities.connectionCreatePriority;
            break;
        case EVENT_TYPE_FIREWALL_CONFIGURATION:
            *prioriy = eventPriorities.firewallConfigurationPriority;
            break;
        case EVENT_TYPE_BASELINE:
            *prioriy = eventPriorities.baselinePriority;
            break;
        case EVENT_TYPE_DIAGNOSTIC:
            *prioriy = eventPriorities.diagnostic;
            break;
        case EVENT_TYPE_OPERATIONAL_EVENT:
            *prioriy = eventPriorities.operational;
            break;
        default:
            return TWIN_EXCEPTION;
    }
    return TWIN_OK;
}

static TwinConfigurationResult TwinConfigurationEventCollectors_SafeGetPrioritiesJson(JsonObjectWriterHandle prioritiesJson){
    TwinConfigurationResult result = TWIN_OK;

    const char* priorityAsString;
    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.baselinePriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, BASELINE_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.connectionCreatePriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, CONNECTION_CREATE_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.diagnostic, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, DIAGNOSTIC_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.firewallConfigurationPriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, FIREWALL_CONFIGURATION_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.listeningPortsPriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, LISTENING_PORTS_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.localUsersPriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, LOCAL_USERS_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.loginPriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, LOGIN_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.operational, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, OPERATIONAL_EVENT_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.processCreatePriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, PROCESS_CREATE_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    TwinConfigurationEventCollectors_PriorityEnumAsString(eventPriorities.systemInformationPriority, &priorityAsString);
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, SYSTEM_INFORMATION_PRIORITY_KEY, priorityAsString);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteBoolConfigurationToJson(prioritiesJson, PROCESS_CREATE_AGGREGATION_ENABLED_KEY, eventPriorities.processCreateAggregationEnabled);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    char iso8601Interval[DURATION_MAX_LENGTH] = {0};
    if (TimeUtils_MillisecondsToISO8601DurationString(eventPriorities.processCreateAggregationInterval, iso8601Interval, DURATION_MAX_LENGTH) == false) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, PROCESS_CREATE_AGGREGATION_INTERVAL_KEY, iso8601Interval);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteBoolConfigurationToJson(prioritiesJson, CONNECTION_CREATE_AGGREGATION_ENABLED_KEY, eventPriorities.connectionCreateAggregationEnabled);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    if (TimeUtils_MillisecondsToISO8601DurationString(eventPriorities.connectionCreateAggregationInterval, iso8601Interval, DURATION_MAX_LENGTH) == false) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteStringConfigurationToJson(prioritiesJson, CONNECTION_CREATE_AGGREGATION_INTERVAL_KEY, iso8601Interval);
    if (result != TWIN_OK) {
        goto cleanup;
    }


cleanup:
    return result;
}