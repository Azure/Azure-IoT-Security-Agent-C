// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "twin_configuration.h"

#include <stdio.h>
#include <stdlib.h>

#include "azure_c_shared_utility/lock.h"

#include "internal/time_utils.h"
#include "internal/time_utils_consts.h"
#include "json/json_object_reader.h"
#include "local_config.h"
#include "logger.h"
#include "twin_configuration_event_collectors.h"
#include "twin_configuration_utils.h"
#include "utils.h"

/**
 * Agent's twin configurtaion 
 */
typedef struct _TwinConfiguration {
    uint32_t maxLocalCacheSize;
    uint32_t maxMessageSize;
    uint32_t lowPriorityMessageFrequency;
    uint32_t highPriorityMessageFrequency;
    uint32_t snapshotFrequency;
    
    bool baselineCustomChecksEnabled;
    char* baselineCustomChecksFilePath;
    char* baselineCustomChecksFileHash;

    LOCK_HANDLE lock;
} TwinConfiguration;

static const char* twinConfigurationObjectName = NULL;

static TwinConfiguration twinConfiguration;
static TwinConfigurationUpdateResult updateResult;

/**
 * @brief   extracts the twin configuration from the json object and initializes\updates the static
 *          twin configuration accordingly, will replace with local configuration values in case the 
 *          field is missing from the json.
 * 
 * @param   jsonReader  The json reader to read the configuration with.
 * 
 * @return  TWIN_OK             on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfiguration_ExtractConfiguration(JsonObjectReaderHandle jsonReader, TwinConfigurationBundleStatus* status, TwinConfiguration* newConfiguration);

/**
 * @brief   retrieves the value of a given twin configuration in a thread safe manner (currently using a lock)
 * 
 * @param   value       out param: the parsed value
 * @param   field       field taken from the twin
 * 
 * @return  TWIN_OK     on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfiguration_GetFieldInteger(uint32_t* value, uint32_t field);

/**
 * @brief   retrieves the value of a given twin configuration in a thread safe manner (currently using a lock)
 * 
 * @param   value       out param: the parsed value
 * @param   field       field taken from the twin
 * 
 * @return  TWIN_OK     on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfiguration_GetFieldBool(bool* value, bool field);

/**
 * @brief   retrieves the value of a given twin configuration in a thread safe manner (currently using a lock)
 * 
 * @param   value       out param: the parsed value
 * @param   field       field taken from the twin
 * 
 * @return  TWIN_OK     on success or an error code upon failure
 */
static TwinConfigurationResult TwinConfiguration_GetFieldString(char** value, char* field);

TwinConfigurationResult TwinConfiguration_Init();

TwinConfigurationResult TwinConfiguration_DeepCopy(TwinConfiguration* dest, TwinConfiguration* src);

void TwinConfiguration_SafeDeinit();

void TwinConfiguration_Deinit();

TwinConfigurationResult TwinConfiguration_Update(const char* json, bool complete);

TwinConfigurationResult TwinConfiguration_Init() {
    TwinConfigurationResult returnValue = TWIN_OK;

    twinConfiguration.lock = Lock_Init();
    if (twinConfiguration.lock == NULL) {
        returnValue = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }

    twinConfiguration.maxLocalCacheSize = DEFAULT_MAX_LOCAL_CACHE_SIZE;
    twinConfiguration.maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE;
    twinConfiguration.lowPriorityMessageFrequency = DEFAULT_LOW_PRIORITY_MESSAGE_FREQUENCY;
    twinConfiguration.highPriorityMessageFrequency = DEFAULT_HIGH_PRIORITY_MESSAGE_FREQUENCY;
    twinConfiguration.snapshotFrequency = DEFAULT_SNAPSHOT_FREQUENCY;

    twinConfiguration.baselineCustomChecksEnabled = DEFAULT_BASELINE_CUSTOM_CHECKS_ENABLED;
    if (Utils_DuplicateString(&twinConfiguration.baselineCustomChecksFilePath, DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH) == ACTION_MEMORY_EXCEPTION) {
        returnValue = TWIN_MEMORY_EXCEPTION;
        goto cleanup;
    }

    if (Utils_DuplicateString(&twinConfiguration.baselineCustomChecksFileHash, DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH) == ACTION_MEMORY_EXCEPTION) {
        returnValue = TWIN_MEMORY_EXCEPTION;
        goto cleanup;
    }
    twinConfigurationObjectName = LocalConfiguration_GetRemoteConfigurationObjectName();

    returnValue = TwinConfigurationEventCollectors_Init();
    if (returnValue != TWIN_OK) {
        Lock_Deinit(twinConfiguration.lock);
        twinConfiguration.lock = NULL;
        goto cleanup;
    }

cleanup:
    if (returnValue != TWIN_OK) {
        TwinConfiguration_Deinit();
    }
    return returnValue;
}

TwinConfigurationResult TwinConfiguration_DeepCopy(TwinConfiguration* dest, TwinConfiguration* src) {
    TwinConfigurationResult returnValue = TWIN_OK;

    // Note: `dest->lock` maintains the global lock (consider change implementation)

    dest->maxLocalCacheSize = src->maxLocalCacheSize;
    dest->maxMessageSize = src->maxMessageSize;
    dest->lowPriorityMessageFrequency = src->lowPriorityMessageFrequency;
    dest->highPriorityMessageFrequency = src->highPriorityMessageFrequency;
    dest->snapshotFrequency = src->snapshotFrequency;

    dest->baselineCustomChecksEnabled = src->baselineCustomChecksEnabled;

    if (Utils_DuplicateString(&(dest->baselineCustomChecksFilePath), src->baselineCustomChecksFilePath) == ACTION_MEMORY_EXCEPTION) {
        returnValue = TWIN_MEMORY_EXCEPTION;
        goto cleanup;
    }

    if (Utils_DuplicateString(&(dest->baselineCustomChecksFileHash), src->baselineCustomChecksFileHash) == ACTION_MEMORY_EXCEPTION) {
        returnValue = TWIN_MEMORY_EXCEPTION;
        goto cleanup;
    }

cleanup:
    return returnValue;
}

void TwinConfiguration_SafeDeinit() {
    if (twinConfiguration.baselineCustomChecksFilePath != NULL) {
        free(twinConfiguration.baselineCustomChecksFilePath);
        memcpy(&twinConfiguration.baselineCustomChecksFilePath, &DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH, sizeof(char*));
    }

    if (twinConfiguration.baselineCustomChecksFileHash != NULL) {
        free(twinConfiguration.baselineCustomChecksFileHash);
        memcpy(&twinConfiguration.baselineCustomChecksFileHash, &DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH, sizeof(char*));
    }
}

void TwinConfiguration_Deinit() {
    TwinConfiguration_SafeDeinit();

    TwinConfigurationEventCollectors_Deinit();

    if (twinConfiguration.lock != NULL) {
        Lock_Deinit(twinConfiguration.lock);
        twinConfiguration.lock = NULL;
    }
}

TwinConfigurationResult TwinConfiguration_Update(const char* json, bool complete) {
    bool isLocked = false;
    TwinConfigurationBundleStatus newBundleStatus = { 0 };
    TwinConfiguration newConfiguration = { 0 };
    TwinConfigurationResult returnValue = TWIN_OK;
    JsonObjectReaderHandle jsonReader = NULL;

    JsonReaderResult result = JsonObjectReader_InitFromString(&jsonReader, json);
    if (result != JSON_READER_OK) {
        returnValue = TWIN_EXCEPTION;
        goto cleanup;
    }
    
    if (complete) {
        if (JsonObjectReader_StepIn(jsonReader, "desired") != JSON_READER_OK) {
            returnValue = TWIN_PARSE_EXCEPTION;
            goto cleanup;
        }
    }

    result = JsonObjectReader_StepIn(jsonReader, twinConfigurationObjectName); 
    if (result == JSON_READER_KEY_MISSING || result == JSON_READER_VALUE_IS_NULL) {
        JsonObjectReader_Deinit(jsonReader);
        if (JsonObjectReader_InitFromString(&jsonReader, "{}") != JSON_READER_OK) {
            returnValue = TWIN_EXCEPTION;
            goto cleanup;
        }
    } else if (result != JSON_READER_OK) {
        returnValue = TWIN_PARSE_EXCEPTION;
        goto cleanup;
    }

    returnValue = TwinConfiguration_ExtractConfiguration(jsonReader, &newBundleStatus, &newConfiguration);
    if (returnValue != TWIN_OK){
        goto cleanup;
    }

    if (Lock(twinConfiguration.lock) == LOCK_OK) {
        isLocked = true;
    } else  {
        returnValue = TWIN_LOCK_EXCEPTION;
        goto cleanup;
    }
   
    returnValue = TwinConfigurationEventCollectors_Update(jsonReader);
    if (returnValue == TWIN_PARSE_EXCEPTION) {
        newBundleStatus.eventPriorities = CONFIGURATION_TYPE_MISMATCH;
        goto cleanup;
    } else if (returnValue != TWIN_OK){
        goto cleanup;
    }
    
    TwinConfiguration_SafeDeinit();
    returnValue = TwinConfiguration_DeepCopy(&twinConfiguration, &newConfiguration);
    if (returnValue != TWIN_OK){
        goto cleanup;
    }

cleanup:
    memcpy(&updateResult.configurationBundleStatus, &newBundleStatus, sizeof(TwinConfigurationBundleStatus));
    updateResult.lastUpdateResult = returnValue;
    updateResult.lastUpdateTime = TimeUtils_GetCurrentTime();

    if (jsonReader != NULL) {
        JsonObjectReader_Deinit(jsonReader);
    }

    if (isLocked && Unlock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    if (returnValue == TWIN_MEMORY_EXCEPTION) {
        TwinConfiguration_Deinit();
    }

    return returnValue;
}

TwinConfigurationResult TwinConfiguration_GetMaxLocalCacheSize(uint32_t* maxLocalCacheSize) {
    return TwinConfiguration_GetFieldInteger(maxLocalCacheSize, twinConfiguration.maxLocalCacheSize);
}

TwinConfigurationResult TwinConfiguration_GetMaxMessageSize(uint32_t* maxMessageSize) {
    return TwinConfiguration_GetFieldInteger(maxMessageSize, twinConfiguration.maxMessageSize);
}

TwinConfigurationResult TwinConfiguration_GetLowPriorityMessageFrequency(uint32_t* lowPriorityMessageFrequency) {
    return TwinConfiguration_GetFieldInteger(lowPriorityMessageFrequency, twinConfiguration.lowPriorityMessageFrequency);
}

TwinConfigurationResult TwinConfiguration_GetHighPriorityMessageFrequency(uint32_t* highPriorityMessageFrequency) {
    return TwinConfiguration_GetFieldInteger(highPriorityMessageFrequency, twinConfiguration.highPriorityMessageFrequency);
}

TwinConfigurationResult TwinConfiguration_GetSnapshotFrequency(uint32_t* snapshotFrequency) {
    return TwinConfiguration_GetFieldInteger(snapshotFrequency, twinConfiguration.snapshotFrequency);
}

TwinConfigurationResult TwinConfiguration_GetBaselineCustomChecksEnabled(bool* baselineCustomChecksEnabled) {
    return TwinConfiguration_GetFieldBool(baselineCustomChecksEnabled, twinConfiguration.baselineCustomChecksEnabled);
}

TwinConfigurationResult TwinConfiguration_GetBaselineCustomChecksFilePath(char** baselineCustomChecksFilePath) {
    return TwinConfiguration_GetFieldString(baselineCustomChecksFilePath, twinConfiguration.baselineCustomChecksFilePath);
}

TwinConfigurationResult TwinConfiguration_GetBaselineCustomChecksFileHash(char** baselineCustomChecksFileHash) {
    return TwinConfiguration_GetFieldString(baselineCustomChecksFileHash, twinConfiguration.baselineCustomChecksFileHash);
}

static TwinConfigurationResult TwinConfiguration_SetSingleUintValueFromJsonOrDefault(uint32_t* value, uint32_t defaultValue, JsonObjectReaderHandle reader, const char* key, bool isTime, TwinConfigurationStatus* outStatus) {
    *outStatus = CONFIGURATION_OK;
    TwinConfigurationResult result;

    if (isTime){
        result = TwinConfigurationUtils_GetConfigurationTimeValueFromJson(reader, key, value);
    } else {
        result = TwinConfigurationUtils_GetConfigurationUintValueFromJson(reader, key, value);
    } 
    
    if (result == TWIN_CONF_NOT_EXIST) {
        *value = defaultValue;
        result = TWIN_OK;
    } else if (result == TWIN_PARSE_EXCEPTION) {
        *outStatus = CONFIGURATION_TYPE_MISMATCH;
    } 

    return result;
}

static TwinConfigurationResult TwinConfiguration_SetSingleBoolValueFromJsonOrDefault(bool* value, bool defaultValue, JsonObjectReaderHandle reader, const char* key, TwinConfigurationStatus* outStatus) {
    *outStatus = CONFIGURATION_OK;
    TwinConfigurationResult result;

    result = TwinConfigurationUtils_GetConfigurationBoolValueFromJson(reader, key, value);
    
    if (result == TWIN_CONF_NOT_EXIST) {
        *value = defaultValue;
        result = TWIN_OK;
    } else if (result == TWIN_PARSE_EXCEPTION) {
        *outStatus = CONFIGURATION_TYPE_MISMATCH;
    } 

    return result;
}

static TwinConfigurationResult TwinConfiguration_SetSingleStringValueFromJsonOrDefault(char** value, const char* defaultValue, JsonObjectReaderHandle reader, const char* key, TwinConfigurationStatus* outStatus) {
    *outStatus = CONFIGURATION_OK;
    TwinConfigurationResult result;

    result = TwinConfigurationUtils_GetConfigurationStringValueFromJson(reader, key, value);
    
    if (result == TWIN_CONF_NOT_EXIST) {
        if (Utils_DuplicateString(value, defaultValue) == ACTION_MEMORY_EXCEPTION) {
            result = TWIN_MEMORY_EXCEPTION;
        } else {
            result = TWIN_OK;
        }
    } else if (result == TWIN_PARSE_EXCEPTION) {
        *outStatus = CONFIGURATION_TYPE_MISMATCH;
    } 

    return result;
}

static TwinConfigurationResult TwinConfiguration_ExtractConfiguration(JsonObjectReaderHandle jsonReader, TwinConfigurationBundleStatus* parsingResult, TwinConfiguration* newConfiguration) {  
    TwinConfigurationResult result = TWIN_OK;
    TwinConfigurationResult currentKeyResult;

    currentKeyResult = TwinConfiguration_SetSingleUintValueFromJsonOrDefault(&(newConfiguration->maxLocalCacheSize), DEFAULT_MAX_LOCAL_CACHE_SIZE, jsonReader, MAX_LOCAL_CACHE_SIZE_KEY, false, &(parsingResult->maxLocalCacheSize));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleUintValueFromJsonOrDefault(&(newConfiguration->maxMessageSize), DEFAULT_MAX_MESSAGE_SIZE, jsonReader, MAX_MESSAGE_SIZE_KEY, false, &(parsingResult->maxMessageSize));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleUintValueFromJsonOrDefault(&(newConfiguration->highPriorityMessageFrequency), DEFAULT_HIGH_PRIORITY_MESSAGE_FREQUENCY, jsonReader, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, true, &(parsingResult->highPriorityMessageFrequency));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleUintValueFromJsonOrDefault(&(newConfiguration->lowPriorityMessageFrequency), DEFAULT_LOW_PRIORITY_MESSAGE_FREQUENCY, jsonReader, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, true, &(parsingResult->lowPriorityMessageFrequency));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleUintValueFromJsonOrDefault(&(newConfiguration->snapshotFrequency), DEFAULT_SNAPSHOT_FREQUENCY, jsonReader, SNAPSHOT_FREQUENCY_KEY, true, &(parsingResult->snapshotFrequency));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleBoolValueFromJsonOrDefault(&(newConfiguration->baselineCustomChecksEnabled), DEFAULT_BASELINE_CUSTOM_CHECKS_ENABLED, jsonReader, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, &(parsingResult->baselineCustomChecksEnabled));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleStringValueFromJsonOrDefault(&(newConfiguration->baselineCustomChecksFilePath), DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH, jsonReader, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, &(parsingResult->baselineCustomChecksFilePath));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

    currentKeyResult = TwinConfiguration_SetSingleStringValueFromJsonOrDefault(&(newConfiguration->baselineCustomChecksFileHash), DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH, jsonReader, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, &(parsingResult->baselineCustomChecksFileHash));
    if (currentKeyResult == TWIN_PARSE_EXCEPTION) {
        result = currentKeyResult;
    } else if (currentKeyResult != TWIN_OK) {
        result = currentKeyResult;
        goto cleanup;
    }

cleanup:
    return result;
}

static TwinConfigurationResult TwinConfiguration_GetFieldInteger(uint32_t* value, uint32_t field) {
    if (Lock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    *value = field;

    if (Unlock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    return TWIN_OK;
}

static TwinConfigurationResult TwinConfiguration_GetFieldBool(bool* value, bool field) {
    if (Lock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    *value = field;

    if (Unlock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    return TWIN_OK;
}

static TwinConfigurationResult TwinConfiguration_GetFieldString(char** value, char* field) {
    if (Lock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    *value = field;

    if (Unlock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    return TWIN_OK;
}

void TwinConfiguration_GetLastTwinUpdateData(TwinConfigurationUpdateResult* outResult) {
    if (outResult == NULL) {
        return;
    }

    outResult->lastUpdateResult = updateResult.lastUpdateResult;
    outResult->lastUpdateTime = updateResult.lastUpdateTime;
    memcpy(&(outResult->configurationBundleStatus), &updateResult.configurationBundleStatus, sizeof(TwinConfigurationBundleStatus));
}

TwinConfigurationResult TwinConfiguration_GetSerializedTwinConfiguration(char** twin, uint32_t* size){
    TwinConfigurationResult result = TWIN_OK;
    JsonObjectWriterHandle configurationObject = NULL;
    JsonObjectWriterHandle twinRoot = NULL;

    if (Lock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }
    
    if (JsonObjectWriter_Init(&twinRoot) != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_Init(&configurationObject) != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteUintConfigurationToJson(configurationObject, MAX_LOCAL_CACHE_SIZE_KEY, twinConfiguration.maxLocalCacheSize);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteUintConfigurationToJson(configurationObject, MAX_MESSAGE_SIZE_KEY, twinConfiguration.maxMessageSize);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    char timeSpan[DURATION_MAX_LENGTH] = { '\0' };
    if (TimeUtils_MillisecondsToISO8601DurationString(twinConfiguration.highPriorityMessageFrequency, timeSpan, sizeof(timeSpan)) == false) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteStringConfigurationToJson(configurationObject, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, timeSpan);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    if (TimeUtils_MillisecondsToISO8601DurationString(twinConfiguration.lowPriorityMessageFrequency, timeSpan, sizeof(timeSpan)) == false) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }
    result = TwinConfigurationUtils_WriteStringConfigurationToJson(configurationObject, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, timeSpan);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    if (TimeUtils_MillisecondsToISO8601DurationString(twinConfiguration.snapshotFrequency, timeSpan, sizeof(timeSpan)) == false) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteStringConfigurationToJson(configurationObject, SNAPSHOT_FREQUENCY_KEY, timeSpan);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteBoolConfigurationToJson(configurationObject, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, twinConfiguration.baselineCustomChecksEnabled);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteStringConfigurationToJson(configurationObject, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, twinConfiguration.baselineCustomChecksFilePath);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationUtils_WriteStringConfigurationToJson(configurationObject, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, twinConfiguration.baselineCustomChecksFileHash);
    if (result != TWIN_OK) {
        goto cleanup;
    }

    result = TwinConfigurationEventCollectors_GetPrioritiesJson(configurationObject);
    if (result != TWIN_OK){
        goto cleanup;
    }

    if (JsonObjectWriter_WriteObject(twinRoot, twinConfigurationObjectName, configurationObject) != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_Serialize(twinRoot, twin, size) != JSON_WRITER_OK){
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (configurationObject != NULL) {
        JsonObjectWriter_Deinit(configurationObject);
    }

    if (twinRoot != NULL) {
        JsonObjectWriter_Deinit(twinRoot);
    }

    if (Unlock(twinConfiguration.lock) != LOCK_OK) {
        return TWIN_LOCK_EXCEPTION;
    }

    return result;
}