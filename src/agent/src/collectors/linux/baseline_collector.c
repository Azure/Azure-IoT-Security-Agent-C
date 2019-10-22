// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>

#include "collectors/linux/baseline_collector.h"
#include "json/json_array_reader.h"
#include "json/json_array_writer.h"
#include "json/json_object_reader.h"
#include "json/json_object_writer.h"
#include "message_schema_consts.h"
#include "os_utils/process_info_handler.h"
#include "os_utils/process_utils.h"
#include "utils.h"
#include "logger.h"
#include "twin_configuration.h"


#define OMS_BASELINE_MAX_OUTPUT_SIZE 5242880 // 5mb
static const char* OMS_BASELINE_COMMAND = "./omsbaseline -d .";
static const char* OMS_BASELINE_CUSTOM_CHECKS_COMMAND = "./omsbaseline -ccfp %s -ccfh %s";
static const char* OMS_BASELINE_RESULT_KEY = "result";
static const char* OMS_BASELINE_DESCRIPTION_KEY = "description";
static const char* OMS_BASELINE_CCEID_KEY = "cceid";
static const char* OMS_BASELINE_ERROR_KEY = "error_text";
static const char* OMS_BASELINE_SERVERITY_KEY = "severity";
static const char* OMS_BASELINE_PASS_VALUE = "PASS";
static const char* OMS_BASELINE_RESULTS_LIST_VALUE = "results";

/**
 * Baseline Custom Checks configurtaion 
 */
typedef struct _BaselineCustomChecksConfiguration {
    bool enabled;
    char* filePath;
    char* fileHash;
} BaselineCustomChecksConfiguration;

/**
 * @brief Adds all the baseline payload to the given array.
 * 
 * @param   baselinePayloadArray    The payloads array.
 * @param   baselineCommand         The baseline executable command.
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult BaselineCollector_AddPayloads(JsonArrayWriterHandle baselinePayloadArray, const char* baselineCommand);

/**
 * @brief Adds a single baseline result to the given array.
 * 
 * @param   item                    The item reader.
 * @param   baselinePayloadArray    The payloads array.
 * 
 * @return EVENT_COLLECTOR_OK on  success, EVENT_COLLECTOR_RECORD_FILTERED in case the item was filtered and was't written,
 *         EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult BaselineCollector_AddSingleResult(JsonObjectReaderHandle item, JsonArrayWriterHandle baselinePayloadArray);

/**
 * @brief Adds baseline custom checks payload to the given array.
 * 
 * @param   baselinePayloadArray    The payloads array.
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult BaselineCollector_AddBaselineCustomChecksPayload(JsonArrayWriterHandle baselinePayloadArray, BaselineCustomChecksConfiguration baselineCustomChecksConfiguration);

/**
 * @brief Runs the omsbaseline process and writes it output to the given buffer.
 * 
 * @param   output      The output buffer.
 * @param   bytesRead   Out param. The number of bytes written to the output.
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult BaselineCollector_RunOmsbaseline(const char* command, char* output, uint32_t* bytesRead);

/**
 * @brief OMSBaseline custom checks configuration enabled predicate
 * 
 * @return bool true iff baseline custom checks prerequisites are satisfied.
 */
bool BaselineCollector_IsBaselineCustomChecksEnabled(BaselineCustomChecksConfiguration* config);

void BaselineCollector_BaselineCustomChecksConfiguration_Deinit(BaselineCustomChecksConfiguration* config);

/**
 * @brief Copy a value from the src key of the reader to the dest key of the writer.
 * 
 * @param   reader      The copy src.
 * @param   srcKey      The src key.
 * @param   writer      The copy destenation.
 * @param   destKey     The key on the dest writer.
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult BaselineCollector_CopyStringValue(JsonObjectReaderHandle reader, const char* srcKey, JsonObjectWriterHandle writer, const char* destKey);

EventCollectorResult BaselineCollector_GetEvents(SyncQueue* queue) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle baselineEventWriter = NULL;
    JsonArrayWriterHandle baselinePayloadArray = NULL;
    char* messageBuffer = NULL;
    BaselineCustomChecksConfiguration baselineCustomChecksConfiguration = { 0 };

    if (JsonObjectWriter_Init(&baselineEventWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (GenericEvent_AddMetadata(baselineEventWriter, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonArrayWriter_Init(&baselinePayloadArray) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    
    result = BaselineCollector_AddPayloads(baselinePayloadArray, OMS_BASELINE_COMMAND);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (BaselineCollector_IsBaselineCustomChecksEnabled(&baselineCustomChecksConfiguration)) {
        BaselineCollector_AddBaselineCustomChecksPayload(baselinePayloadArray, baselineCustomChecksConfiguration);
    }

    result = GenericEvent_AddPayload(baselineEventWriter, baselinePayloadArray);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    uint32_t messageBufferSize = 0;
    if (JsonObjectWriter_Serialize(baselineEventWriter, &messageBuffer, &messageBufferSize) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (SyncQueue_PushBack(queue, messageBuffer, messageBufferSize) != QUEUE_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != EVENT_COLLECTOR_OK) {
        if (messageBuffer !=  NULL) {
            free(messageBuffer);
        }
    }

    if (baselinePayloadArray != NULL) {
        JsonArrayWriter_Deinit(baselinePayloadArray);
    }

    if (baselineEventWriter != NULL) {
        JsonObjectWriter_Deinit(baselineEventWriter);
    }

    return result;
}


EventCollectorResult BaselineCollector_AddPayloads(JsonArrayWriterHandle baselinePayloadArray, const char* baselineCommand) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectReaderHandle baselineResultHandle = NULL;
    JsonArrayReaderHandle resultsListHandle = NULL;

    char* buffer = malloc(OMS_BASELINE_MAX_OUTPUT_SIZE);
    if (buffer == NULL) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    // empty string
    buffer[0] = '\0';

    uint32_t bufferSize = 0;
    result = BaselineCollector_RunOmsbaseline(baselineCommand, buffer, &bufferSize);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (bufferSize == 0) {
        goto cleanup;
    }

    if (JsonObjectReader_InitFromString(&baselineResultHandle, buffer) != JSON_READER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectReader_ReadArray(baselineResultHandle, OMS_BASELINE_RESULTS_LIST_VALUE, &resultsListHandle) != JSON_READER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t numberOfResults = 0 ;
    JsonArrayReader_GetSize(resultsListHandle, &numberOfResults);
    for (uint32_t i = 0; i < numberOfResults; ++i) {
        JsonObjectReaderHandle item = NULL;
        if (JsonArrayReader_ReadObject(resultsListHandle, i, &item) != JSON_READER_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
        result = BaselineCollector_AddSingleResult(item, baselinePayloadArray);
        if (item != NULL) {
            JsonObjectReader_Deinit(item);
        }
        if (result != EVENT_COLLECTOR_OK && result != EVENT_COLLECTOR_RECORD_FILTERED) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
    }
    result = EVENT_COLLECTOR_OK;

cleanup:
    if (resultsListHandle != NULL) {
        JsonArrayReader_Deinit(resultsListHandle);
    }

    if (baselineResultHandle != NULL) {
        JsonObjectReader_Deinit(baselineResultHandle);
    }

    if (buffer != NULL) {
        free(buffer);
    }

    return result;
}


EventCollectorResult BaselineCollector_AddSingleResult(JsonObjectReaderHandle item, JsonArrayWriterHandle baselinePayloadArray) {

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle itemWriter = NULL;

    char* strValue = NULL;
    if (JsonObjectReader_ReadString(item, OMS_BASELINE_RESULT_KEY, &strValue) != JSON_READER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (Utils_UnsafeAreStringsEqual(OMS_BASELINE_PASS_VALUE, strValue, false)) {
        result = EVENT_COLLECTOR_RECORD_FILTERED;
        goto cleanup;
    }

    if (JsonObjectWriter_Init(&itemWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(itemWriter, BASELINE_RESULT_KEY, strValue) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = BaselineCollector_CopyStringValue(item, OMS_BASELINE_DESCRIPTION_KEY, itemWriter, BASELINE_DESCRIPTION_KEY);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    result = BaselineCollector_CopyStringValue(item, OMS_BASELINE_CCEID_KEY, itemWriter, BASELINE_CCEID_KEY);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    result = BaselineCollector_CopyStringValue(item, OMS_BASELINE_ERROR_KEY, itemWriter, BASELINE_ERROR_KEY);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    result = BaselineCollector_CopyStringValue(item, OMS_BASELINE_SERVERITY_KEY, itemWriter, BASELINE_SEVERITY_KEY);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    if (JsonArrayWriter_AddObject(baselinePayloadArray, itemWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (itemWriter != NULL) {
        JsonObjectWriter_Deinit(itemWriter);
    }
    return result;
}


EventCollectorResult BaselineCollector_AddBaselineCustomChecksPayload(JsonArrayWriterHandle baselinePayloadArray, BaselineCustomChecksConfiguration baselineCustomChecksConfiguration) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    char* baselineCommand = NULL;
    if (Utils_StringFormat(OMS_BASELINE_CUSTOM_CHECKS_COMMAND, &baselineCommand, baselineCustomChecksConfiguration.filePath, baselineCustomChecksConfiguration.fileHash) != ACTION_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = BaselineCollector_AddPayloads(baselinePayloadArray, baselineCommand);
    if (result != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != EVENT_COLLECTOR_OK) {
        Logger_Debug("BaselineCollector failed to execute custom checks, error=%d", result);
    }

    if (baselineCommand != NULL) {
        free(baselineCommand);
    }
}


EventCollectorResult BaselineCollector_RunOmsbaseline(const char *command, char* output, uint32_t* bytesRead) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    ProcessInfo info;
    bool processInfoWasSet = false;

    if (!ProcessInfoHandler_ChangeToRoot(&info)) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    processInfoWasSet = true;

    *bytesRead = OMS_BASELINE_MAX_OUTPUT_SIZE;
    if (!ProcessUtils_Execute(command, output, bytesRead)) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (processInfoWasSet) {
        ProcessInfoHandler_Reset(&info);
    }

    return result;
}


bool BaselineCollector_IsBaselineCustomChecksEnabled(BaselineCustomChecksConfiguration* config) {
    if ((TwinConfiguration_GetBaselineCustomChecksEnabled(&(config->enabled)) != TWIN_OK) ||
        (TwinConfiguration_GetBaselineCustomChecksFilePath(&(config->filePath)) != TWIN_OK) ||
        (TwinConfiguration_GetBaselineCustomChecksFileHash(&(config->fileHash)) != TWIN_OK)) {
        return false;
    }

    return config->enabled && 
        !Utils_IsStringBlank(config->filePath) && 
        !Utils_IsStringBlank(config->fileHash);
}


void BaselineCollector_BaselineCustomChecksConfiguration_Deinit(BaselineCustomChecksConfiguration* config) {
    if (config != NULL) {
        if (config->filePath != NULL) {
            free(config->filePath);
        }

        if (config->fileHash != NULL) {
            free(config->fileHash);
        }
    }
}

EventCollectorResult BaselineCollector_CopyStringValue(JsonObjectReaderHandle reader, const char* srcKey, JsonObjectWriterHandle writer, const char* destKey) {
    char* strValue = NULL;
    if (JsonObjectReader_ReadString(reader, srcKey, &strValue) != JSON_READER_OK) {
        return EVENT_COLLECTOR_EXCEPTION;
    }
    if (JsonObjectWriter_WriteString(writer, destKey, strValue) != JSON_WRITER_OK) {
        return EVENT_COLLECTOR_EXCEPTION;
    }
    return EVENT_COLLECTOR_OK;
}
