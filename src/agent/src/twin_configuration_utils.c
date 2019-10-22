// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "twin_configuration_utils.h"

//Configuration properties types
typedef enum _TwinConfigurationTypes {
    STRING,
    UINT,
    TIME,
    BOOL
} TwinConfigurationTypes;

static const char* VALUE_KEY = "value";

/**
 * @brief Reads PnP formatted time configuration from twin json reader in PnP 
 * 
 * @param reader        Twin json reader
 * @param key           The key to read
 * @param value         Out param. the value of the configuration
 * @param types         configuration type
 * 
 * @return TWIN_OK on success or an error code upon failure
 */
TwinConfigurationResult TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(JsonObjectReaderHandle reader, const char* key, void* value, TwinConfigurationTypes type);

/**
 * @brief writes PnP formatted configuration to json writer
 * 
 * @param writer        Twin json writer
 * @param key           The key to write
 * @param valuePtr      Pointer to value of the configuration to write
 * @param types         configuration type
 * 
 * @return TWIN_OK on success or an error code upon failure
 */  
TwinConfigurationResult TwinConfigurationUtils_Internal_WriteConfigurationToJson(JsonObjectWriterHandle writer, const char* key, const void* valuePtr, TwinConfigurationTypes type);


TwinConfigurationResult TwinConfigurationUtils_GetConfigurationTimeValueFromJson(JsonObjectReaderHandle reader, const char* key, uint32_t* value) {
    return TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(reader, key, value, TIME);
}

TwinConfigurationResult TwinConfigurationUtils_GetConfigurationUintValueFromJson(JsonObjectReaderHandle reader, const char* key, uint32_t* value) {
    return TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(reader, key, value, UINT);
}

TwinConfigurationResult TwinConfigurationUtils_GetConfigurationStringValueFromJson(JsonObjectReaderHandle reader, const char* key, char** value) {
    return TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(reader, key, value, STRING);
}

TwinConfigurationResult TwinConfigurationUtils_GetConfigurationBoolValueFromJson(JsonObjectReaderHandle reader, const char* key, bool* value) {
    return TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(reader, key, value, BOOL);
}

TwinConfigurationResult TwinConfigurationUtils_WriteUintConfigurationToJson(JsonObjectWriterHandle writer, const char* key, uint32_t value) {
    return TwinConfigurationUtils_Internal_WriteConfigurationToJson(writer, key, &value, UINT);
}

TwinConfigurationResult TwinConfigurationUtils_WriteStringConfigurationToJson(JsonObjectWriterHandle writer, const char* key, const char* value) {
    if (value == NULL) {
        return TWIN_OK;
    }
    return TwinConfigurationUtils_Internal_WriteConfigurationToJson(writer, key, value, STRING);
}

TwinConfigurationResult TwinConfigurationUtils_WriteBoolConfigurationToJson(JsonObjectWriterHandle writer, const char* key, bool value) {
    return TwinConfigurationUtils_Internal_WriteConfigurationToJson(writer, key, &value, BOOL);
}

TwinConfigurationResult TwinConfigurationUtils_Internal_GetConfigurationValueFromJson(JsonObjectReaderHandle reader, const char* key, void* value, TwinConfigurationTypes type) {
    TwinConfigurationResult result = TWIN_OK;
    JsonReaderResult readerResult = JsonObjectReader_StepIn(reader, key);
    if (readerResult == JSON_READER_KEY_MISSING || readerResult == JSON_READER_VALUE_IS_NULL) {
        return TWIN_CONF_NOT_EXIST;
    } else if (readerResult == JSON_READER_PARSE_ERROR) {
        return TWIN_PARSE_EXCEPTION;
    } else if (readerResult != JSON_READER_OK) {
        return TWIN_EXCEPTION;
    }

    switch (type)
    {
    case STRING: 
        readerResult = JsonObjectReader_ReadString(reader, VALUE_KEY, (char**)value);
        break;
    case UINT:
        readerResult = JsonObjectReader_ReadInt(reader, VALUE_KEY, (int32_t*)value);  
        break;
    case TIME:
        readerResult = JsonObjectReader_ReadTimeInMilliseconds(reader, VALUE_KEY, (uint32_t*)value);
        break;
    case BOOL:
        readerResult = JsonObjectReader_ReadBool(reader, VALUE_KEY, (bool*)value);
        break;    
    default:
        return TWIN_EXCEPTION;
    }

    if (readerResult == JSON_READER_KEY_MISSING || readerResult == JSON_READER_VALUE_IS_NULL || readerResult == JSON_READER_PARSE_ERROR) {
        result = TWIN_PARSE_EXCEPTION;
    } else if (readerResult != JSON_READER_OK) {
        result = TWIN_EXCEPTION;
    }

    if (JsonObjectReader_StepOut(reader) != JSON_READER_OK) {
        result = TWIN_EXCEPTION;
    }

    return result;
}

TwinConfigurationResult TwinConfigurationUtils_Internal_WriteConfigurationToJson(JsonObjectWriterHandle writer, const char* key, const void* valuePtr, TwinConfigurationTypes type) {
    TwinConfigurationResult result = TWIN_OK;
    JsonObjectWriterHandle configurationObject = NULL;
    if (JsonObjectWriter_Init(&configurationObject) != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    JsonWriterResult writerResult; 
    switch (type)
    {
    case STRING: 
        writerResult = JsonObjectWriter_WriteString(configurationObject, VALUE_KEY, valuePtr);
        break;
    case UINT:
        writerResult = JsonObjectWriter_WriteInt(configurationObject, VALUE_KEY, *(int32_t*)valuePtr);  
        break;
    case BOOL:
        writerResult = JsonObjectWriter_WriteBool(configurationObject, VALUE_KEY, *(bool*)valuePtr);
        break;    
    default:
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    if (writerResult != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteObject(writer, key, configurationObject) != JSON_WRITER_OK) {
        result = TWIN_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (configurationObject != NULL) {
        JsonObjectWriter_Deinit(configurationObject);
    }

    return result;
}