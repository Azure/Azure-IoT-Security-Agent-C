// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "json/json_object_writer.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "parson.h"

#include "json/json_writer.h"


JsonWriterResult JsonObjectWriter_Init(JsonObjectWriterHandle* writer) {
    JsonWriterResult result = JSON_WRITER_OK;

    JsonObjectWriter* writerObj = malloc(sizeof(JsonObjectWriter));
    if (writerObj == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }
    memset(writerObj, 0, sizeof(JsonObjectWriter));
    writerObj->shouldFree = true;

    writerObj->rootValue = json_value_init_object();
    if (writerObj->rootValue == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }   

    writerObj->rootObject = json_value_get_object(writerObj->rootValue);
    if (writerObj->rootObject == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }

    *writer = (JsonObjectWriterHandle)writerObj;

cleanup:
    if (result != JSON_WRITER_OK) {
        if (writerObj != NULL) {
            JsonObjectWriter_Deinit((JsonObjectWriterHandle)writerObj);
        }
    }
    return result;
}

JsonWriterResult JsonObjectWriter_InitFromString(JsonObjectWriterHandle* writer, const char* json) {
    JsonWriterResult result = JSON_WRITER_OK;

    JsonObjectWriter* writerObj = malloc(sizeof(JsonObjectWriter));
    if (writerObj == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }
    memset(writerObj, 0, sizeof(*writerObj));
    writerObj->shouldFree = true;

    writerObj->rootValue = json_parse_string(json);
    if (writerObj->rootValue == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }   

    writerObj->rootObject = json_value_get_object(writerObj->rootValue);
    if (writerObj->rootObject == NULL) {
        result = JSON_WRITER_EXCEPTION;
        goto cleanup;
    }

    *writer = (JsonObjectWriterHandle)writerObj;

cleanup:
    if (result != JSON_WRITER_OK) {
        if (writerObj != NULL) {
            JsonObjectWriter_Deinit((JsonObjectWriterHandle)writerObj);
        }
    }
    return result;
}

void JsonObjectWriter_Deinit(JsonObjectWriterHandle writer) {
    JsonObjectWriter* writerObj = (JsonObjectWriter*)writer;
    if (writerObj != NULL) {
        if (writerObj->shouldFree) {
            if (writerObj->rootValue != NULL) {
                json_value_free(writerObj->rootValue);
            }
        }
        free(writerObj);
    }
}

JsonWriterResult JsonObjectWriter_WriteString(JsonObjectWriterHandle writer, const char* key, const char* value) {
    JsonObjectWriter* writerObj = (JsonObjectWriter*)writer;
    if (json_object_set_string(writerObj->rootObject, key, value) != JSONSuccess) {
        return JSON_WRITER_EXCEPTION;
    }
    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_WriteInt(JsonObjectWriterHandle writer, const char* key, int value) {
    JsonObjectWriter* writerObj = (JsonObjectWriter*)writer;
    if (json_object_set_number(writerObj->rootObject, key, value) != JSONSuccess) {
        return JSON_WRITER_EXCEPTION;
    }
    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_WriteBool(JsonObjectWriterHandle writer, const char* key, bool value) {
    JsonObjectWriter* writerObj = (JsonObjectWriter*)writer;
    if (json_object_set_boolean(writerObj->rootObject, key, value) != JSONSuccess) {
        return JSON_WRITER_EXCEPTION;
    }
    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_WriteArray(JsonObjectWriterHandle writer, const char* key, JsonArrayWriterHandle array) {
    JsonObjectWriter* objectWriter = (JsonObjectWriter*)writer;
    JsonArrayWriter* arrayWriter = (JsonArrayWriter*)array;

    if (json_object_set_value(objectWriter->rootObject, key, arrayWriter->rootValue) != JSONSuccess) {
        return JSON_WRITER_EXCEPTION;
    }

    arrayWriter->shouldFree = false;   
    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_Serialize(JsonObjectWriterHandle writer, char** output, uint32_t* size) {
    JsonObjectWriter* writerObj = (JsonObjectWriter*)writer;

    *output = json_serialize_to_string(writerObj->rootValue);
    if (*output == NULL) {
        return JSON_WRITER_EXCEPTION;
    }
    *size = strlen(*output);

    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_WriteObject(JsonObjectWriterHandle writer, const char* key, JsonObjectWriterHandle object) {
    JsonObjectWriter* rootObj = (JsonObjectWriter*)writer;
    JsonObjectWriter* objToAdd = (JsonObjectWriter*)object;

    if (json_object_set_value(rootObj->rootObject, key, objToAdd->rootValue) != JSONSuccess) {
        return JSON_WRITER_EXCEPTION;
    }

    objToAdd->shouldFree = false;   
    return JSON_WRITER_OK;
}

JsonWriterResult JsonObjectWriter_Copy(JsonObjectWriterHandle* dst, JsonObjectWriterHandle src) {
    JsonWriterResult result = JSON_WRITER_OK;

    char* serializedSource = NULL;
    uint32_t size = 0;
    result = JsonObjectWriter_Serialize(src, &serializedSource, &size);
    if (result != JSON_WRITER_OK) {
        goto cleanup;
    }

    result = JsonObjectWriter_InitFromString(dst, serializedSource);
    if (result != JSON_WRITER_OK) {
        goto cleanup;
    }
    
cleanup:

    if (serializedSource != NULL) {
        free(serializedSource);
    }
    return result;
}

bool JsonObjectWriter_Compare(JsonObjectWriterHandle a, JsonObjectWriterHandle b) {
    JsonObjectWriter* writerObjA = (JsonObjectWriter*)a;
    JsonObjectWriter* writerObjB = (JsonObjectWriter*)b;

    return json_value_equals(writerObjA->rootValue, writerObjB->rootValue);
}

JsonWriterResult JsonObjectWriter_GetSize(JsonObjectWriterHandle handle, uint32_t* size) {
    JsonObjectWriter* writer = (JsonObjectWriter*)handle;
    *size = json_object_get_count(writer->rootObject);
    return JSON_WRITER_OK;
}