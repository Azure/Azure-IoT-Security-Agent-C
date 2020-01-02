// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef JSON_OBJECT_WRITER_H
#define JSON_OBJECT_WRITER_H

#include <stdbool.h>
#include <stdint.h>

#include "umock_c_prod.h"
#include "macro_utils.h"

#include "json/json_defs.h"

/**
 * @brief Initiates a new json object writer on the given json.
 * 
 * @param   writer  Out param. The handle to use for the json writer operations.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_Init, JsonObjectWriterHandle*, writer);

/**
 * @brief Initiates a new json object writer from the given string.
 * 
 * @param   writer  Out param. The handle to use for the json writer operations.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_InitFromString, JsonObjectWriterHandle*, writer, const char*, json);

/**
 * @brief Deinitiate the json writer.
 * 
 * @param   writer  The reader instance to deiniitate.
 */
MOCKABLE_FUNCTION(, void, JsonObjectWriter_Deinit, JsonObjectWriterHandle, writer);

/**
 * @brief Write the key with the given string value to the json.
 * 
 * @param   writer  The json writer instance.
 * @param   key     The key to write.
 * @param   value   The value of the new key.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_WriteString, JsonObjectWriterHandle, writer, const char*, key, const char*, value);

/**
 * @brief Write the key with the given int value to the json.
 * 
 * @param   writer  The json writer instance.
 * @param   key     The key to write.
 * @param   value   The value of the new key.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_WriteInt, JsonObjectWriterHandle, writer, const char*, key, int, value);

/**
 * @brief Write the key with the given bool value to the json.
 * 
 * @param   writer  The json writer instance.
 * @param   key     The key to write.
 * @param   value   The value of the new key.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_WriteBool, JsonObjectWriterHandle, writer, const char*, key, bool, value);

/**
 * @brief Write the given array to this json objecto.
 * 
 * @param   writer  The json writer instance.
 * @param   key     The key to write.
 * @param   array   The new array to add.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_WriteArray, JsonObjectWriterHandle, writer, const char*, key, JsonArrayWriterHandle, array);

/**
 * @brief Serialize the given object to char*.
 * 
 * @param   writer  The json writer instance.
 * @param   output  Out param. The serialized object.
 * @param   size    Out param. The size of the serialized output.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure. 
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_Serialize, JsonObjectWriterHandle, writer, char**, output, uint32_t*, size);

/**
 * @brief Write the given object to this json object.
 * 
 * @param   writer  The json writer instance.
 * @param   key     The key to add.
 * @param   object  The new object to add.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_WriteObject, JsonObjectWriterHandle, writer, const char*, key, JsonObjectWriterHandle, object);

/**
 * @brief Creates a newly allocated copy of the given object
 * 
 * @param   dst     Destination object
 * @param   key     The key to add.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_Copy, JsonObjectWriterHandle*, dst, JsonObjectWriterHandle, src);

/**
 * @brief Compares two json objects
 * 
 * @param   a            first object
 * @param   b            second object
 * 
 * @return true if object are equal, else false
 */
MOCKABLE_FUNCTION(, bool, JsonObjectWriter_Compare, JsonObjectWriterHandle, a, JsonObjectWriterHandle, b);

/**
 * @brief Returns the number of items in this array.
 * 
 * @param   handle          The writer instance.
 * @param   size   Out param. On success contains the number of elements in the array.
 * 
 * @return JSON_WRITER_OK.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_GetSize, JsonObjectWriterHandle, handle, uint32_t*, size);

/**
 * @brief Sets the new root of the json writer to be the given key.
 * 
 * @param   handle  Out param. The handle to use for the json writer operations.
 * @param   key     The key to set the root.
 * 
 * @return JSON_WRITER_OK on success, an indicative error in failure. The state of the writer will be the same in case of error.
 */
MOCKABLE_FUNCTION(, JsonWriterResult, JsonObjectWriter_StepIn, JsonObjectWriterHandle, handle, const char*, key);



#endif //JSON_OBJECT_WRITER_H