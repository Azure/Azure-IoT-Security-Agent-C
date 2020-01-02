// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "macro_utils.h"
#include "umock_c_prod.h"
#include "azure_c_shared_utility/map.h"

/**
 * Utils action result
 */
typedef enum _ActionResult {
    ACTION_OK,
    ACTION_FAILED,
    ACTION_MEMORY_EXCEPTION
} ActionResult;

/**
 * @brief   converts a string to an integer using a given base
 * 
 * @param   input       the input string
 * @param   base        the relative base
 * @param   output      out param: the returned integer
 * 
 * @return  true        on success or false upon failure
 */
MOCKABLE_FUNCTION(, bool, Utils_ConvertStringToInteger, const char*, input, int, base, int*, output);

/**
 * @brief   converts an integer to string
 * 
 * @param   input           The input integer
 * @param   output          Out param: the returned string
 * @param   outputSize      In out param. On calling the parameter will contain the size of the buffer.
 *                          On return it will contain the actual size of the output; 
 * 
 * @return  true        on success or false upon failure
 */
MOCKABLE_FUNCTION(, bool, Utils_IntegerToString, int, input, char*, output, int32_t*, outputSize);

/**
 * @brief   trims the suffix following the last occurence of a token
 * 
 * @param   string      the input string
 * @param   base        the token to trim by

 */
MOCKABLE_FUNCTION(, void, Utils_TrimLastOccurance, char*, string, char, token);

/**
 * @brief   checks if one string is a prefix of the other
 * 
 * @param   prefix          the prefix to check
 * @param   prefixLength    the prefix length to check
 * @param   string          the input string
 * @param   stringLength    the input string length
 * 
 * @return  true        on success or false upon failure
 */
MOCKABLE_FUNCTION(, bool, Utils_IsPrefixOf, const char*, prefix, uint32_t, prefixLength, const char*, string, uint32_t, stringLength);

/**
 * @brief checks if the strnigs are equal.
 * 
 * @param    firstString             String to compare.
 * @param    firstStringLength       String length to compare.
 * @param    secondString            String to compare.
 * @param    secondStringLength      String length to compare.
 * @param    caseSensitive           Should regard case in comparison. In case this is false the comparison will ignore case.
 * 
 * @return true if the strings are equal, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_AreStringsEqual, const char*, firstString, uint32_t, firstStringLength, const char*, secondString, uint32_t, secondStringLength, bool, caseSensitive);

/**
 * @brief checks if the strnigs are equal. Assumes that the strings are null terminated.
 * 
 * @param   firstString             String to compare.
 * @param   secondString            String to compare.
 * @param   caseSensitive           Should regard case in comparison. In case this is false the comparison will ignore case.
 * 
 * @return true if the strings are equal, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_UnsafeAreStringsEqual, const char*, firstString, const char*, secondString, bool, caseSensitive);

/**
 * @brief   check for boundries and if possible copy the src string to the dest buffer.
 * 
 * @param   src         The source buffer.
 * @param   srcLength   The length of the source buffer.
 * @param   dest        The dest buffer.
 * @param   destLength  The length of the dest buffer.
 * 
 * @return true if the data was copied, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_CopyString, const char*, src, uint32_t, srcLength, char*, dest, uint32_t, destLength);

/**
 * @brief   concatenate the data to the given buffer and progress the buffer to its new end.
 * 
 * @param   buffer       The source buffer.
 * @param   bufferSize   In out param. The length of the buffer. After the functon is called the value of this argument
 *                       will be reduced by the size of the data that was writter.
 * @param   fmt          The format of the values to concatenate.
 * 
 * @return true on success, false otherwise.
 */
#ifdef ENABLE_MOCKS
bool Utils_ConcatenateToString(char** buffer, uint32_t* bufferSize, const char* fmt, ...) {
    return true;
}
#else
bool Utils_ConcatenateToString(char** buffer, uint32_t* bufferSize, const char* fmt, ...);
#endif

/**
 * @brief   Safely add two untrusted unsigned integers, while checking for overflow.
 * 
 * @param   result       The result buffer.
 * @param   a            First number to add.
 * @param   b            Second number to add.
 * 
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_AddUnsignedIntsWithOverflowCheck, uint32_t*, resultOut, uint32_t, a, uint32_t, b);

/**
 * @brief   allocates buffer and create new string dest from src
 * 
 * @param   dest         Pointer for the newly alocated string
 * @param   src          The string to copy
 *
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, ActionResult, Utils_DuplicateString, char**, dest, const char*, src);

/**
 * @brief   allocates buffer and copies the src string to newCopy
 * 
 * @param   newCopy      Pointer for the newly alocated copy
 * @param   src          The string to copy
 *
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_CreateStringCopy, char**, newCopy, const char*, src);

/**
 * @brief   Converts Hex string to byte array
 * 
 * @param   hexString    Hex string to convert
 * @param   buffer       Buffer for the converted byte array
 * @param   bufferSize   In-Out param - the size of the buffer, returns with amount of bytes written
 *
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_HexStringToByteArray, const char*, hexString, unsigned char*, buffer, uint32_t*, bufferSize);

/**
 * @brief   Check if char* is blank {NULL, empty, whitespaces}
 * 
 * @param   s   string
 *
 * @return true iff s is blank.
 */
MOCKABLE_FUNCTION(, bool, Utils_IsStringBlank, const char*, s);

/**
 * @brief   Checks if the given string contains numbers only.
 * 
 * @param   string   string
 *
 * @return true iff string contains numbers only.
 */
MOCKABLE_FUNCTION(, bool, Utils_IsStringNumeric, char*, string);

/**
 * @brief   Generates substring of the given string according to given offsets.
 *          Allocates memory for dest and copies into it the substring.
 * 
 * @param   src             string
 * @param   dest            Pointer for the newly allocated string
 * @param   startOffset     start offset
 * @param   endOffset       end offset
 *
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_Substring, const char*, src, char**, dest, uint32_t, startOffset, uint32_t, endOffset);

/**
 * @brief   Returns map size in the given size pointer.
 * 
 * @param   handle          Map_Hanle pointer
 * @param   size            out param: the returned map size
 * 
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, Utils_GetMapSize, MAP_HANDLE, handle, size_t*, size);

/**
 * @brief   allocates memory for output and copies into it the formatted string.
 * 
 * @param   str   string
 * @paran   output Pointer for the newly alocated string
 *
 * @return ACTION_RESULT 
 */
#ifdef ENABLE_MOCKS
ActionResult Utils_StringFormat(const char* str, char** output, ...){
    return ACTION_OK;
}
#else
ActionResult Utils_StringFormat(const char* str, char** output, ...);
#endif

#endif //UTILS_H
