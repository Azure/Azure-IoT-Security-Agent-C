// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "utils.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "logger.h"

bool Utils_ConvertStringToInteger(const char* input, int base, int* output) {
    if (input == NULL) {
        Logger_Error("NULL input is given");
        return false;
    }

    char* end;
    // strtol documentation asks to set errno to 0 before calling it
    errno = 0;
    long int value = strtol(input, &end, base);

    if (input == end) {
        Logger_Error("couldn't read any digits from input");
        return false;
    } else if ((value == LONG_MIN || value == LONG_MAX || value == LLONG_MIN || value == LLONG_MAX) && errno == ERANGE) {
        Logger_Error("out of range");
        return false;
    }
    else if (errno != 0 && value == 0) {
        Logger_Error("number invalid! %d", errno);
        return false;
    } else if (value > INT_MAX || value < INT_MIN) {
        Logger_Error("out of range");
        return false;
    }

    *output = (int)value;
    return true;
}

bool Utils_IntegerToString(int input, char* output, int32_t* outputSize) {
    int stringLength = snprintf(NULL, 0, "%d", input);
    if (stringLength < 0) {
        return false;
    }
    // adding null terminator
    ++stringLength;

    if (stringLength > *outputSize) {
        return false;
    }
    
    *outputSize = snprintf(output, *outputSize, "%d", input);
    if (*outputSize < 0 || *outputSize >= stringLength) {
        return false;
    }
    return true;
}

void Utils_TrimLastOccurance(char* string, char token) {
    int i = strlen(string);
    while (i >= 0 && string[i] != token) {
        --i;
    }
    if (i >= 0) {
        string[i] = '\0';
    }
}

bool Utils_IsPrefixOf(const char* prefix, uint32_t prefixLength, const char* string, uint32_t stringLength) {
    return stringLength >= prefixLength && (strncmp(string, prefix, prefixLength) == 0);
}

bool Utils_AreStringsEqual(const char* firstString, uint32_t firstStringLength, const char* secondString, uint32_t secondStringLength, bool caseSensitive) {
    if (firstStringLength != secondStringLength) {
        return false;
    }

    if (caseSensitive) {
        return (strncmp(firstString, secondString, secondStringLength) == 0);
    }

    return (strncasecmp(firstString, secondString, secondStringLength) == 0);
}

bool Utils_UnsafeAreStringsEqual(const char* firstString, const char* secondString, bool caseSensitive) {
    return Utils_AreStringsEqual(firstString, strlen(firstString), secondString, strlen(secondString), caseSensitive);
}

bool Utils_CopyString(const char* src, uint32_t srcLength, char* dest, uint32_t destLength) {
    if (destLength < srcLength) {
        return false;
    }
    memcpy(dest, src, srcLength);
    return true; 
}

bool Utils_ConcatenateToString(char** buffer, uint32_t* bufferSize, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int result = vsnprintf(*buffer, *bufferSize, fmt, args);
    va_end(args);

    if (result < 0 || result >= *bufferSize) {
        return false;
    }

    (*buffer) += result;
    (*bufferSize) -= result;
    return true;
}


ActionResult Utils_DuplicateString(char** dest, const char* src) {
    if (src == NULL) {
        *dest = NULL;
        return ACTION_OK;
    }

    uint32_t size = strlen(src) + 1;
    *dest = NULL;
    *dest = malloc(size * sizeof(char));

    if (*dest == NULL) {
        return ACTION_MEMORY_EXCEPTION;
    }

    memcpy(*dest, src, size);
    return ACTION_OK;
}


bool Utils_CreateStringCopy(char** newCopy, const char* src) {
    if (src == NULL || newCopy == NULL) {
        return false;
    }

    uint32_t size = strlen(src) + 1;
    *newCopy = NULL;
    *newCopy = malloc(size * sizeof(char));

    if (*newCopy == NULL) {
        return false;
    }

    memcpy(*newCopy, src, size);
    return true;
}


bool Utils_Substring(const char* src, char** dest, uint32_t startOffset, uint32_t endOffset){
    if (src == NULL || dest == NULL || startOffset < 0 || endOffset < 0){
        return false;
    }
    uint32_t len = strlen(src);
    if (startOffset >= len || endOffset >= len || (startOffset + endOffset) >= len) {
        return false;
    }
    uint32_t size = 0;
    size = len - startOffset - endOffset + 1;

    *dest = malloc(size * sizeof(char));
    if (*dest == NULL) {
        return false;
    }
    int i=startOffset,j=0;
    char* s = *dest;
    for(; j < size -1 ; i++,j++){
        s[j] = src[i];
    }

    s[size-1] = '\0';
    return true;
}

bool Utils_AddUnsignedIntsWithOverflowCheck(uint32_t* result, uint32_t a, uint32_t b) {
    if (a > UINT32_MAX - b) {
        return false;
    }
    *result = a + b;
    return true;
}

bool Utils_HexStringToByteArray(const char* hexString, unsigned char* buffer, uint32_t* bufferSize) {
    uint32_t hexStringLen = strlen(hexString);
    if (hexStringLen % 2 == 1 || hexStringLen / 2 >= *bufferSize) {
            return false;
    }

    for (uint32_t i = 0; i < hexStringLen; i+= 2) {
        if (sscanf(hexString+i, "%2hhx", &buffer[i/2]) != 1) {
            return false;
        }
    }

    buffer[hexStringLen / 2] = 0; // Terminate with null
    *bufferSize = hexStringLen / 2;
    return true;
}

bool Utils_IsStringBlank(const char* s) {
    if (s == NULL) {
        return true;
    }

    while (*s != '\0') {
        if (!isspace((unsigned char)*s)) {
            return false;
        }
      
        s++;
    }

  return true;
}

bool Utils_IsStringNumeric(char* string){

    if(string == NULL){
        return false;
    }
    
    while (*string != '\0') {
        if(!isdigit((unsigned char)*string)){
            return false;
        }
        string++;
    }

    return true;
}

ActionResult Utils_StringFormat(const char* str, char** output, ...) {
    va_list args = {0};
    ActionResult result = ACTION_OK;

    if (str == NULL) {
        result = ACTION_FAILED;
        goto cleanup;
    }

    // resolve new str length without memory allocation
    va_start(args, output);
    int newStrFormattedLength = 1 + vsnprintf(NULL, 0, str, args);
    va_end(args);

    // allocate exact memory
    *output = malloc(sizeof(char) * newStrFormattedLength);
    if (*output == NULL) {
        result = ACTION_MEMORY_EXCEPTION;
        goto cleanup;
    }

    // format string with dynamic parameters
    va_start(args, *output);
    vsnprintf(*output, newStrFormattedLength, str, args);
    va_end(args);
cleanup:
    if ((result != ACTION_OK) && (*output != NULL)) {
        free(*output);
        *output = NULL;
    }

    return result;
}

bool Utils_GetMapSize(MAP_HANDLE handle, size_t* size){
    const char*const* keys;
    const char*const* values;
    if (Map_GetInternals(handle, &keys, &values, size) != MAP_OK){
        return false;
    }

    return true;
}