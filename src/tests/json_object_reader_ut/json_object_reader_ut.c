// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"
#include "umock_c.h"
#include "azure_c_shared_utility/map.h"

#define ENABLE_MOCKS
#include "json/json_array_reader.h"
#include "utils.h"
#undef ENABLE_MOCKS

#include "consts.h"
#include "internal/time_utils.h"
#include "internal/time_utils_consts.h"
#include "json/json_object_reader.h"
#include "os_utils/os_utils.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

void Real_Utils_TrimLastOccurance(char* string, char token) {
    int i = strlen(string);
    while (i >= 0 && string[i] != token) {
        --i;
    }
    if (i >= 0) {
        string[i] = '\0';
    }
}

bool Real_Utils_AddUnsignedIntsWithOverflowCheck(uint32_t* result, uint32_t a, uint32_t b) {
    if (a > UINT32_MAX - b) {
        return false;
    }
    *result = a + b;
    return true;
}

BEGIN_TEST_SUITE(json_object_reader_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    REGISTER_GLOBAL_MOCK_HOOK(Utils_TrimLastOccurance, Real_Utils_TrimLastOccurance);
    REGISTER_GLOBAL_MOCK_HOOK(Utils_AddUnsignedIntsWithOverflowCheck, Real_Utils_AddUnsignedIntsWithOverflowCheck);

    REGISTER_UMOCK_ALIAS_TYPE(JsonReaderResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectReaderHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);

    umocktypes_bool_register_types();
    umocktypes_charptr_register_types();

}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(JsonObjectReader_InitFromString_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_IS_NOT_NULL(reader);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_InitFromFile_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    char fileName[] = "/json_reader_test.json";
    char* connectionString = NULL;
    char* agentId = NULL;

    char* file = GetExecutableDirectory();
    ASSERT_IS_NOT_NULL(file);
    int pathLength = strlen(file);
    char* temp = (char*)realloc(file, pathLength + strlen(fileName) + 1);
    ASSERT_IS_NOT_NULL(temp);
    file = temp;
    memcpy(file + pathLength, fileName, strlen(fileName) + 1);

    JsonReaderResult result = JsonObjectReader_InitFromFile(&reader, file);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    result = JsonObjectReader_ReadString(reader, "Configuration.ConnectionString", &connectionString);
    ASSERT_ARE_EQUAL(char_ptr,connectionString, "<ConnectionString placeholder>");

    result = JsonObjectReader_ReadString(reader, "Configuration.AgentId", &agentId);
    ASSERT_ARE_EQUAL(char_ptr, agentId, "<AgentId placeholder>");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_IS_NOT_NULL(reader);

    JsonObjectReader_Deinit(reader);

    free(file);
}

TEST_FUNCTION(JsonObjectReader_InitFromString_InvalidJson_ExpectFailure)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{asd");

    ASSERT_ARE_EQUAL(int, JSON_READER_EXCEPTION, result);
    ASSERT_IS_NULL(reader);
}

TEST_FUNCTION(JsonObjectReader_InitFromFile_ExpectFailure)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromFile(&reader, "/Idontreallyexist.json");

    ASSERT_ARE_EQUAL(int, JSON_READER_EXCEPTION, result);
    ASSERT_IS_NULL(reader);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_Deinit_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_StepIn_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{\"a\": {\"b\" : \"c\"}}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    result = JsonObjectReader_StepIn(reader, "a");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_StepIn_KeyDoesNotExist_ExpectFailure)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{\"a\": {\"b\" : \"c\"}}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    result = JsonObjectReader_StepIn(reader, "b");
    ASSERT_ARE_EQUAL(int, JSON_READER_KEY_MISSING, result);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_StepInAndOut_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{\"a\": {\"b\" : \"c\"}}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    result = JsonObjectReader_StepIn(reader, "a");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    result = JsonObjectReader_StepOut(reader);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    result = JsonObjectReader_StepIn(reader, "a");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_StepOut_NoParentObject_ExpectFailure)
{
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = JsonObjectReader_InitFromString(&reader, "{\"a\": {\"b\" : \"c\"}}");

    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    result = JsonObjectReader_StepOut(reader);
    ASSERT_ARE_EQUAL(int, JSON_READER_EXCEPTION, result);

    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_ReadTimeInMilliseconds_ExpectSuccess)
{
    uint32_t timeField = 0;
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = 0;

    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"datetime\":\"PT1H2M3S\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadTimeInMilliseconds(reader, "datetime", &timeField);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_ARE_EQUAL(uint32_t, MILLISECONDS_IN_AN_HOUR + 2 * MILLISECONDS_IN_A_MINUTE + 3 * MILLISECONDS_IN_A_SECOND, timeField);
    JsonObjectReader_Deinit(reader);

    // invalid date format
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"datetime\":\"010203\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadTimeInMilliseconds(reader, "datetime", &timeField);
    ASSERT_ARE_EQUAL(int, JSON_READER_PARSE_ERROR, result);
    JsonObjectReader_Deinit(reader);

    // invalid date format - contains characters
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"datetime\":\"PT1H:0a03S\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadTimeInMilliseconds(reader, "datetime", &timeField);
    ASSERT_ARE_EQUAL(int, JSON_READER_PARSE_ERROR, result);
    JsonObjectReader_Deinit(reader);

    // missing key
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"datetime\":\"01:02:03\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadTimeInMilliseconds(reader, "datetim", &timeField);
    ASSERT_ARE_EQUAL(int, JSON_READER_KEY_MISSING, result);
    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_ExtractFieldInteger_ExpectSuccess)
{
    uint32_t integerField = 0;
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = 0;


    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"integer\":75842}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadInt(reader, "integer", &integerField);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_ARE_EQUAL(uint32_t, 75842, integerField);
    JsonObjectReader_Deinit(reader);

    // invalid iteger
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"integer\":\"abcd\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadInt(reader, "integer", &integerField);
    ASSERT_ARE_EQUAL(int, JSON_READER_PARSE_ERROR, result);
    JsonObjectReader_Deinit(reader);

    // missing key
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"integer\":123}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadInt(reader, "datetim", &integerField);
    ASSERT_ARE_EQUAL(int, JSON_READER_KEY_MISSING, result);
    JsonObjectReader_Deinit(reader);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(JsonObjectReader_ExtractFieldString_ExpectSuccess)
{
    char* strField = NULL;
    JsonObjectReaderHandle reader = NULL;
    JsonReaderResult result = 0;

    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"value\":\"This is a nice message 123#\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadString(reader, "value", &strField);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "This is a nice message 123#", strField);
    JsonObjectReader_Deinit(reader);

    // missing key
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"value\":\"123\"}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    result = JsonObjectReader_ReadString(reader, "datetim", &strField);
    ASSERT_ARE_EQUAL(int, JSON_READER_KEY_MISSING, result);
    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_ReadArray_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonArrayReaderHandle arrayReader = NULL;
    JsonReaderResult result = 0;

    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"value\": [{\"1\": \"one\"}, {\"2\": \"two\"}]}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    STRICT_EXPECTED_CALL(JsonArrayReader_Init(&arrayReader, reader, "value")).SetReturn(JSON_READER_OK);
    result = JsonObjectReader_ReadArray(reader, "value", &arrayReader);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    
    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_ReadObject_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonArrayReaderHandle arrayReader = NULL;
    JsonReaderResult result = 0;

    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"value\": {\"1\": \"one\", \"2\": \"two\"}}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    JsonObjectReaderHandle innerObject = NULL;
    result = JsonObjectReader_ReadObject(reader, "value", &innerObject);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_IS_NOT_NULL(innerObject);
    
    JsonObjectReader_Deinit(innerObject);
    JsonObjectReader_Deinit(reader);
}

TEST_FUNCTION(JsonObjectReader_ReadObject_ReadNested_ExpectSuccess)
{
    JsonObjectReaderHandle reader = NULL;
    JsonArrayReaderHandle arrayReader = NULL;
    JsonReaderResult result = 0;

    // valid json
    result = JsonObjectReader_InitFromString(&reader, "{\"a\" : \"b\", \"value\": {\"value2\" : {\"1\": \"one\", \"2\": \"two\"}}}");
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);

    JsonObjectReaderHandle innerObject = NULL;
    result = JsonObjectReader_ReadObject(reader, "value.value2", &innerObject);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_IS_NOT_NULL(innerObject);

    char* strValue = NULL;
    result = JsonObjectReader_ReadString(innerObject, "1", &strValue);
    ASSERT_ARE_EQUAL(int, JSON_READER_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "one", strValue);
    
    JsonObjectReader_Deinit(innerObject);
    JsonObjectReader_Deinit(reader);
}

END_TEST_SUITE(json_object_reader_ut)
