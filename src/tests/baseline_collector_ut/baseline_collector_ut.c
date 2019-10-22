// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"
#include "umock_c_negative_tests.h"

#define ENABLE_MOCKS
#include "collectors/generic_event.h"
#include "json/json_array_reader.h"
#include "json/json_array_writer.h"
#include "json/json_object_reader.h"
#include "json/json_object_writer.h"
#include "os_utils/process_info_handler.h"
#include "os_utils/process_utils.h"
#include "synchronized_queue.h"
#include "twin_configuration.h"
#include "utils.h"
#undef ENABLE_MOCKS

#include "twin_configuration_consts.h"
#include "twin_configuration_defs.h"
#include "collectors/linux/baseline_collector.h"
#include "message_schema_consts.h"


static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

static int numberOfItems = 2;
JsonReaderResult Mocked_JsonArrayReader_GetSize(JsonArrayReaderHandle handle, uint32_t* numOfelements) {
    *numOfelements = numberOfItems;
    return JSON_READER_OK;
}

static const char* RESULT = "RES";
static const char* DESCRIPTION = "desc desc";
static const char* CCEID = "cceid";
static const char* ERROR = "err";
static const char* SEVERITY = "Critical";

JsonReaderResult Mocked_JsonObjectReader_ReadString(JsonObjectReaderHandle handle, const char* key, char** output) {
    if (strcmp(key, "result") == 0) {
        *output = (char*)RESULT;
    } else if (strcmp(key, "description") == 0) {
        *output = (char*)DESCRIPTION;
    } else if (strcmp(key, "cceid") == 0) {
        *output = (char*)CCEID;
    } else if (strcmp(key, "error_text") == 0) {
        *output = (char*)ERROR;
    } else if (strcmp(key, "severity") == 0) {
        *output = (char*)SEVERITY;
    } else {
        return JSON_READER_EXCEPTION;
    }

    return JSON_READER_OK;
}

JsonWriterResult Mocked_JsonObjectWriter_Init(JsonObjectWriterHandle* writer) {
    *writer = (JsonObjectWriterHandle)0x1;
    return JSON_WRITER_OK;
}

JsonWriterResult Mocked_JsonArrayWriter_Init(JsonArrayWriterHandle* writer) {
    *writer = (JsonArrayWriterHandle)0x2;
    return JSON_WRITER_OK;
}

JsonReaderResult Mocked_JsonObjectReader_InitFromString(JsonObjectReaderHandle* handle, const char* data) {
    *handle = (JsonObjectReaderHandle)0x3;
    return JSON_READER_OK;
}

JsonReaderResult Mocked_JsonArrayReader_ReadObject(JsonArrayReaderHandle handle, uint32_t index, JsonObjectReaderHandle* objectHandle) {
    *objectHandle = (JsonObjectReaderHandle)0x4;
    return JSON_READER_OK;
}

JsonReaderResult Mocked_JsonObjectReader_ReadArray(JsonObjectReaderHandle handle, const char* key, JsonArrayReaderHandle* output) {
    *output = (JsonArrayReaderHandle)0x5;
    return JSON_READER_OK;
}

BEGIN_TEST_SUITE(baseline_collector_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectReaderHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonReaderResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonArrayWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonArrayReaderHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(EventCollectorResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(QueueResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(TwinConfigurationResult, int);

    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayReader_GetSize, Mocked_JsonArrayReader_GetSize);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadString, Mocked_JsonObjectReader_ReadString);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, Mocked_JsonObjectWriter_Init);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayWriter_Init, Mocked_JsonArrayWriter_Init);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_InitFromString, Mocked_JsonObjectReader_InitFromString);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayReader_ReadObject, Mocked_JsonArrayReader_ReadObject);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadArray, Mocked_JsonObjectReader_ReadArray);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadArray, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_InitFromString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayReader_ReadObject, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayWriter_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayReader_GetSize, NULL);
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(BaselineCollector_GetEvents_ExpectSuccess)
{
    SyncQueue mockedQueue;
    
    EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION)).SetReturn(EVENT_COLLECTOR_OK);
    EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG));

    // run the oms baseline
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessUtils_Execute("./omsbaseline -d .", IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG)).SetReturn(true);

    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadArray(IGNORED_PTR_ARG, "results", IGNORED_PTR_ARG));
    numberOfItems = 2;
    STRICT_EXPECTED_CALL(JsonArrayReader_GetSize(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    // first item in the osbasline - will be PASS result
    STRICT_EXPECTED_CALL(JsonArrayReader_ReadObject(IGNORED_PTR_ARG, 0, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "result", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(Utils_UnsafeAreStringsEqual("PASS", IGNORED_PTR_ARG, false)).SetReturn(true);
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(IGNORED_PTR_ARG));

    // second item in the osbasline 
    STRICT_EXPECTED_CALL(JsonArrayReader_ReadObject(IGNORED_PTR_ARG, 1, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "result", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(Utils_UnsafeAreStringsEqual("PASS", IGNORED_PTR_ARG, false)).SetReturn(false);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Result", RESULT)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "description", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Description", DESCRIPTION)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "cceid", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "CceId", CCEID)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "error_text", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Error", ERROR)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "severity", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Severity", SEVERITY)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonArrayReader_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(TwinConfiguration_GetBaselineCustomChecksEnabled(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfiguration_GetBaselineCustomChecksFilePath(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfiguration_GetBaselineCustomChecksFileHash(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);

    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(QUEUE_OK);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

    EventCollectorResult result = BaselineCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(BaselineCollector_GetEvents_ExpectFailure)
{
    umock_c_negative_tests_init();
    SyncQueue mockedQueue;
    
    EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION)).SetFailReturn(!EVENT_COLLECTOR_OK);
    EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // run the oms baseline
    // can't set fail return to all 3 functions
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessUtils_Execute("./omsbaseline -d .", IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG)).SetReturn(true);

    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadArray(IGNORED_PTR_ARG, "results", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    numberOfItems = 1;
    // no fail case
    STRICT_EXPECTED_CALL(JsonArrayReader_GetSize(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonArrayReader_ReadObject(IGNORED_PTR_ARG, 0, IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "result", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    // no fail case
    STRICT_EXPECTED_CALL(Utils_UnsafeAreStringsEqual("PASS", IGNORED_PTR_ARG, false)).SetReturn(false);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Result", RESULT)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "description", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Description", DESCRIPTION)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "cceid", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "CceId", CCEID)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "error_text", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Error", ERROR)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(IGNORED_PTR_ARG, "severity", IGNORED_PTR_ARG)).SetFailReturn(!JSON_READER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, "Severity", SEVERITY)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    // no fail case
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    // no fail case
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(IGNORED_PTR_ARG));

    // no fail case
    STRICT_EXPECTED_CALL(JsonArrayReader_Deinit(IGNORED_PTR_ARG));
    // no fail case
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG)).SetReturn(true);

    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(EVENT_COLLECTOR_EXCEPTION);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!QUEUE_OK);

    // no fail case
    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));
    // no fail case
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

    umock_c_negative_tests_snapshot();

    int count = umock_c_negative_tests_call_count();

    for (int i = 0; i < count; i++) {
        switch (i) {
            case 3:
            case 4:
            case 5:
            case 8:
            case 11:
            case 23:
            case 24:
            case 25:
            case 26:
            case 27:
            case 28:
            case 29:
            case 30:
            case 31:
            case 32:
            case 33:
                // skip deinit since they don't have a fail return
                continue;
        }
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);
        
        EventCollectorResult result = BaselineCollector_GetEvents(&mockedQueue);
        ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    }

    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(BaselineCollector_GetEvents_ProcessUtilsFailed_ExpectFailure) {
    
    SyncQueue mockedQueue;
    
    // set privileges failed
    EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION)).SetFailReturn(!EVENT_COLLECTOR_OK);
    EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // run the oms baseline
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(false);
    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

    EventCollectorResult result = BaselineCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());


    // execute failed
    EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION)).SetFailReturn(!EVENT_COLLECTOR_OK);
    EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // run the oms baseline
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessUtils_Execute("./omsbaseline -d .", IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(false);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG)).SetReturn(true);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    result = BaselineCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // reset privileges failed
    EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, BASELINE_NAME, EVENT_TYPE_SECURITY_VALUE, BASELINE_PAYLOAD_SCHEMA_VERSION)).SetFailReturn(!EVENT_COLLECTOR_OK);
    EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // run the oms baseline
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(ProcessUtils_Execute("./omsbaseline -d .", IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(false);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG)).SetReturn(false);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    result = BaselineCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

END_TEST_SUITE(baseline_collector_ut)
