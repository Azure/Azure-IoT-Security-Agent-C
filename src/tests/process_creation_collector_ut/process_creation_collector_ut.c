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
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/linux/audit/audit_search.h"
#include "os_utils/linux/audit/audit_search_record.h"
#include "collectors/linux/generic_audit_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "synchronized_queue.h"
#include "collectors/event_aggregator.h"
#include "azure_c_shared_utility/map.h"
#undef ENABLE_MOCKS

#include "collectors/process_creation_collector.h"
#include "message_schema_consts.h"

const char AUDIT_CONTROL_ON_SUCCESS_FILTER[] = "success=1";
const char AUDIT_CONTROL_TYPE_EXECVE[] = "execve";
const char AUDIT_CONTROL_TYPE_EXECVEAT[] = "execveat";
const char AUDIT_CONTROL_TYPE_CONNECT[] = "connect";
const char AUDIT_CONTROL_TYPE_ACCEPT[] = "accept";

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

AuditSearchResultValues Mocked_AuditSearchRecord_MaxRecordLength(AuditSearch* auditSearch, uint32_t* length) {
    *length = 10;
    return AUDIT_SEARCH_OK;
}

AuditSearchResultValues Mocked_AuditSearchRecord_ReadInt(AuditSearch* auditSearch, const char* fieldName, int* output) {
    *output = 2;
    return AUDIT_SEARCH_OK;
}

static const char* DUMMY_VALUE = "ab";
AuditSearchResultValues Mocked_AuditSearchRecord_InterpretString(AuditSearch* auditSearch, const char* fieldName, const char** output) {
    *output = DUMMY_VALUE;
    return AUDIT_SEARCH_OK;
}

static bool isAggregationEnabled = false;
EventAggregatorResult Mocked_EventAggregator_IsAggregationEnabled(EventAggregatorHandle handle, bool* isEnabled) {
    *isEnabled = isAggregationEnabled;

    return EVENT_AGGREGATOR_OK;
}
MAP_HANDLE Mocked_Map_Create(MAP_FILTER_CALLBACK mapFilterFunc) {
    return (MAP_HANDLE)0x5;
}
MAP_RESULT Mocked_Map_GetInternals(MAP_HANDLE handle, const char*const** keys, const char*const** values, size_t* count){
    *count = 1;
    return MAP_OK;
}

void VailidateCommandLine() {
    STRICT_EXPECTED_CALL(AuditSearchRecord_Goto(IGNORED_PTR_ARG, 1309)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearchRecord_MaxRecordLength(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearchRecord_ReadInt(IGNORED_PTR_ARG, "argc", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearchRecord_InterpretString(IGNORED_PTR_ARG, "a0", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearchRecord_InterpretString(IGNORED_PTR_ARG, "a1", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, PROCESS_CREATION_COMMAND_LINE_KEY, "ab ab")).SetReturn(JSON_WRITER_OK);
}

BEGIN_TEST_SUITE(process_creation_collector_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(QueueResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonArrayWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(EventCollectorResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchCriteria, int);
    REGISTER_UMOCK_ALIAS_TYPE(Architecture, int);
    REGISTER_UMOCK_ALIAS_TYPE(EventAggregatorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(EventAggregatorResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditControlResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_FILTER_CALLBACK, void*);

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_MaxRecordLength, Mocked_AuditSearchRecord_MaxRecordLength);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_ReadInt, Mocked_AuditSearchRecord_ReadInt);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_InterpretString, Mocked_AuditSearchRecord_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(EventAggregator_IsAggregationEnabled, Mocked_EventAggregator_IsAggregationEnabled);
    REGISTER_GLOBAL_MOCK_HOOK(Map_Create, Mocked_Map_Create);
    REGISTER_GLOBAL_MOCK_HOOK(Map_GetInternals, Mocked_Map_GetInternals);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_MaxRecordLength, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_ReadInt, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(EventAggregator_IsAggregationEnabled, NULL);
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_AggregationDisabled_ExpectSuccess)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = false;

    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE, IGNORED_PTR_ARG, 2, "/var/tmp/processCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, PROCESS_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    VailidateCommandLine();
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", PROCESS_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", PROCESS_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "ppid", PROCESS_CREATION_PARENT_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(Map_GetValueFromKey(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(QUEUE_OK);

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);

    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ProcessCreationCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_AggregationEnabled_ExpectSuccess)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = true;

    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE, IGNORED_PTR_ARG, 2, "/var/tmp/processCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    VailidateCommandLine();
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", PROCESS_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", PROCESS_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "ppid", PROCESS_CREATION_PARENT_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(Map_GetValueFromKey(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, PROCESS_CREATION_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, PROCESS_CREATION_PARENT_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(EventAggregator_AggregateEvent(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);

    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ProcessCreationCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_AggregationEnabled_FailOnAggregation_ExpectFalil)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = true;

    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE, IGNORED_PTR_ARG, 2, "/var/tmp/processCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    VailidateCommandLine();
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", PROCESS_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", PROCESS_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "ppid", PROCESS_CREATION_PARENT_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(Map_GetValueFromKey(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, PROCESS_CREATION_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, PROCESS_CREATION_PARENT_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(EventAggregator_AggregateEvent(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_AGGREGATOR_EXCEPTION);

    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ProcessCreationCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_AggregationDisabled_BadRecord_ExpectSuccess)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = false;

    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE, IGNORED_PTR_ARG, 2, "/var/tmp/processCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, PROCESS_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    VailidateCommandLine();
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", PROCESS_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", PROCESS_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "ppid", PROCESS_CREATION_PARENT_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(Map_GetValueFromKey(IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(QUEUE_OK);

    // another record - the uncomplete record
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, PROCESS_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG,IGNORED_PTR_ARG,IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    VailidateCommandLine();
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, false)).SetReturn(EVENT_COLLECTOR_RECORD_HAS_ERRORS);

    // no more records
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);

    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ProcessCreationCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_AggregationDisabled_ExpectFailure)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = false;
    umock_c_negative_tests_init();

    STRICT_EXPECTED_CALL(AuditSearch_Init(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE, "EXECVE", "/var/tmp/processCreationCheckpoint")).SetFailReturn(!AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, PROCESS_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, PROCESS_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetFailReturn(EVENT_COLLECTOR_EXCEPTION);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // we can't have a fail return to all fields since the negative tests count on the fact that 0 is the value of success
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "exe", PROCESS_CREATION_EXECUTABLE_KEY, false)).SetFailReturn(EVENT_COLLECTOR_EXCEPTION);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!QUEUE_OK);

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetFailReturn(!AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetFailReturn(!AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    umock_c_negative_tests_snapshot();

    for (int i = 0; i < umock_c_negative_tests_call_count(); i++) {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        EventCollectorResult result = ProcessCreationCollector_GetEvents(&mockedQueue);
        ASSERT_ARE_NOT_EQUAL(int, EVENT_COLLECTOR_OK, result);
    }

    umock_c_negative_tests_deinit();

}

TEST_FUNCTION(ProcessCreationCollector_Init_ExpectSuccess)
{
    STRICT_EXPECTED_CALL(AuditControl_Init(IGNORED_PTR_ARG)).SetReturn(AUDIT_CONTROL_OK);

    STRICT_EXPECTED_CALL(AuditControl_AddRule(IGNORED_PTR_ARG, IGNORED_PTR_ARG, 2, NULL)).SetReturn(AUDIT_CONTROL_OK);
    STRICT_EXPECTED_CALL(EventAggregator_Init(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_AGGREGATOR_OK);
    STRICT_EXPECTED_CALL(Map_Create(IGNORED_PTR_ARG)).SetReturn((MAP_HANDLE)0x01);
    STRICT_EXPECTED_CALL(AuditSearch_Init(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_TYPE,IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(Map_GetInternals(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditControl_Deinit(IGNORED_PTR_ARG));

    EventCollectorResult result = ProcessCreationCollector_Init();
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

END_TEST_SUITE(process_creation_collector_ut)
