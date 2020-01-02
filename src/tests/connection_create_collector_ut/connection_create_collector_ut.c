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
#include "collectors/event_aggregator.h"
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/linux/audit/audit_search.h"
#include "collectors/linux/generic_audit_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "synchronized_queue.h"
#undef ENABLE_MOCKS

#include "collectors/connection_create_collector.h"
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

static char* MOCKED_INTET_SOCKET_ADDRESS = "inet host:68.232.34.200 serv:53";
static char* MOCKED_LOCAL_SOCKET_ADDRESS = "local /tmp/dbus";
static char* MOCKED_UNKNOWN_SOCKET_ADDRESS = "Peter Quill ruined everything";
static char* MOCKED_SOCKET_ADDRESS;
static int MOCKED_CONNECT_SYSCAL = 42;
static char* MOCKED_EXE = "testing exe";
static char* MOCKED_CMD = "testing cmd";


AuditSearchResultValues Mocked_AuditSearch_InterpretString(AuditSearch* auditSearch, const char* fieldName, const char** output) {
    if (strcmp(fieldName, "saddr") == 0) {
        *output = MOCKED_SOCKET_ADDRESS;
        return AUDIT_SEARCH_OK;
    } else if (strcmp(fieldName, "exe") == 0) {
        *output = MOCKED_EXE;
        return AUDIT_SEARCH_OK;
    } else if (strcmp(fieldName, "proctitle") == 0) {
        *output = MOCKED_CMD;
        return AUDIT_SEARCH_OK;
    } else if (strcmp(fieldName, "syscall") == 0) {
        *output = AUDIT_CONTROL_TYPE_CONNECT;
        return AUDIT_SEARCH_OK;
    }
}

static bool isAggregationEnabled = false;
EventAggregatorResult Mocked_EventAggregator_IsAggregationEnabled(EventAggregatorHandle handle, bool* isEnabled) {
    *isEnabled = isAggregationEnabled;

    return EVENT_AGGREGATOR_OK;
}

char* hexNonInet = "01002F72756E2F73797374656D642F6A6F75726E616C2F7374646F7574";
char* hexInet = "02000035C0A832F10000000000000000";
char* hexInet6 = "0A00D97C000000000000000000000000000000000000000100000000";
char* saddrHex = NULL;
AuditSearchResultValues Mocked_AuditSearch_ReadString(AuditSearch* auditSearch, const char* fieldName, const char** output) {
        if (strcmp(fieldName, "saddr") == 0) {
        *output = saddrHex;
        return AUDIT_SEARCH_OK;
    }
    
    return AUDIT_SEARCH_OK;
}

BEGIN_TEST_SUITE(connection_create_collector_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(EventCollectorResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(QueueResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonArrayWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchCriteria, int);
    REGISTER_UMOCK_ALIAS_TYPE(Architecture, int);
    REGISTER_UMOCK_ALIAS_TYPE(EventAggregatorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(EventAggregatorResult, int);

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, Mocked_AuditSearch_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(EventAggregator_IsAggregationEnabled, Mocked_EventAggregator_IsAggregationEnabled);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, Mocked_AuditSearch_ReadString);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(EventAggregator_IsAggregationEnabled, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, NULL);
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
    MOCKED_SOCKET_ADDRESS = MOCKED_INTET_SOCKET_ADDRESS;
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEventsWithInetConnection_AggregationEnabled_ExpectSuccess)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = true;
    MOCKED_SOCKET_ADDRESS = MOCKED_INTET_SOCKET_ADDRESS;
    saddrHex = hexInet;
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_SYSCALL, IGNORED_PTR_ARG, 2, "/var/tmp/connectionCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_ReadString(IGNORED_PTR_ARG, "saddr", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_PROTOCOL_KEY, "tcp")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_DIRECTION_KEY, CONNECTION_CREATION_DIRECTION_OUTBOUND_NAME)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_ADDRESS_KEY, "192.168.50.241")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_PORT_KEY, "53")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "exe", CONNECTION_CREATION_EXECUTABLE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "proctitle", CONNECTION_CREATION_COMMAND_LINE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", CONNECTION_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", CONNECTION_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);

    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, CONNECTION_CREATION_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(EventAggregator_AggregateEvent(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ConnectionCreateEventCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEventsWithInetConnection_AggregationEnabled_FailOnAggregate_ExpectFail)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = true;
    MOCKED_SOCKET_ADDRESS = MOCKED_INTET_SOCKET_ADDRESS;
    saddrHex = hexInet;
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_SYSCALL, IGNORED_PTR_ARG, 2, "/var/tmp/connectionCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_ReadString(IGNORED_PTR_ARG, "saddr", IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_PROTOCOL_KEY, "tcp")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_DIRECTION_KEY, CONNECTION_CREATION_DIRECTION_OUTBOUND_NAME)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_ADDRESS_KEY, "192.168.50.241")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_PORT_KEY, "53")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "exe", CONNECTION_CREATION_EXECUTABLE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "proctitle", CONNECTION_CREATION_COMMAND_LINE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", CONNECTION_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", CONNECTION_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);

    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, CONNECTION_CREATION_PROCESS_ID_KEY, 0));
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(EventAggregator_AggregateEvent(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_AGGREGATOR_EXCEPTION);

    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ConnectionCreateEventCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
}


void TestGetEvents_ExpectSuccess(char* hexInputString, char* ipAddress, char* port) {
    SyncQueue mockedQueue;
    MOCKED_SOCKET_ADDRESS = MOCKED_INTET_SOCKET_ADDRESS;
    
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_SYSCALL, IGNORED_PTR_ARG, 2, "/var/tmp/connectionCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, CONNECTION_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, CONNECTION_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    saddrHex = hexInputString;
    STRICT_EXPECTED_CALL(AuditSearch_ReadString(IGNORED_PTR_ARG, "saddr", IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_PROTOCOL_KEY, "tcp")).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_DIRECTION_KEY, CONNECTION_CREATION_DIRECTION_OUTBOUND_NAME)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_ADDRESS_KEY, ipAddress)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, CONNECTION_CREATION_REMOTE_PORT_KEY, port)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "exe", CONNECTION_CREATION_EXECUTABLE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleInterpretStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "proctitle", CONNECTION_CREATION_COMMAND_LINE_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleIntValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "pid", CONNECTION_CREATION_PROCESS_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(GenericAuditEvent_HandleStringValue(IGNORED_PTR_ARG, IGNORED_PTR_ARG, "uid", CONNECTION_CREATION_USER_ID_KEY, false)).SetReturn(EVENT_COLLECTOR_OK);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(QUEUE_OK);

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ConnectionCreateEventCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEventsWithInetConnection_ExpectSuccess)
{
    isAggregationEnabled = false;
    TestGetEvents_ExpectSuccess(hexInet, "192.168.50.241", "53");
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEventsWithInet6Connection_ExpectSuccess)
{
    TestGetEvents_ExpectSuccess(hexInet6, "0000:0000:0000:0000:0000:0000:0000:0001", "55676");
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEventsWitUnknownConnection_AggregationDisabled_ExpectSuccess)
{
    SyncQueue mockedQueue;
    isAggregationEnabled = false;
    MOCKED_SOCKET_ADDRESS = MOCKED_UNKNOWN_SOCKET_ADDRESS;
    
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_SYSCALL, IGNORED_PTR_ARG, 2, "/var/tmp/connectionCreationCheckpoint")).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, CONNECTION_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, CONNECTION_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);

    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    saddrHex = hexNonInet;
    STRICT_EXPECTED_CALL(AuditSearch_ReadString(IGNORED_PTR_ARG, "saddr", IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(EventAggregator_GetAggregatedEvents(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    EventCollectorResult result = ConnectionCreateEventCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(ConnectionCreateEventCollector_GetEvents_AggregationDisabled_ExpectFailure)
{

    SyncQueue mockedQueue;
    isAggregationEnabled = false;
    umock_c_negative_tests_init();

    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, AUDIT_SEARCH_CRITERIA_SYSCALL, IGNORED_PTR_ARG, 2, "/var/tmp/connectionCreationCheckpoint")).SetFailReturn(!AUDIT_SEARCH_OK);
    
    // This does not have a fail valie since it is important for the flow. Skip this on negative tests
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(EventAggregator_IsAggregationEnabled(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!EVENT_AGGREGATOR_OK);
    STRICT_EXPECTED_CALL(AuditSearch_GetEventTime(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!AUDIT_SEARCH_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadataWithTimes(IGNORED_PTR_ARG, EVENT_TRIGGERED_CATEGORY, CONNECTION_CREATION_NAME, EVENT_TYPE_SECURITY_VALUE, CONNECTION_CREATION_PAYLOAD_SCHEMA_VERSION, IGNORED_PTR_ARG)).SetFailReturn(!EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);

    // if we fail in a single record, we still continue
    saddrHex = hexNonInet;
    STRICT_EXPECTED_CALL(AuditSearch_InterpretString(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_RECORD_HAS_ERRORS);

    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!QUEUE_OK);

    // This does not have a fail valie since it is importatn for the flow. Skip this on negative tests
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);
    STRICT_EXPECTED_CALL(AuditSearch_SetCheckpoint(IGNORED_PTR_ARG)).SetFailReturn(!AUDIT_SEARCH_OK);
    // This does not have a fail valie since it is importatn for the flow. Skip this on negative tests
    STRICT_EXPECTED_CALL(AuditSearch_Deinit(IGNORED_PTR_ARG)); 

    umock_c_negative_tests_snapshot();

    for (int i = 0; i < umock_c_negative_tests_call_count(); i++) {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        if (i == 1 || i == 13 || i == 15) {
            // skip on the non-SetFailReturn calls
            continue;
        }

        EventCollectorResult result = ConnectionCreateEventCollector_GetEvents(&mockedQueue);
        ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    }
    
    umock_c_negative_tests_deinit();

}

TEST_FUNCTION(ConnectionCreateEventCollector_Init_ExpectSuccess)
{
    STRICT_EXPECTED_CALL(AuditControl_Init(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(AuditControl_AddRule(IGNORED_PTR_ARG, IGNORED_PTR_ARG, 2, AUDIT_CONTROL_ON_SUCCESS_FILTER));
    STRICT_EXPECTED_CALL(EventAggregator_Init(IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AuditControl_Deinit(IGNORED_PTR_ARG));

    EventCollectorResult result = ConnectionCreateEventCollector_Init();
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

END_TEST_SUITE(connection_create_collector_ut)
