// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"
#include "consts.h"

#include "umock_c.h"
#include "umocktypes_charptr.h"
#include "umocktypes_bool.h"

#include "azure_c_shared_utility/map.h"
#include "agent_telemetry_counters.h"
#include "schema_utils.h"
#include "twin_configuration.h"
#include "collectors/user_login_collector.h"
#include "collectors/agent_telemetry_collector.h"
#include "collectors/listening_ports_collector.h"
#include "collectors/diagnostic_event_collector.h"
#include "collectors/system_information_collector.h"
#include "collectors/agent_configuration_error_collector.h"
#include "collectors/connection_creation_collector.h"
#include "collectors/firewall_collector.h"
#include "collectors/local_users_collector.h"
#include "collectors/process_creation_collector.h"
#include "collectors/event_aggregator.h"

#define ENABLE_MOCKS
#include "twin_configuration_event_collectors.h"
#include "agent_telemetry_provider.h"
#include "local_config.h"
#include "os_utils/users_iterator.h"
#include "os_utils/process_info_handler.h"
#include "os_utils/listening_ports_iterator.h"
#include "os_utils/os_utils.h"
#include "os_utils/linux/iptables/iptables_iterator.h"
#include "os_utils/linux/iptables/iptables_rules_iterator.h"
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/linux/audit/audit_search.h"
#include "os_utils/linux/audit/audit_search_record.h"
#undef ENABLE_MOCKS

const char AUDIT_CONTROL_ON_SUCCESS_FILTER[] = "dummy1";
const char AUDIT_CONTROL_TYPE_EXECVE[] = "dummy2";
const char AUDIT_CONTROL_TYPE_EXECVEAT[] = "dummy3";
const char AUDIT_CONTROL_TYPE_CONNECT[] = "dummy4";
const char AUDIT_CONTROL_TYPE_ACCEPT[] = "dummy5";

 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

ListeningPortsIteratorResults Mock_ListenintPortsIterator_Init(ListeningPortsIteratorHandle* iterator, const char* type) {
    *iterator = (ListeningPortsIteratorHandle)0x3;
    return LISTENING_PORTS_ITERATOR_OK;
}

const char* MockLocalConfiguration_GetAgentId() {
    return "7aaeef0e-614f-4ff2-97d2-1442186f73fa";
}

const char* MockLocalConfiguration_GetRemoteConfigurationObjectName() {
    return "ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration";
}

BEGIN_TEST_SUITE(schema_validation_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    umock_c_init(on_umock_c_error);

    umocktypes_bool_register_types();
    umocktypes_charptr_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);
    REGISTER_UMOCK_ALIAS_TYPE(int32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(ListeningPortsIteratorResults, int);
    REGISTER_UMOCK_ALIAS_TYPE(ListeningPortsIteratorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(AgentQueueMeter, int);
    REGISTER_UMOCK_ALIAS_TYPE(AgentTelemetryProviderResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchCriteria, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(IptablesResults, int);
    REGISTER_UMOCK_ALIAS_TYPE(IptablesIteratorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(IptablesRulesIteratorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(UsersIteratorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(GroupsIteratorHandle, void*);    
    REGISTER_UMOCK_ALIAS_TYPE(MAP_FILTER_CALLBACK, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(ListenintPortsIterator_Init, Mock_ListenintPortsIterator_Init);
    REGISTER_GLOBAL_MOCK_HOOK(LocalConfiguration_GetAgentId, MockLocalConfiguration_GetAgentId);
    REGISTER_GLOBAL_MOCK_HOOK(LocalConfiguration_GetRemoteConfigurationObjectName, MockLocalConfiguration_GetRemoteConfigurationObjectName);

    ASSERT_ARE_EQUAL(int, TWIN_OK, TwinConfiguration_Init());
}


TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(ListenintPortsIterator_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(LocalConfiguration_GetAgentId, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(LocalConfiguration_GetRemoteConfigurationObjectName, NULL);

    TwinConfiguration_Deinit();

    umock_c_deinit();
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(SchemaValidation_ListeningPorts)
{   
    size_t i = 0;
    for(; i < NUM_OF_PROTOCOLS; i++){
        STRICT_EXPECTED_CALL(ListenintPortsIterator_Init(IGNORED_PTR_ARG, PROTOCOL_TYPES[i]));
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_HAS_NEXT);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_address("1.1.1.1", 7);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalPort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_port("1", 1);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemoteAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_address("2.2.2.2", 7);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemotePort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_port("2", 1);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetPid(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_pid("", 1);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_NO_MORE_DATA);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_Deinit(IGNORED_PTR_ARG));
    }
   
    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, ListeningPortCollector_GetEvents(&queue));

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

TEST_FUNCTION(SchemaValidation_Diagnostic)
{
    DiagnosticEvent* diagnosticEvent = malloc(sizeof(DiagnosticEvent));
    diagnosticEvent->message = malloc(4);
    strcpy(diagnosticEvent->message, "abc");
    diagnosticEvent->processId = 1;
    diagnosticEvent->severity = SEVERITY_ERROR;
    diagnosticEvent->threadId = 2;
    diagnosticEvent->timeLocal = TimeUtils_GetCurrentTime();
    diagnosticEvent->correlationId = malloc(38);
    strcpy(diagnosticEvent->correlationId, "5c6ac315-2875-4380-9495-a4af0264ce24");

    SyncQueue initQueue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&initQueue, false));
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_PushBack(&initQueue, diagnosticEvent, sizeof(*diagnosticEvent)));

    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, DiagnosticEventCollector_Init(&initQueue));

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, DiagnosticEventCollector_GetEvents(&queue));

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    DiagnosticEventCollector_Deinit();

    SyncQueue_Deinit(&queue);
    SyncQueue_Deinit(&initQueue);
}

TEST_FUNCTION(SchemaValidation_Telemetry)
{
    QueueCounter counter;
    counter.collected = 1;
    counter.dropped = 2;

    MessageCounter counterData;
    counterData.failedMessages = 3;
    counterData.sentMessages = 4;
    counterData.smallMessages = 5;

    STRICT_EXPECTED_CALL(AgentTelemetryProvider_GetQueueCounterData(IGNORED_NUM_ARG, IGNORED_PTR_ARG)).SetReturn(TELEMETRY_PROVIDER_OK).CopyOutArgumentBuffer_counterData(&counter, sizeof(counter));
    STRICT_EXPECTED_CALL(AgentTelemetryProvider_GetMessageCounterData(IGNORED_PTR_ARG)).SetReturn(TELEMETRY_PROVIDER_OK).CopyOutArgumentBuffer_counterData(&counterData, sizeof(counterData));

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, AgentTelemetryCollector_GetEvents(&queue));

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

TEST_FUNCTION(SchemaValidation_SystemInformation)
{
    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, SystemInformationCollector_GetEvents(&queue));

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

TEST_FUNCTION(SchemaValidation_ConfigurationError)
{
    ASSERT_ARE_EQUAL(int, TWIN_OK, TwinConfiguration_Update("{\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\":{\"highPriorityMessageFrequency\": {\"value\" :\"PT25S\"},\"lowPriorityMessageFrequency\":{\"value\" : \"PT35S\"},\"maxLocalCacheSizeInBytes\":{\"value\": 10000000},\"maxMessageSizeInBytes\":{\"value\" :100000},\"snapshotFrequency\":{\"value\": \"PT15S\"},\"hubResourceId\":{\"value\" : \"/fake/resource/id\"},\"eventPriorityprocessCreate\":{\"value\" :\"High\"},\"eventPrioritysystemInformation\":{\"value\" :\"High\"},\"eventPrioritylocalUsers\":{\"value\" :\"High\"}}}", false));

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, AgentConfigurationErrorCollector_GetEvents(&queue));

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

AuditSearchResultValues MockAuditSearch_InterpretString(AuditSearch* auditSearch, const char* fieldName, const char** output) 
{
    *output = "inet host:1.2.3.4 serv:5";
    return 0;
}

AuditSearchResultValues MockAuditSearch_ReadString(AuditSearch* auditSearch, const char* fieldName, const char** output)
{
    if(strcmp(fieldName, "addr") == 0)
        *output = "?";
    else if(strcmp(fieldName, "res") == 0)
        *output = "success";
    else if(strcmp(fieldName, "saddr") == 0)
        *output = "02000035C0A832F10000000000000000";
    else
        *output = "something";

    return 0;
}

AuditSearchResultValues MockAuditSearch_ReadInt(AuditSearch* auditSearch, const char* fieldName, int* output) 
{
    *output = 42;
    return 0;
}

EventAggregatorResult MockEventAggregator_IsAggregationEnabled(EventAggregatorHandle aggregator, bool* isEnabled) {
    *isEnabled = false;
    return EVENT_AGGREGATOR_OK;
}

TEST_FUNCTION(SchemaValidation_UserLogin)
{
    AuditSearch search;
    search.checkpointFile = "XYZ";
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK).CopyOutArgumentBuffer_auditSearch(&search, sizeof(search));

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, MockAuditSearch_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, MockAuditSearch_ReadString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadInt, MockAuditSearch_ReadInt);

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, UserLoginCollector_GetEvents(&queue));

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadInt, NULL);

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

TEST_FUNCTION(SchemaValidation_ConnectionCreation)
{
    AuditSearch search;
    search.checkpointFile = "XYZ";
    STRICT_EXPECTED_CALL(AuditSearch_InitMultipleSearchCriteria(IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK).CopyOutArgumentBuffer_auditSearch(&search, sizeof(search));

    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_HAS_MORE_DATA);
    STRICT_EXPECTED_CALL(AuditSearch_GetNext(IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_NO_MORE_DATA);

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, MockAuditSearch_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, MockAuditSearch_ReadString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadInt, MockAuditSearch_ReadInt);

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, ConnectionCreationEventCollector_GetEvents(&queue));

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadInt, NULL);


    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

int IptablesRulesIteratorPosition = 0;
IptablesResults MockIptablesRulesIterator_GetNext(IptablesRulesIteratorHandle iterator) 
{
    int original = IptablesRulesIteratorPosition;
    IptablesRulesIteratorPosition++;

    if(original % 2 == 0)
        return IPTABLES_ITERATOR_HAS_NEXT;
    else
        return IPTABLES_ITERATOR_NO_MORE_ITEMS;
}

int IptablesIteratorPosition = 0;
IptablesResults MockIptablesIterator_GetNext(IptablesIteratorHandle iterator) 
{
    int original = IptablesIteratorPosition;
    IptablesIteratorPosition++;

    if(original % 2 == 0)
        return IPTABLES_ITERATOR_HAS_NEXT;
    else
        return IPTABLES_ITERATOR_NO_MORE_ITEMS;
}

IptablesResults MockIptablesRulesIterator_GetChainName(IptablesRulesIteratorHandle iterator, const char** chainName) 
{
    *chainName = "INPUT";
    return IPTABLES_OK;
}

IptablesResults MockIptablesIterator_GetChainName(IptablesIteratorHandle iterator, const char** chainName) 
{
    *chainName = "INPUT";
    return IPTABLES_OK;
}

IptablesResults MockIptablesIterator_GetPolicyAction(IptablesIteratorHandle iterator, IptablesActionType* actionType)
{
    *actionType = IPTABLES_ACTION_DENY;
    return IPTABLES_OK;
}

TEST_FUNCTION(SchemaValidation_Firewall)
{
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);

    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetNext, MockIptablesIterator_GetNext);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesRulesIterator_GetNext, MockIptablesRulesIterator_GetNext);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesRulesIterator_GetChainName, MockIptablesRulesIterator_GetChainName);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetChainName, MockIptablesIterator_GetChainName);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetPolicyAction, MockIptablesIterator_GetPolicyAction);

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, FirewallCollector_GetEvents(&queue));

    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetNext, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesRulesIterator_GetNext, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesRulesIterator_GetChainName, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetChainName, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(IptablesIterator_GetPolicyAction, NULL);

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

int UsersIteratorPosition = 0;
UserIteratorResults MockUsersIterator_GetNext(UsersIteratorHandle iterator) 
{
    int original = UsersIteratorPosition;
    UsersIteratorPosition++;

    if(original % 2 == 0)
        return USER_ITERATOR_HAS_NEXT;
    else
        return USER_ITERATOR_STOP;
}

UserIteratorResults MockUsersIterator_GetUserId(UsersIteratorHandle iterator, char* outBuffer, int32_t* outBufferSize)
{
    strcpy(outBuffer, "1234");
    return USER_ITERATOR_OK;
}

int GroupsIteratorPosition = 0;
bool MockGroupsIterator_HasNext(GroupsIteratorHandle iterator) 
{
    int original = GroupsIteratorPosition;
    GroupsIteratorPosition++;

    if(original % 2 == 0)
    {
        return true;
    }
    else
        return false;
}

bool MockGroupsIterator_Next(GroupsIteratorHandle iterator) 
{
    return true;
}

const char* MockGroupsIterator_GetName(GroupsIteratorHandle iterator) 
{
    return "myGroup";
}

uint32_t MockGroupsIterator_GetId(GroupsIteratorHandle iterator) 
{
    return 123;
}

uint32_t MockGroupsIterator_GetGroupsCount(GroupsIteratorHandle iterator) 
{
    return 1;
}

TEST_FUNCTION(SchemaValidation_LocalUsers)
{
    REGISTER_GLOBAL_MOCK_HOOK(UsersIterator_GetNext, MockUsersIterator_GetNext);
    REGISTER_GLOBAL_MOCK_HOOK(UsersIterator_GetUserId, MockUsersIterator_GetUserId);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_HasNext, MockGroupsIterator_HasNext);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_Next, MockGroupsIterator_Next);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetName, MockGroupsIterator_GetName);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetId, MockGroupsIterator_GetId);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetGroupsCount, MockGroupsIterator_GetGroupsCount);

    STRICT_EXPECTED_CALL(UsersIterator_GetUsername(IGNORED_PTR_ARG)).SetReturn("myUser");

    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, LocalUsersCollector_GetEvents(&queue));

    REGISTER_GLOBAL_MOCK_HOOK(UsersIterator_GetNext, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(UsersIterator_GetUserId, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_HasNext, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_Next, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetName, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetId, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(GroupsIterator_GetGroupsCount, NULL);

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

int AuditSearchIteratorPosition = 0;
AuditSearchResultValues MockAuditSearch_GetNext(AuditSearch* auditSearch) 
{
    int original = AuditSearchIteratorPosition;
    AuditSearchIteratorPosition++;

    if(original % 2 == 0)
        return AUDIT_SEARCH_HAS_MORE_DATA;
    else
        return AUDIT_SEARCH_NO_MORE_DATA;
}

AuditSearchResultValues MockAuditSearchRecord_ReadInt(AuditSearch* auditSearch, const char* fieldName, int* output) 
{
    *output = 1;
    return AUDIT_SEARCH_OK;
}

AuditSearchResultValues MockAuditSearchRecord_InterpretString(AuditSearch* auditSearch, const char* fieldName, const char** output) 
{
    *output = "value";
    return AUDIT_SEARCH_OK;
}

TEST_FUNCTION(SchemaValidation_ProcessCreation)
{
    uint32_t maxLength = 256;
    STRICT_EXPECTED_CALL(AuditSearchRecord_MaxRecordLength(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(AUDIT_SEARCH_OK).CopyOutArgumentBuffer_length(&maxLength, sizeof(&maxLength));

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_InterpretString, MockAuditSearchRecord_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_ReadInt, MockAuditSearchRecord_ReadInt);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_GetNext, MockAuditSearch_GetNext);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, MockAuditSearch_InterpretString);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, MockAuditSearch_ReadString);
    
    SyncQueue queue;
    ASSERT_ARE_EQUAL(int, QUEUE_OK, SyncQueue_Init(&queue, false));
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, ProcessCreationCollector_GetEvents(&queue));

    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearchRecord_ReadInt, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_GetNext, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_InterpretString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(AuditSearch_ReadString, NULL);

    ASSERT_ARE_EQUAL(int, SCHEMA_VALIDATION_OK, validate_schema(&queue));

    SyncQueue_Deinit(&queue);
}

END_TEST_SUITE(schema_validation_ut)