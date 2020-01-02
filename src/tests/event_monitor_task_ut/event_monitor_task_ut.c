// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdint.h>

#include "testrunnerswitcher.h"
#include "macro_utils.h"
#include "umock_c.h"
#include "umocktypes_charptr.h"

#define ENABLE_MOCKS
#include "collectors/agent_configuration_error_collector.h"
#include "collectors/agent_telemetry_collector.h"
#include "collectors/connection_create_collector.h"
#include "collectors/diagnostic_event_collector.h"
#include "collectors/firewall_collector.h"
#include "collectors/linux/baseline_collector.h"
#include "collectors/listening_ports_collector.h"
#include "collectors/local_users_collector.h"
#include "collectors/process_creation_collector.h"
#include "collectors/process_creation_collector.h"
#include "collectors/system_information_collector.h"
#include "collectors/user_login_collector.h"
#include "internal/time_utils.h"
#include "local_config.h"
#include "synchronized_queue.h"
#include "twin_configuration_event_collectors.h"
#include "twin_configuration.h"
#undef ENABLE_MOCKS

#include "tasks/event_monitor_task.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code) {
    char temp_str[256];
    snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

const uint32_t mockedSnapshotFrequiency = 10;

TwinConfigurationResult Mocked_TwinConfiguration_GetSnapshotFrequency(uint32_t* snapshotFrequency) {
    *snapshotFrequency = mockedSnapshotFrequiency;
    return TWIN_OK;
}

TwinConfigurationResult Mocked_TwinConfigurationEventCollectors_GetPriority(TwinConfigurationEventType eventType, TwinConfigurationEventPriority* priority){
    *priority = eventType == EVENT_TYPE_OPERATIONAL_EVENT ? EVENT_PRIORITY_OPERATIONAL : EVENT_PRIORITY_HIGH;
    return TWIN_OK;
}

int Mocked_SyncQueue_PushBack(SyncQueue* syncQueue, void* data, uint32_t dataSize) {
    if (data != NULL) {
        free(data);
    }

    return QUEUE_OK;
}

BEGIN_TEST_SUITE(event_monitor_task_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);
    umocktypes_charptr_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(TwinConfigurationResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);
    REGISTER_UMOCK_ALIAS_TYPE(int32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(time_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(TwinConfigurationEventType, int);

    REGISTER_GLOBAL_MOCK_HOOK(TwinConfiguration_GetSnapshotFrequency, Mocked_TwinConfiguration_GetSnapshotFrequency);
    REGISTER_GLOBAL_MOCK_HOOK(TwinConfigurationEventCollectors_GetPriority, Mocked_TwinConfigurationEventCollectors_GetPriority);
    REGISTER_GLOBAL_MOCK_HOOK(SyncQueue_PushBack, Mocked_SyncQueue_PushBack);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(TwinConfiguration_GetSnapshotFrequency, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(TwinConfigurationEventCollectors_GetPriority, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(SyncQueue_PushBack, NULL);

    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(EventMonitorTask_Init_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    ASSERT_ARE_EQUAL(void_ptr, &operationalEventsQueue, task.operationalEventsQueue);
    ASSERT_ARE_EQUAL(void_ptr, &highPriorityQueue, task.highPriorityQueue);
    ASSERT_ARE_EQUAL(void_ptr, &lowPriorityQueue, task.lowPriorityQueue);
    ASSERT_ARE_EQUAL(uint32_t, 0, task.lastPeriodicExecution);
    ASSERT_ARE_EQUAL(uint32_t, 0, task.lastTriggeredExecution);

    EventMonitorTask_Deinit(&task);
}

TEST_FUNCTION(EventMonitorTask_Deinit_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    EventMonitorTask_Deinit(&task);
    
    ASSERT_IS_NULL(task.highPriorityQueue);
    ASSERT_IS_NULL(task.lowPriorityQueue);
}

TEST_FUNCTION(EventMonitorTask_ExecuteGetSnapshotFrequencyFailed_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    STRICT_EXPECTED_CALL(TwinConfiguration_GetSnapshotFrequency(IGNORED_PTR_ARG)).SetReturn(TWIN_EXCEPTION);
    
    EventMonitorTask_Execute(&task);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    EventMonitorTask_Deinit(&task);
}

TEST_FUNCTION(EventMonitorTask_ExecuteTimeoutDidNotPass_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    STRICT_EXPECTED_CALL(TwinConfiguration_GetSnapshotFrequency(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime());
    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(0);

    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(0);
    STRICT_EXPECTED_CALL(LocalConfiguration_GetTriggeredEventInterval()).SetReturn(100);

    EventMonitorTask_Execute(&task);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    EventMonitorTask_Deinit(&task);
}

TEST_FUNCTION(EventMonitorTask_ExecuteSnapshotTimeout_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;
    uint32_t triggeredInterval = 20;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    // check periodic events interval
    STRICT_EXPECTED_CALL(TwinConfiguration_GetSnapshotFrequency(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime());
    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(mockedSnapshotFrequiency * 10);

    // all periodic collectors
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_OPERATIONAL_EVENT, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AgentTelemetryCollector_GetEvents(&operationalEventsQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_LOCAL_USERS, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(LocalUsersCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_SYSTEM_INFORMATION, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(SystemInformationCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_LISTENING_PORTS, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ListeningPortCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_FIREWALL_CONFIGURATION, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(FirewallCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_BASELINE, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(BaselineCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_DIAGNOSTIC, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(DiagnosticEventCollector_GetEvents(&highPriorityQueue));

    // check triggered events interval
    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(triggeredInterval / 2);
    STRICT_EXPECTED_CALL(LocalConfiguration_GetTriggeredEventInterval()).SetReturn(triggeredInterval);

    EventMonitorTask_Execute(&task);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    EventMonitorTask_Deinit(&task);
}

TEST_FUNCTION(EventMonitorTask_ExecuteTriggeredTimeout_ExpectSuccess)
{
    EventMonitorTask task;
    SyncQueue operationalEventsQueue;
    SyncQueue highPriorityQueue;
    SyncQueue lowPriorityQueue;
    uint32_t triggeredInterval = 20;

    // init collectors
    STRICT_EXPECTED_CALL(ProcessCreationCollector_Init());
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_Init());
    bool result = EventMonitorTask_Init(&task, &highPriorityQueue, &lowPriorityQueue, &operationalEventsQueue);
    ASSERT_IS_TRUE(result);

    // check periodic events interval
    STRICT_EXPECTED_CALL(TwinConfiguration_GetSnapshotFrequency(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime());
    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(0);

    // check triggered events interval
    STRICT_EXPECTED_CALL(TimeUtils_GetTimeDiff(IGNORED_NUM_ARG, IGNORED_NUM_ARG)).SetReturn(triggeredInterval * 10);
    STRICT_EXPECTED_CALL(LocalConfiguration_GetTriggeredEventInterval()).SetReturn(triggeredInterval);

    // all collectors
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_OPERATIONAL_EVENT, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(AgentConfigurationErrorCollector_GetEvents(&operationalEventsQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_PROCESS_CREATE, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ProcessCreationCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_USER_LOGIN, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(UserLoginCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_CONNECTION_CREATE, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(ConnectionCreateEventCollector_GetEvents(&highPriorityQueue));

    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPriority(EVENT_TYPE_DIAGNOSTIC, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(DiagnosticEventCollector_GetEvents(&highPriorityQueue));

    EventMonitorTask_Execute(&task);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    EventMonitorTask_Deinit(&task);
}

END_TEST_SUITE(event_monitor_task_ut)
