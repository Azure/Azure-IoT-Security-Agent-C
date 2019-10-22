// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"
#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"

#define ENABLE_MOCKS
#include "os_utils/linux/audit/audit_control.h"
#include "os_utils/process_info_handler.h"
#undef ENABLE_MOCKS

#include <string.h>
#include "test_defs.h"
#include "security_agent.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;

const char AUDIT_CONTROL_ON_SUCCESS_FILTER[] = "success=1";
const char AUDIT_CONTROL_TYPE_EXECVE[] = "execve";
const char AUDIT_CONTROL_TYPE_EXECVEAT[] = "execveat";
const char AUDIT_CONTROL_TYPE_CONNECT[] = "connect";
const char AUDIT_CONTROL_TYPE_ACCEPT[] = "accept";

 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

BEGIN_TEST_SUITE(agent_int)

TEST_SUITE_INITIALIZE(suite_init)
{
     
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);
    umock_c_init(on_umock_c_error);
    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();

    // initialize the sentMessages object
    sentMessages.lock = Lock_Init();
    ASSERT_IS_NOT_NULL(sentMessages.lock);
    sentMessages.index = 0;
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    if (sentMessages.lock != NULL) {
        Lock_Deinit(sentMessages.lock);
    }
    
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
    processCreateMessageCounter = 0;
    listeningPortsMessageCounter = 0;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    for (uint32_t i = 0; i < sentMessages.index; ++i) {
        free(sentMessages.items[i].data);
    }
    sentMessages.index = 0;
}

const char* currentTwinConfiguration;
const char HIGH_PRIORITY_TIMEOUT_CONFIG[] = "{\"desired\" : {\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\": { \"highPriorityMessageFrequency\": { \"value\" : \"PT15S\" }, \"lowPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"maxLocalCacheSizeInBytes\" : { \"value\" : 5000000 }, \"maxMessageSizeInBytes\" : { \"value\" : 2560000 }, \"snapshotFrequency\" : { \"value\" : \"PT5M\" }, \"hubResourceId\" : { \"value\" : \"/fake/resource/id\" }}}}";
const char LOW_PRIORITY_TIMEOUT_CONFIG[] = "{\"desired\" : {\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\": { \"highPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"lowPriorityMessageFrequency\": { \"value\" : \"PT15S\" }, \"maxLocalCacheSizeInBytes\" : { \"value\" : 5000000 }, \"maxMessageSizeInBytes\" : { \"value\" : 2560000 }, \"snapshotFrequency\" : { \"value\" : \"PT5M\" }, \"hubResourceId\" : { \"value\" : \"/fake/resource/id\" }}}}";
const char MAX_MESSAGE_SIZE_EXCEED_CONFIG[] = "{\"desired\" : {\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\": { \"highPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"lowPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"maxLocalCacheSizeInBytes\" : { \"value\" : 5000000 }, \"maxMessageSizeInBytes\" : { \"value\" : 1150 }, \"snapshotFrequency\" : { \"value\" : \"PT5M\" }, \"hubResourceId\" : { \"value\" : \"/fake/resource/id\" }}}}";
const char HIGH_PRIORITY_TIMEOUT_LOW_SNAPSHOT_INTERVAL_CONFIG[] = "{\"desired\" : {\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\": { \"highPriorityMessageFrequency\": { \"value\" : \"PT15S\" }, \"lowPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"maxLocalCacheSizeInBytes\" : { \"value\" : 5000000 }, \"maxMessageSizeInBytes\" : { \"value\" : 2560000 }, \"snapshotFrequency\" : { \"value\" : \"PT2S\" }, \"hubResourceId\" : { \"value\" : \"/fake/resource/id\" }}}}";
const char LOW_PRIORITY_TIMEOUT_MULTIPLE_EVENTS_CONFIG[] = "{\"desired\" : {\"ms_iotn:urn_azureiot_Security_SecurityAgentConfiguration\": { \"highPriorityMessageFrequency\": { \"value\" : \"PT1H\" }, \"lowPriorityMessageFrequency\": { \"value\" : \"PT5S\" }, \"maxLocalCacheSizeInBytes\" : { \"value\" : 5000000 }, \"maxMessageSizeInBytes\" : { \"value\" : 2560000 }, \"snapshotFrequency\" : { \"value\" : \"PT8S\" }, \"hubResourceId\" : { \"value\" : \"/fake/resource/id\" }, \"eventPriorityListeningPorts\" : { \"value\" : \"Low\"}}}}";

    
TEST_FUNCTION(SecurityAgentIntegrationTest_HighPriorityTimeout_ExpectSuccess)
{
    EXPECTED_CALL(ProcessInfoHandler_SwitchRealAndEffectiveUsers()).SetReturn(true);
    SecurityAgent agent;
    currentTwinConfiguration = HIGH_PRIORITY_TIMEOUT_CONFIG;
    bool agentInitiated = SecurityAgent_Init(&agent);
    ASSERT_IS_TRUE(agentInitiated);

    bool success = SecurityAgent_Start(&agent);
    ASSERT_IS_TRUE(success);

    ThreadAPI_Sleep(25 * 1000);
    
    SecurityAgent_Stop(&agent);

    const char expectedResult[] = "{\"AgentVersion\":\"0.0.5\",\"AgentId\":\"7aaeef0e-614f-4ff2-97d2-1442186f73fa\",\"MessageSchemaVersion\":\"1.0\",\"Events\":[{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"710fe408-c468-442e-ae3a-3228827271b5\",\"TimestampLocal\":\"2018-12-25 07:11:27UTC\",\"TimestampUTC\":\"2018-12-25 07:11:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"25324\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"22\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5671\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"52128\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"08c2c0c1-007b-4388-88b3-0809888bc4e7\",\"TimestampLocal\":\"2018-12-25 07:15:57UTC\",\"TimestampUTC\":\"2018-12-25 07:15:57GMT\",\"Payload\":[{\"Executable\":\"\\/usr\\/sbin\\/nscd\",\"CommandLine\":\"worker_nscd 0\",\"UserId\":112,\"ProcessId\":7273,\"ParentProcessId\":1365}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"a639f185-fc1f-45da-8e3b-5565fa6098c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/dash\",\"CommandLine\":\"\\/bin\\/sh -c iptables --version\",\"UserId\":0,\"ProcessId\":7258,\"ParentProcessId\":1923}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"6a7a926b-50dc-4031-923d-aa7a0d5144c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/bash\",\"CommandLine\":\"\\/bin\\/bash -c sudo ausearch -sc connect  input-logs  --checkpoint \\/var\\/tmp\\/OutboundConnEventGeneratorCheckpoint\",\"UserId\":1002,\"ProcessId\":7256,\"ParentProcessId\":29037}]}]}";
    ASSERT_ARE_EQUAL(int, 1, sentMessages.index);
    ASSERT_ARE_EQUAL(char_ptr, expectedResult, sentMessages.items[0].data);

cleanup:
    if (agentInitiated) {
        SecurityAgent_Deinit(&agent);
    }
}

TEST_FUNCTION(SecurityAgentIntegrationTest_LowPriorityTimeout_ExpectSuccess)
{
    EXPECTED_CALL(ProcessInfoHandler_SwitchRealAndEffectiveUsers()).SetReturn(true);
    SecurityAgent agent;
    currentTwinConfiguration = LOW_PRIORITY_TIMEOUT_CONFIG;
    bool agentInitiated = SecurityAgent_Init(&agent);
    ASSERT_IS_TRUE(agentInitiated);

    bool success = SecurityAgent_Start(&agent);
    ASSERT_IS_TRUE(success);

    ThreadAPI_Sleep(25 * 1000);
    
    SecurityAgent_Stop(&agent);

    const char expectedResult[] = "{\"AgentVersion\":\"0.0.5\",\"AgentId\":\"7aaeef0e-614f-4ff2-97d2-1442186f73fa\",\"MessageSchemaVersion\":\"1.0\",\"Events\":[{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"08c2c0c1-007b-4388-88b3-0809888bc4e7\",\"TimestampLocal\":\"2018-12-25 07:15:57UTC\",\"TimestampUTC\":\"2018-12-25 07:15:57GMT\",\"Payload\":[{\"Executable\":\"\\/usr\\/sbin\\/nscd\",\"CommandLine\":\"worker_nscd 0\",\"UserId\":112,\"ProcessId\":7273,\"ParentProcessId\":1365}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"a639f185-fc1f-45da-8e3b-5565fa6098c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/dash\",\"CommandLine\":\"\\/bin\\/sh -c iptables --version\",\"UserId\":0,\"ProcessId\":7258,\"ParentProcessId\":1923}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"6a7a926b-50dc-4031-923d-aa7a0d5144c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/bash\",\"CommandLine\":\"\\/bin\\/bash -c sudo ausearch -sc connect  input-logs  --checkpoint \\/var\\/tmp\\/OutboundConnEventGeneratorCheckpoint\",\"UserId\":1002,\"ProcessId\":7256,\"ParentProcessId\":29037}]},{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"710fe408-c468-442e-ae3a-3228827271b5\",\"TimestampLocal\":\"2018-12-25 07:11:27UTC\",\"TimestampUTC\":\"2018-12-25 07:11:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"25324\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"22\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5671\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"52128\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]}]}";
    ASSERT_ARE_EQUAL(int, 1, sentMessages.index);
    ASSERT_ARE_EQUAL(char_ptr, expectedResult, sentMessages.items[0].data);

cleanup:
    if (agentInitiated) {
        SecurityAgent_Deinit(&agent);
    }
}

TEST_FUNCTION(SecurityAgentIntegrationTest_MaxMessageSize_ExpectSuccess)
{
    EXPECTED_CALL(ProcessInfoHandler_SwitchRealAndEffectiveUsers()).SetReturn(true);
    SecurityAgent agent;
    currentTwinConfiguration = MAX_MESSAGE_SIZE_EXCEED_CONFIG;
    bool agentInitiated = SecurityAgent_Init(&agent);
    ASSERT_IS_TRUE(agentInitiated);

    bool success = SecurityAgent_Start(&agent);
    ASSERT_IS_TRUE(success);

    ThreadAPI_Sleep(10 * 1000);
    
    SecurityAgent_Stop(&agent);

    const char expectedResult[] = "{\"AgentVersion\":\"0.0.5\",\"AgentId\":\"7aaeef0e-614f-4ff2-97d2-1442186f73fa\",\"MessageSchemaVersion\":\"1.0\",\"Events\":[{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"710fe408-c468-442e-ae3a-3228827271b5\",\"TimestampLocal\":\"2018-12-25 07:11:27UTC\",\"TimestampUTC\":\"2018-12-25 07:11:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"25324\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"22\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5671\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"52128\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"08c2c0c1-007b-4388-88b3-0809888bc4e7\",\"TimestampLocal\":\"2018-12-25 07:15:57UTC\",\"TimestampUTC\":\"2018-12-25 07:15:57GMT\",\"Payload\":[{\"Executable\":\"\\/usr\\/sbin\\/nscd\",\"CommandLine\":\"worker_nscd 0\",\"UserId\":112,\"ProcessId\":7273,\"ParentProcessId\":1365}]}]}";
    ASSERT_ARE_EQUAL(int, 1, sentMessages.index);
    ASSERT_ARE_EQUAL(char_ptr, expectedResult, sentMessages.items[0].data);

cleanup:
    if (agentInitiated) {
        SecurityAgent_Deinit(&agent);
    }
}

TEST_FUNCTION(SecurityAgentIntegrationTest_HighPriorityTimeoutLowSnapshotInterval_ExpectSuccess)
{
    EXPECTED_CALL(ProcessInfoHandler_SwitchRealAndEffectiveUsers()).SetReturn(true);
    SecurityAgent agent;
    currentTwinConfiguration = HIGH_PRIORITY_TIMEOUT_LOW_SNAPSHOT_INTERVAL_CONFIG;
    bool agentInitiated = SecurityAgent_Init(&agent);
    ASSERT_IS_TRUE(agentInitiated);

    bool success = SecurityAgent_Start(&agent);
    ASSERT_IS_TRUE(success);

    ThreadAPI_Sleep(25 * 1000);
    
    SecurityAgent_Stop(&agent);

    const char expectedResult[] = "{\"AgentVersion\":\"0.0.5\",\"AgentId\":\"7aaeef0e-614f-4ff2-97d2-1442186f73fa\",\"MessageSchemaVersion\":\"1.0\",\"Events\":[{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"710fe408-c468-442e-ae3a-3228827271b5\",\"TimestampLocal\":\"2018-12-25 07:11:27UTC\",\"TimestampUTC\":\"2018-12-25 07:11:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"25324\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"22\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5671\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"52128\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]},{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"5d7696b9-eb7d-4b78-b129-53cdce75458d\",\"TimestampLocal\":\"2018-12-25 07:12:27UTC\",\"TimestampUTC\":\"2018-12-25 07:12:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"1234\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"80\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5412\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"28361\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"08c2c0c1-007b-4388-88b3-0809888bc4e7\",\"TimestampLocal\":\"2018-12-25 07:15:57UTC\",\"TimestampUTC\":\"2018-12-25 07:15:57GMT\",\"Payload\":[{\"Executable\":\"\\/usr\\/sbin\\/nscd\",\"CommandLine\":\"worker_nscd 0\",\"UserId\":112,\"ProcessId\":7273,\"ParentProcessId\":1365}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"a639f185-fc1f-45da-8e3b-5565fa6098c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/dash\",\"CommandLine\":\"\\/bin\\/sh -c iptables --version\",\"UserId\":0,\"ProcessId\":7258,\"ParentProcessId\":1923}]},{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"6a7a926b-50dc-4031-923d-aa7a0d5144c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/bash\",\"CommandLine\":\"\\/bin\\/bash -c sudo ausearch -sc connect  input-logs  --checkpoint \\/var\\/tmp\\/OutboundConnEventGeneratorCheckpoint\",\"UserId\":1002,\"ProcessId\":7256,\"ParentProcessId\":29037}]}]}";
    ASSERT_ARE_EQUAL(int, 1, sentMessages.index);
    ASSERT_ARE_EQUAL(char_ptr, expectedResult, sentMessages.items[0].data);

cleanup:
    if (agentInitiated) {
        SecurityAgent_Deinit(&agent);
    }
}

TEST_FUNCTION(SecurityAgentIntegrationTest_LowPriorityTimeoutMultipleEvents_ExpectSuccess)
{
    EXPECTED_CALL(ProcessInfoHandler_SwitchRealAndEffectiveUsers()).SetReturn(true);
    SecurityAgent agent;
    currentTwinConfiguration = LOW_PRIORITY_TIMEOUT_MULTIPLE_EVENTS_CONFIG;
    bool agentInitiated = SecurityAgent_Init(&agent);
    ASSERT_IS_TRUE(agentInitiated);

    bool success = SecurityAgent_Start(&agent);
    ASSERT_IS_TRUE(success);

    ThreadAPI_Sleep(30 * 1000);
    
    SecurityAgent_Stop(&agent);

    char combinedMessage[5000] = "";
    char* combinedMessageCopyPtr = combinedMessage;
    
    for (uint32_t i = 0; i < sentMessages.index; ++i) {
        memcpy(combinedMessageCopyPtr, sentMessages.items[i].data, sentMessages.items[i].dataSize);
        combinedMessageCopyPtr += sentMessages.items[i].dataSize;
    }

    const char expectedEvent1[] = "{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"08c2c0c1-007b-4388-88b3-0809888bc4e7\",\"TimestampLocal\":\"2018-12-25 07:15:57UTC\",\"TimestampUTC\":\"2018-12-25 07:15:57GMT\",\"Payload\":[{\"Executable\":\"\\/usr\\/sbin\\/nscd\",\"CommandLine\":\"worker_nscd 0\",\"UserId\":112,\"ProcessId\":7273,\"ParentProcessId\":1365}]}";
    const char expectedEvent2[] = "{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"710fe408-c468-442e-ae3a-3228827271b5\",\"TimestampLocal\":\"2018-12-25 07:11:27UTC\",\"TimestampUTC\":\"2018-12-25 07:11:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"25324\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"22\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5671\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"52128\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]}";
    const char expectedEvent3[] = "{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"a639f185-fc1f-45da-8e3b-5565fa6098c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/dash\",\"CommandLine\":\"\\/bin\\/sh -c iptables --version\",\"UserId\":0,\"ProcessId\":7258,\"ParentProcessId\":1923}]}";
    const char expectedEvent4[] = "{\"Category\":\"Triggered\",\"IsOperational\":false,\"Name\":\"ProcessCreate\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"6a7a926b-50dc-4031-923d-aa7a0d5144c9\",\"TimestampLocal\":\"2018-12-25 07:15:48UTC\",\"TimestampUTC\":\"2018-12-25 07:15:48GMT\",\"Payload\":[{\"Executable\":\"\\/bin\\/bash\",\"CommandLine\":\"\\/bin\\/bash -c sudo ausearch -sc connect  input-logs  --checkpoint \\/var\\/tmp\\/OutboundConnEventGeneratorCheckpoint\",\"UserId\":1002,\"ProcessId\":7256,\"ParentProcessId\":29037}]}]}";
    const char expectedEvent5[] = "{\"Category\":\"Periodic\",\"IsOperational\":false,\"Name\":\"ListeningPorts\",\"PayloadSchemaVersion\":\"1.0\",\"Id\":\"5d7696b9-eb7d-4b78-b129-53cdce75458d\",\"TimestampLocal\":\"2018-12-2507:12:27UTC\",\"TimestampUTC\":\"2018-12-2507:12:27GMT\",\"Payload\":[{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"1234\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"0.0.0.0\",\"LocalPort\":\"80\",\"RemoteAddress\":\"0.0.0.0\",\"RemotePort\":\"*\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"59941\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"5412\"},{\"Protocol\":\"tcp\",\"LocalAddress\":\"10.0.0.4\",\"LocalPort\":\"28361\",\"RemoteAddress\":\"137.117.83.38\",\"RemotePort\":\"8883\"}]}";
    ASSERT_IS_TRUE(sentMessages.index > 1);

    char* eventExists = strstr(combinedMessage, expectedEvent1);
    ASSERT_IS_NOT_NULL(eventExists);
    eventExists = strstr(combinedMessage, expectedEvent2);
    ASSERT_IS_NOT_NULL(eventExists);
    eventExists = strstr(combinedMessage, expectedEvent3);
    ASSERT_IS_NOT_NULL(eventExists);
    eventExists = strstr(combinedMessage, expectedEvent4);
    ASSERT_IS_NOT_NULL(eventExists);

cleanup:
    if (agentInitiated) {
        SecurityAgent_Deinit(&agent);
    }
}

END_TEST_SUITE(agent_int)