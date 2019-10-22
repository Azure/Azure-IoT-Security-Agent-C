// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <dirent.h>
#include <stdio.h>
#include "azure_c_shared_utility/map.h"
#include "utils.h"
#include "testrunnerswitcher.h"
#include "consts.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"
#include "umock_c_negative_tests.h"

#define ENABLE_MOCKS
#include "collectors/generic_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "os_utils/listening_ports_iterator.h"
#include "synchronized_queue.h"
#include "os_mock.h"
#undef ENABLE_MOCKS

#include "collectors/listening_ports_collector.h"
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

static char MOCKED_PROC_LINE[]  = "lrwx------ 1 root root 64 Sep 19 07:22 406 -> 'socket:[13491]' \n";
static char* READDIR_RETURN_STRING = NULL;
static char* FGETS_RETURN_STRING = NULL;

JsonWriterResult Mocked_JsonObjectWriter_Init(JsonObjectWriterHandle* writer) {
    *writer = (JsonObjectWriterHandle)0x1;
    return JSON_WRITER_OK;
}

JsonWriterResult Mocked_JsonArrayWriter_Init(JsonArrayWriterHandle* writer) {
    *writer = (JsonArrayWriterHandle)0x2;
    return JSON_WRITER_OK;
}

ListeningPortsIteratorResults Mock_ListenintPortsIterator_Init(ListeningPortsIteratorHandle* iterator, const char* type) {
    *iterator = (ListeningPortsIteratorHandle)0x3;
    return LISTENING_PORTS_ITERATOR_OK;
}

char* Mocked_fgets(char* s, int size, FILE* stream) {
    memcpy(s, FGETS_RETURN_STRING, strlen(FGETS_RETURN_STRING));
    return s;
}

BEGIN_TEST_SUITE(listening_ports_collector_ut)

TEST_SUITE_INITIALIZE(suite_init)
{

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(QueueResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(JsonArrayWriterHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ListeningPortsIteratorHandle, void*);
    REGISTER_UMOCK_ALIAS_TYPE(EventCollectorResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(ListeningPortsIteratorResults, int);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_FILTER_CALLBACK, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, Mocked_JsonObjectWriter_Init);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayWriter_Init, Mocked_JsonArrayWriter_Init);
    REGISTER_GLOBAL_MOCK_HOOK(ListenintPortsIterator_Init, Mock_ListenintPortsIterator_Init);
    REGISTER_GLOBAL_MOCK_HOOK(fgets, Mocked_fgets);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonArrayWriter_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(ListenintPortsIterator_Init, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(fgets, NULL);

    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);

}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(ListeningPortCollector_GetEvents_ExpectSuccess)
{
    SyncQueue mockedQueue;
    DIR* mockedDir = (DIR*) 0x4;
    FILE* mockedFile = (FILE*) 0x5;
    const char* command = "ls -l /proc/100/fd";
    const uint32_t mockedSize = 2;
    READDIR_RETURN_STRING = "100";
    struct dirent entry = { 0 };
    memcpy(entry.d_name, READDIR_RETURN_STRING, strlen(READDIR_RETURN_STRING));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, LISTENING_PORTS_NAME, EVENT_TYPE_SECURITY_VALUE, LISTENING_PORTS_PAYLOAD_SCHEMA_VERSION)).SetReturn(EVENT_COLLECTOR_OK);

    STRICT_EXPECTED_CALL(opendir("/proc/")).SetReturn(mockedDir);
    STRICT_EXPECTED_CALL(readdir(mockedDir)).SetReturn(&entry);
    FGETS_RETURN_STRING = MOCKED_PROC_LINE;
    STRICT_EXPECTED_CALL(popen(command, "r")).SetReturn(mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, mockedFile));
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, mockedFile)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(pclose(mockedFile));
    STRICT_EXPECTED_CALL(readdir(mockedDir)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(closedir(mockedDir));


    // ports
    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG));
    size_t i;
    for(i=0; i < NUM_OF_PROTOCOLS; i++){
        STRICT_EXPECTED_CALL(ListenintPortsIterator_Init(IGNORED_PTR_ARG, PROTOCOL_TYPES[i]));
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_HAS_NEXT);

        // add port
        STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_PROTOCOL_KEY, PROTOCOL_TYPES[i])).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_LOCAL_ADDRESS_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalPort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_LOCAL_PORT_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemoteAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_REMOTE_ADDRESS_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemotePort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_REMOTE_PORT_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        //add pid
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetPid(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG, IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_OK).CopyOutArgumentBuffer_pid(READDIR_RETURN_STRING, strlen(READDIR_RETURN_STRING));
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_PID_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_GetSize(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK).CopyOutArgumentBuffer_size(&mockedSize, sizeof(mockedSize));
        STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG, EXTRA_DETAILS_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        
        STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
        STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
        STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

        // end
        STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_NO_MORE_DATA);
        STRICT_EXPECTED_CALL(ListenintPortsIterator_Deinit(IGNORED_PTR_ARG));
    }

    
    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(EVENT_COLLECTOR_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(QUEUE_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

    EventCollectorResult result = ListeningPortCollector_GetEvents(&mockedQueue);
    ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(ProcessCreationCollector_GetEvents_ExpectFailure)
{

    SyncQueue mockedQueue;
    umock_c_negative_tests_init();

    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(GenericEvent_AddMetadata(IGNORED_PTR_ARG, EVENT_PERIODIC_CATEGORY, LISTENING_PORTS_NAME, EVENT_TYPE_SECURITY_VALUE, LISTENING_PORTS_PAYLOAD_SCHEMA_VERSION)).SetFailReturn(!EVENT_COLLECTOR_OK);

    // ports
    STRICT_EXPECTED_CALL(JsonArrayWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(ListenintPortsIterator_Init(IGNORED_PTR_ARG, TCP_PROTOCOL)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_HAS_NEXT);

    // adds port
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_PROTOCOL_KEY, "tcp")).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_LOCAL_ADDRESS_KEY, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetLocalPort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_LOCAL_PORT_KEY, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemoteAddress(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_REMOTE_ADDRESS_KEY, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetRemotePort(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LISTENING_PORTS_REMOTE_PORT_KEY, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonArrayWriter_AddObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

    // end
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_NO_MORE_DATA);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(ListenintPortsIterator_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(ListenintPortsIterator_Init(IGNORED_PTR_ARG, UDP_PROTOCOL)).SetFailReturn(!LISTENING_PORTS_ITERATOR_OK);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(ListenintPortsIterator_GetNext(IGNORED_PTR_ARG)).SetReturn(LISTENING_PORTS_ITERATOR_HAS_NEXT);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(ListenintPortsIterator_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(GenericEvent_AddPayload(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!EVENT_COLLECTOR_OK);
    // should be ignored by negative tests
    STRICT_EXPECTED_CALL(JsonArrayWriter_Deinit(IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetFailReturn(!JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(SyncQueue_PushBack(&mockedQueue, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(!QUEUE_OK);

    umock_c_negative_tests_snapshot();

    for (int i = 0; i < umock_c_negative_tests_call_count(); i++) {
        if (i == 4 || i == 17 || i == 18 || i == 19 || i == 22 || i == 24) {
            // skip non failed expected calls
            continue;
        }

        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        EventCollectorResult result = ListeningPortCollector_GetEvents(&mockedQueue);
        ASSERT_ARE_EQUAL(int, EVENT_COLLECTOR_EXCEPTION, result);
    }

    umock_c_negative_tests_deinit();

}

END_TEST_SUITE(listening_ports_collector_ut)
