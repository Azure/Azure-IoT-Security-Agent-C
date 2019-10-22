// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "consts.h"
#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"

#define ENABLE_MOCKS
#include "utils.h" 
#include "os_mock.h"
#include "azure_c_shared_utility/map.h"
#undef ENABLE_MOCKS

#include "os_utils/listening_ports_iterator.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

static char MOCKED_TCP_LINE[]  = "   0: 0101007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 15364 1 0000000000000000 100 0 0 10 0 \n";
static char MOCKED_TCP_LINE_CONNECTION_CLOSE[]  = "   0: 0101007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 15364 1 0000000000000000 100 0 0 10 0 \n";
static char* FGETS_RETURN_STRING = NULL;

char* Mocked_fgets(char* s, int size, FILE* stream) {
    memcpy(s, FGETS_RETURN_STRING, strlen(FGETS_RETURN_STRING));
    return s;
}

bool Mocked_Utils_IntegerToString(int input, char* output, int32_t* outputSize) {
    ASSERT_ARE_EQUAL(int, 53, input);
    memcpy(output, "53", 2);
    *outputSize = 2;
    return true;
}

bool Mocked_Utils_CopyString(const char* src, uint32_t srcLength, char* dest, uint32_t destLength) {
    memcpy(dest, src, srcLength);
    return true;
}


BEGIN_TEST_SUITE(listening_ports_iterator_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
    umocktypes_bool_register_types();

    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(ListeningPortsIteratorResults, int);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_FILTER_CALLBACK, void*);
    REGISTER_UMOCK_ALIAS_TYPE(MAP_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(fgets, Mocked_fgets);
    REGISTER_GLOBAL_MOCK_HOOK(Utils_IntegerToString, Mocked_Utils_IntegerToString);
    REGISTER_GLOBAL_MOCK_HOOK(Utils_CopyString, Mocked_Utils_CopyString);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(Utils_CopyString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(Utils_IntegerToString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(fgets, NULL);
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
    FGETS_RETURN_STRING = MOCKED_TCP_LINE;
}

TEST_FUNCTION(ListenintPortsIterator_Init_ExpectSuccess)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}

TEST_FUNCTION(ListenintPortsIterator_Init_Udp_ExpectSuccess)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/udp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, UDP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}

TEST_FUNCTION(ListenintPortsIterator_Init_OpenFailed_ExpectSuccess)
{
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(NULL);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(ListenintPortsIterator_GetNext_ExpectSuccess)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);

    STRICT_EXPECTED_CALL(feof(&mockedFile)).SetReturn(0);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile));

    result = ListenintPortsIterator_GetNext(iterator);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_HAS_NEXT, result);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}

TEST_FUNCTION(ListenintPortsIterator_GetNext_EndOfFile_ExpectSuccess)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);

    STRICT_EXPECTED_CALL(feof(&mockedFile)).SetReturn(1);

    result = ListenintPortsIterator_GetNext(iterator);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_NO_MORE_DATA, result);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}

TEST_FUNCTION(ListenintPortsIterator_GetNext_FgetsFailed_ExpectFailure)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);

    STRICT_EXPECTED_CALL(feof(&mockedFile)).SetReturn(0);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(feof(&mockedFile)).SetReturn(0);

    result = ListenintPortsIterator_GetNext(iterator);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_EXCEPTION, result);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}


TEST_FUNCTION(ListenintPortsIterator_GetNext_GetValues_ExpectSuccess)
{
    FILE mockedFile;
    char* mockedBuffer = NULL;
    STRICT_EXPECTED_CALL(fopen("/proc/net/tcp", "r")).SetReturn(&mockedFile);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile)).SetReturn(mockedBuffer);
    STRICT_EXPECTED_CALL(ferror(IGNORED_PTR_ARG)).SetReturn(0);

    ListeningPortsIteratorHandle iterator;
    ListeningPortsIteratorResults result = ListenintPortsIterator_Init(&iterator, TCP_PROTOCOL);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);

    STRICT_EXPECTED_CALL(feof(&mockedFile)).SetReturn(0);
    STRICT_EXPECTED_CALL(fgets(IGNORED_PTR_ARG, IGNORED_NUM_ARG, &mockedFile));

    result = ListenintPortsIterator_GetNext(iterator);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_HAS_NEXT, result);

    char value[128];
    result = ListenintPortsIterator_GetLocalAddress(iterator, value, sizeof(value));
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "127.0.1.1", value);

    memset(value, 0, sizeof(value));
    STRICT_EXPECTED_CALL(Utils_IntegerToString(53, IGNORED_PTR_ARG, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(Utils_CopyString("53", 2,  IGNORED_PTR_ARG, IGNORED_NUM_ARG));
    result = ListenintPortsIterator_GetLocalPort(iterator, value, sizeof(value));
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "53", value);
    
    memset(value, 0, sizeof(value));
    result = ListenintPortsIterator_GetRemoteAddress(iterator, value, sizeof(value));
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "0.0.0.0", value);
    
    memset(value, 0, sizeof(value));
    STRICT_EXPECTED_CALL(Utils_CopyString("*", 1,  IGNORED_PTR_ARG, IGNORED_NUM_ARG));
    result = ListenintPortsIterator_GetRemotePort(iterator, value, sizeof(value));
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "*", value);
    

    memset(value, 0, sizeof(value));
    STRICT_EXPECTED_CALL(Map_GetValueFromKey(IGNORED_PTR_ARG, IGNORED_PTR_ARG)).SetReturn("2000");
    STRICT_EXPECTED_CALL(Utils_CopyString("2000", 4,  IGNORED_PTR_ARG, IGNORED_NUM_ARG));
    result = ListenintPortsIterator_GetPid(iterator, value, sizeof(value), IGNORED_NUM_ARG);
    ASSERT_ARE_EQUAL(int, LISTENING_PORTS_ITERATOR_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, "2000", value);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ListenintPortsIterator_Deinit(iterator);
}

END_TEST_SUITE(listening_ports_iterator_ut)
