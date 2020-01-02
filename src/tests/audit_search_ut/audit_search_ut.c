// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"
#include "umock_c_negative_tests.h"

#define ENABLE_MOCKS
#include "audit_mocks.h"
#include "internal/time_utils.h"
#include "os_utils/file_utils.h"
#include "os_utils/linux/audit/audit_search_utils.h"
#include "os_utils/process_info_handler.h"
#undef ENABLE_MOCKS

#include <errno.h>
#include "os_utils/linux/audit/audit_search.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

static const char* MESSAGE_TYPE = "abc";
static const char* CHECKPOINT_PATH = "xyz";
static time_t MOCKED_SEARCH_TIME;
static time_t TIME_IN_FILE;
static auparse_state_t* mockedAudit;

FileResults Mocked_FileUtils_ReadFile_SetBufferToTime(const char* filename, void* data, uint32_t readCount, bool maxCount) {
    memcpy(data, &TIME_IN_FILE, sizeof(TIME_IN_FILE));
    return FILE_UTILS_OK;
}

void InitAuditSearchFotTests(AuditSearch* search) {
    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search->processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_item(mockedAudit, "type", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false)).SetReturn(FILE_UTILS_FILE_NOT_FOUND);
    STRICT_EXPECTED_CALL(ausearch_set_stop(mockedAudit, AUSEARCH_STOP_EVENT)).SetReturn(0);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(MOCKED_SEARCH_TIME);
    AuditSearchResultValues result = AuditSearch_Init(search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
}

BEGIN_TEST_SUITE(audit_search_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_bool_register_types();
    umocktypes_charptr_register_types();
    REGISTER_UMOCK_ALIAS_TYPE(FileResults, int);
    REGISTER_UMOCK_ALIAS_TYPE(AuditSearchResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(time_t, long);
    REGISTER_UMOCK_ALIAS_TYPE(ausource_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(austop_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(ausearch_rule_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, unsigned int);

    struct tm tmpTime = {0, 0, 13, 14, 2, 118 }; 
    MOCKED_SEARCH_TIME = mktime(&tmpTime);

    struct tm tmpTime2 = {0, 0, 20, 7, 1, 118 }; 
    TIME_IN_FILE = mktime(&tmpTime);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
    mockedAudit = (auparse_state_t*)0x1;
}

TEST_FUNCTION(AuditSearch_InitType_ExpectSuccess)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_item(mockedAudit, "type", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false)).SetReturn(FILE_UTILS_FILE_NOT_FOUND);
    STRICT_EXPECTED_CALL(ausearch_set_stop(mockedAudit, AUSEARCH_STOP_EVENT)).SetReturn(0);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(MOCKED_SEARCH_TIME);

    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(void_ptr, mockedAudit, search.audit);
    ASSERT_ARE_EQUAL(char_ptr, CHECKPOINT_PATH, search.checkpointFile);
    ASSERT_ARE_EQUAL(void_ptr, MOCKED_SEARCH_TIME, search.searchTime);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_InitSysCall_ExpectSuccess)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_interpreted_item(mockedAudit, "syscall", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false)).SetReturn(FILE_UTILS_FILE_NOT_FOUND);
    STRICT_EXPECTED_CALL(ausearch_set_stop(mockedAudit, AUSEARCH_STOP_EVENT)).SetReturn(0);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(MOCKED_SEARCH_TIME);

    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_SYSCALL, MESSAGE_TYPE, CHECKPOINT_PATH);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(void_ptr, mockedAudit, search.audit);
    ASSERT_ARE_EQUAL(char_ptr, CHECKPOINT_PATH, search.checkpointFile);
    ASSERT_ARE_EQUAL(void_ptr, MOCKED_SEARCH_TIME, search.searchTime);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_Init_WithCheckpoint_ExpectSuccess)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_item(mockedAudit, "type", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false));
    STRICT_EXPECTED_CALL(ausearch_add_timestamp_item(mockedAudit, ">", TIME_IN_FILE, 0, AUSEARCH_RULE_AND)).SetReturn(0);
    STRICT_EXPECTED_CALL(ausearch_set_stop(mockedAudit, AUSEARCH_STOP_EVENT)).SetReturn(0);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(MOCKED_SEARCH_TIME);

    REGISTER_GLOBAL_MOCK_HOOK(FileUtils_ReadFile, Mocked_FileUtils_ReadFile_SetBufferToTime);
    
    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);
    
    REGISTER_GLOBAL_MOCK_HOOK(FileUtils_ReadFile, NULL);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(void_ptr, mockedAudit, search.audit);
    ASSERT_ARE_EQUAL(char_ptr, CHECKPOINT_PATH, search.checkpointFile);
    ASSERT_ARE_EQUAL(void_ptr, MOCKED_SEARCH_TIME, search.searchTime);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_Init_ChangeToRootFailed_ExpectFailure)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(false);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(&search.processInfo)).SetReturn(true);

    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_Init_ReadTimeFailed_ExpectFailure)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_item(mockedAudit, "type", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false)).SetReturn(FILE_UTILS_ERROR);
    STRICT_EXPECTED_CALL(auparse_destroy(mockedAudit));
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(&search.processInfo)).SetReturn(true);

    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_IS_NULL(search.audit);
    ASSERT_IS_NULL(search.checkpointFile);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_Init_AuditFunctionFailed_ExpectFailure)
{
    AuditSearch search;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(&search.processInfo)).SetReturn(true);
    STRICT_EXPECTED_CALL(auparse_init(AUSOURCE_LOGS, NULL)).SetReturn(mockedAudit);
    STRICT_EXPECTED_CALL(ausearch_add_item(mockedAudit, "type", "=", MESSAGE_TYPE, AUSEARCH_RULE_CLEAR)).SetReturn(0);
    STRICT_EXPECTED_CALL(FileUtils_ReadFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(time_t), false)).SetReturn(FILE_UTILS_FILE_NOT_FOUND);
    STRICT_EXPECTED_CALL(ausearch_set_stop(mockedAudit, AUSEARCH_STOP_EVENT)).SetReturn(-1);
    STRICT_EXPECTED_CALL(auparse_destroy(mockedAudit));
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(&search.processInfo)).SetReturn(true);

    AuditSearchResultValues result = AuditSearch_Init(&search, AUDIT_SEARCH_CRITERIA_TYPE, MESSAGE_TYPE, CHECKPOINT_PATH);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_IS_NULL(search.audit);
    ASSERT_IS_NULL(search.checkpointFile);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_Deinit_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(auparse_destroy(mockedAudit));
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(&search.processInfo)).SetReturn(true);

    AuditSearch_Deinit(&search);

    ASSERT_IS_NULL(search.audit);
    ASSERT_IS_NULL(search.checkpointFile);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditSearch_GetNext_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(1);

    AuditSearchResultValues result = AuditSearch_GetNext(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_HAS_MORE_DATA, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_LogEventText_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(auparse_get_record_text(mockedAudit)).SetReturn("bobo");
    STRICT_EXPECTED_CALL(auparse_next_record(mockedAudit)).SetReturn(0);

    AuditSearchResultValues result = AuditSearch_LogEventText(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    
    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetNext_NoMatches_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(0);

    AuditSearchResultValues result = AuditSearch_GetNext(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_NO_MORE_DATA, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetNextGetNext_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(auparse_next_event(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(1);

    AuditSearchResultValues result = AuditSearch_GetNext(&search);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_HAS_MORE_DATA, result);

    result = AuditSearch_GetNext(&search);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_HAS_MORE_DATA, result);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetNextGetNext_NoMoreData_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(auparse_next_event(mockedAudit)).SetReturn(0);

    AuditSearchResultValues result = AuditSearch_GetNext(&search);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_HAS_MORE_DATA, result);

    result = AuditSearch_GetNext(&search);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_NO_MORE_DATA, result);

    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetNext_AuditFunctionFailed_ExpectFailure)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(ausearch_next_event(mockedAudit)).SetReturn(-1);

    AuditSearchResultValues result = AuditSearch_GetNext(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_SetCheckpoint_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);
    STRICT_EXPECTED_CALL(FileUtils_WriteToFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(MOCKED_SEARCH_TIME))).SetReturn(FILE_UTILS_OK);

    AuditSearchResultValues result = AuditSearch_SetCheckpoint(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_SetCheckpoint_WriteFailed_ExpectFailure)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);
    STRICT_EXPECTED_CALL(FileUtils_WriteToFile(CHECKPOINT_PATH, IGNORED_PTR_ARG, sizeof(MOCKED_SEARCH_TIME))).SetReturn(!FILE_UTILS_OK);

    AuditSearchResultValues result = AuditSearch_SetCheckpoint(&search);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetEventTime_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    au_event_t expectedTime;
    expectedTime.sec = 5183;
    STRICT_EXPECTED_CALL(auparse_get_timestamp(mockedAudit)).SetReturn(&expectedTime);

    uint32_t eventTime = 0;
    AuditSearchResultValues result = AuditSearch_GetEventTime(&search, &eventTime);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(int, expectedTime.sec, eventTime);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_GetEventTime_AuditFunctionFailed_ExpectFailure)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    STRICT_EXPECTED_CALL(auparse_get_timestamp(mockedAudit)).SetReturn(NULL);

    uint32_t eventTime = 0;
    AuditSearchResultValues result = AuditSearch_GetEventTime(&search, &eventTime);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_ReadInt_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    const char* fieldName = "djdjd";
    int output = 0;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(AuditSearchUtils_ReadInt(&search, fieldName, &output)).SetReturn(AUDIT_SEARCH_OK);

    AuditSearchResultValues result = AuditSearch_ReadInt(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_ReadInt_AuditFunctionFailed_ExpectFailure)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    const char* fieldName = "djdjd";
    int output = 0;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(-1);

    AuditSearchResultValues result = AuditSearch_ReadInt(&search, fieldName, &output);
    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_ReadString_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    const char* fieldName = "djdjd";
    const char* output = 0;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(AuditSearchUtils_ReadString(&search, fieldName, &output)).SetReturn(AUDIT_SEARCH_OK);

    AuditSearchResultValues result = AuditSearch_ReadString(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_ReadString_FieldDoesNotExist_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    const char* fieldName = "djdjd";
    const char* output = 0;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(AuditSearchUtils_ReadString(&search, fieldName, &output)).SetReturn(AUDIT_SEARCH_FIELD_DOES_NOT_EXIST);

    AuditSearchResultValues result = AuditSearch_ReadString(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_FIELD_DOES_NOT_EXIST, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_InterpretString_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);

    const char* fieldName = "djdjd";
    const char* output = NULL;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);    
    STRICT_EXPECTED_CALL(AuditSearchUtils_InterpretString(&search, fieldName, &output)).SetReturn(AUDIT_SEARCH_OK);

    AuditSearchResultValues result = AuditSearch_InterpretString(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_InterpretString_NoData_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);
    const char* fieldName = "djdjd";
    const char* output = NULL;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(0);

    AuditSearchResultValues result = AuditSearch_InterpretString(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_NO_DATA, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

TEST_FUNCTION(AuditSearch_InterpretString_Failed_ExpectSuccess)
{
    AuditSearch search;
    InitAuditSearchFotTests(&search);
    const char* fieldName = "djdjd";
    const char* output = NULL;

    STRICT_EXPECTED_CALL(auparse_first_record(mockedAudit)).SetReturn(1);
    STRICT_EXPECTED_CALL(AuditSearchUtils_InterpretString(&search, fieldName, &output)).SetReturn(AUDIT_SEARCH_EXCEPTION);

    AuditSearchResultValues result = AuditSearch_InterpretString(&search, fieldName, &output);

    ASSERT_ARE_EQUAL(int, AUDIT_SEARCH_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    AuditSearch_Deinit(&search);
}

END_TEST_SUITE(audit_search_ut)
