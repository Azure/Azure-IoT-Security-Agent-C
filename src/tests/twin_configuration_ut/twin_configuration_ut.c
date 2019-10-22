// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umock_c_negative_tests.h"
#include "umocktypes_charptr.h"
#include "umocktypes_stdint.h"
#include "umocktypes_bool.h"
#include "umockalloc.h"

#define ENABLE_MOCKS
#include "azure_c_shared_utility/lock.h"
#include "internal/time_utils.h"
#include "json/json_object_reader.h"
#include "json/json_object_writer.h"
#include "local_config.h"
#include "twin_configuration_event_collectors.h"
#include "twin_configuration_utils.h"
#include "logger.h"
#undef ENABLE_MOCKS

static const LOCK_HANDLE TEST_LOCK_HANDLE = (LOCK_HANDLE)0x4443;

//Control Parameters
static char* DUMMY_JSON = "{\"json\":\"dummy\"}";
static const char* DUMMY_STRING = "dummy";
static int dummyTime = 10000;

#include "twin_configuration.h"
#include "consts.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

static JsonObjectReaderHandle mockedReader = (JsonObjectReaderHandle)0x1;
JsonReaderResult Mocked_JsonObjectReader_InitFromString(JsonObjectReaderHandle* handle, const char* data) {
    *handle = mockedReader;
    return JSON_READER_OK;
}

JsonReaderResult Mocked_JsonObjectReader_ReadObject(JsonObjectReaderHandle handle, const char* key, JsonObjectReaderHandle* output) {    
    *output = (JsonObjectReaderHandle)0x2;
    return JSON_READER_OK;
}

JsonReaderResult Mocked_JsonObjectReader_ReadString(JsonObjectReaderHandle handle, const char* key, char** output) {
    *output = (char*)DUMMY_STRING;
    return JSON_READER_OK;
}

JsonWriterResult Mocked_JsonObjectWriter_Serialize(JsonObjectWriterHandle handle, char** twin, uint32_t* size) {
    *size = 10;
    *twin = "123456789";
    return JSON_WRITER_OK;
}

JsonWriterResult Mocked_JsonObjectWriter_Init(JsonObjectWriterHandle* handle) {
    *handle = (JsonObjectWriterHandle)0x2;
    return JSON_WRITER_OK;
}

/**
 * @brief validates that all twin configuration fields contain the default vaules.
 */
static void ValidateDefaultTwinConfigurationParameters() {
    int result;
    unsigned int num;
    bool boolean;
    char* str;

    result = TwinConfiguration_GetMaxLocalCacheSize(&num);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_MAX_LOCAL_CACHE_SIZE, num);

    result = TwinConfiguration_GetMaxMessageSize(&num);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_MAX_MESSAGE_SIZE, num);

    result = TwinConfiguration_GetLowPriorityMessageFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_LOW_PRIORITY_MESSAGE_FREQUENCY, num);

    result = TwinConfiguration_GetHighPriorityMessageFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_HIGH_PRIORITY_MESSAGE_FREQUENCY, num);

    result = TwinConfiguration_GetSnapshotFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_SNAPSHOT_FREQUENCY, num);

    result = TwinConfiguration_GetBaselineCustomChecksEnabled(&boolean);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, DEFAULT_BASELINE_CUSTOM_CHECKS_ENABLED, boolean);

    result = TwinConfiguration_GetBaselineCustomChecksFilePath(&str);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH, str);

    result = TwinConfiguration_GetBaselineCustomChecksFileHash(&str);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH, str);
}

/**
 * @brief Validates the regular update flows, injection of several errors is supported.
 * 
 * @param   isComplete          whether the update is complete or partial.
 * @param   injectUnlockError   injecting a lock error on Unlock.
 *
 */
static void ValidateTwinConfigurationUpdate(bool isComplete, bool injectUnlockError) {
    const uint32_t mockMaxLocalCacheSize = 11;
    const uint32_t mockMaxMessageSize = 13;
    const uint32_t mockHighPriorityMessageFrequency = 15;
    const uint32_t mockLowPriorityMessageFrequency = 17;
    const uint32_t mockSnapshotFrequency = 19;
    const bool mockBaselineCustomChecksEnabled = true;
    const char* mockBaselineCustomChecksFilePath = "/file/path";
    const char* mockBaselineCustomChecksFileHash = "#filehash!";

    TwinConfigurationResult result, expectedResult = TWIN_OK;


    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, DUMMY_STRING));

    if (isComplete) {
        STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, "desired"));
    }

    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockMaxLocalCacheSize, sizeof(mockMaxLocalCacheSize));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_MESSAGE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockMaxMessageSize, sizeof(mockMaxMessageSize));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockHighPriorityMessageFrequency, sizeof(mockHighPriorityMessageFrequency));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockLowPriorityMessageFrequency, sizeof(mockLowPriorityMessageFrequency));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, SNAPSHOT_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockSnapshotFrequency, sizeof(mockSnapshotFrequency));

    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationBoolValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockBaselineCustomChecksEnabled, sizeof(mockBaselineCustomChecksEnabled));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockBaselineCustomChecksFilePath, sizeof(mockBaselineCustomChecksFilePath));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_OK).CopyOutArgumentBuffer_value(&mockBaselineCustomChecksFileHash, sizeof(mockBaselineCustomChecksFileHash));

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Update(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(dummyTime);
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(mockedReader));


    if (injectUnlockError) {
        expectedResult = TWIN_LOCK_EXCEPTION;
        STRICT_EXPECTED_CALL(Unlock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR);
    }
    else {
        STRICT_EXPECTED_CALL(Unlock(IGNORED_PTR_ARG));;
    }

    //act
    result = TwinConfiguration_Update(DUMMY_STRING, isComplete);

    //assert
    ASSERT_ARE_EQUAL(int, expectedResult, result);

    uint32_t maxLocalCacheSize;
    result = TwinConfiguration_GetMaxLocalCacheSize(&maxLocalCacheSize);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockMaxLocalCacheSize, maxLocalCacheSize);

    uint32_t maxMessageSize;
    result = TwinConfiguration_GetMaxMessageSize(&maxMessageSize);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockMaxMessageSize, maxMessageSize);

    uint32_t highPriorityMessageFrequency;
    result = TwinConfiguration_GetHighPriorityMessageFrequency(&highPriorityMessageFrequency);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockHighPriorityMessageFrequency, highPriorityMessageFrequency);

    uint32_t lowPriorityMessageFrequency;
    result = TwinConfiguration_GetLowPriorityMessageFrequency(&lowPriorityMessageFrequency);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockLowPriorityMessageFrequency, lowPriorityMessageFrequency);

    uint32_t snapshotFrequency;
    result = TwinConfiguration_GetSnapshotFrequency(&snapshotFrequency);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockSnapshotFrequency, snapshotFrequency);

    bool baseLineCustomChecksEnabled;
    result = TwinConfiguration_GetBaselineCustomChecksEnabled(&baseLineCustomChecksEnabled);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, mockBaselineCustomChecksEnabled, baseLineCustomChecksEnabled);

    char* baseLineCustomChecksFilePath;
    result = TwinConfiguration_GetBaselineCustomChecksFilePath(&baseLineCustomChecksFilePath);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, mockBaselineCustomChecksFilePath, baseLineCustomChecksFilePath);

    char* baseLineCustomChecksFileHash;
    result = TwinConfiguration_GetBaselineCustomChecksFileHash(&baseLineCustomChecksFileHash);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, mockBaselineCustomChecksFileHash, baseLineCustomChecksFileHash);
}

BEGIN_TEST_SUITE(twin_configuration_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);
    (void)umocktypes_bool_register_types();
    (void)umocktypes_charptr_register_types();
    
    REGISTER_UMOCK_ALIAS_TYPE(LOCK_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LOCK_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectReaderHandle, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonObjectWriterHandle, int);
    REGISTER_UMOCK_ALIAS_TYPE(TwinConfigurationResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(TwinConfigurationStatus, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonReaderResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(JsonWriterResult, int);
    REGISTER_UMOCK_ALIAS_TYPE(time_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(uint32_t, int);

    // Lock
    REGISTER_GLOBAL_MOCK_RETURN(Lock_Init, TEST_LOCK_HANDLE);
    REGISTER_GLOBAL_MOCK_RETURN(Lock_Deinit, LOCK_OK);
    REGISTER_GLOBAL_MOCK_RETURN(Lock, LOCK_OK);
    REGISTER_GLOBAL_MOCK_RETURN(Unlock, LOCK_OK);

    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_InitFromString, Mocked_JsonObjectReader_InitFromString);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadString, Mocked_JsonObjectReader_ReadString);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadObject, Mocked_JsonObjectReader_ReadObject);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Serialize, Mocked_JsonObjectWriter_Serialize);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, Mocked_JsonObjectWriter_Init);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadObject, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_InitFromString, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectReader_ReadString , NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Serialize, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(JsonObjectWriter_Init, NULL);

    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    // arrange
    TwinConfigurationResult result = TwinConfiguration_Init();
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    umock_c_reset_all_calls();
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    TwinConfiguration_Deinit();
}

TEST_FUNCTION(TwinConfiguration_Init_ExpectSuccess)
{
    STRICT_EXPECTED_CALL(Lock_Init());
    STRICT_EXPECTED_CALL(LocalConfiguration_GetRemoteConfigurationObjectName()).SetReturn("conf");
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Init()).SetReturn(TWIN_OK);
    
    int result = TwinConfiguration_Init();
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ValidateDefaultTwinConfigurationParameters();
    
}

TEST_FUNCTION(TwinConfiguration_Init_LockFailed_ExpectFailure)
{
    STRICT_EXPECTED_CALL(Lock_Init()).SetReturn(NULL);
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Deinit());

    int result = TwinConfiguration_Init();
    
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ValidateDefaultTwinConfigurationParameters();
}

TEST_FUNCTION(TwinConfiguration_Init_InitEventPrioritiesFailed_ExpectFailure)
{
    STRICT_EXPECTED_CALL(Lock_Init());
    STRICT_EXPECTED_CALL(LocalConfiguration_GetRemoteConfigurationObjectName()).SetReturn("conf");
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Init()).SetReturn(TWIN_EXCEPTION);
    STRICT_EXPECTED_CALL(Lock_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Deinit());
    
    int result = TwinConfiguration_Init();
    ASSERT_ARE_EQUAL(int, TWIN_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ValidateDefaultTwinConfigurationParameters();
}

TEST_FUNCTION(TwinConfiguration_UpdateComplete_ExpectSuccess)
{
    ValidateTwinConfigurationUpdate(true /*isComplete*/, false /*injectUnlockError*/);
}

TEST_FUNCTION(TwinConfiguration_UpdatePartial_ExpectSuccess)
{
    ValidateTwinConfigurationUpdate(false /*isComplete*/, false /*injectUnlockError*/);
}

TEST_FUNCTION(TwinConfiguration_AllJsonKeysMissing_ExpectDefaultValuesFallback)
{
    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, DUMMY_STRING));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, "desired"));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, IGNORED_PTR_ARG));

    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_MESSAGE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, SNAPSHOT_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationBoolValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_Update(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(0);
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(mockedReader));

    STRICT_EXPECTED_CALL(Unlock(IGNORED_PTR_ARG));

    // act
    int result = TwinConfiguration_Update(DUMMY_STRING, true);

    // assert
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ValidateDefaultTwinConfigurationParameters();
}

TEST_FUNCTION(TwinConfiguration_InvalidJson_ExpectParseException)
{
    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, DUMMY_JSON)).SetReturn(JSON_READER_EXCEPTION);

    TwinConfigurationResult result = TwinConfiguration_Update(DUMMY_JSON, true);
    ASSERT_ARE_EQUAL(int, TWIN_EXCEPTION, result);
}

TEST_FUNCTION(TwinConfiguration_GetMaxMessageSizeWithLockError_ExpectLockException)
{
    unsigned int num;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetMaxMessageSize(&num);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetLowPriorityMessageFrequencyLockError_ExpectLockException)
{
    unsigned int num;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetLowPriorityMessageFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetHighPriorityMessageFrequencyWithLockError_ExpectLockException)
{
    unsigned int num;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetHighPriorityMessageFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetSnapshotFrequencyWithLockError_ExpectLockException)
{
    unsigned int num;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetSnapshotFrequency(&num);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetBaselineCustomChecksEnabledWithLockError_ExpectLockException)
{
    bool boolean;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetBaselineCustomChecksEnabled(&boolean);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetBaselineCustomChecksFilePathWithLockError_ExpectLockException)
{
    char* str;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetBaselineCustomChecksFilePath(&str);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetBaselineCustomChecksFileHashWithLockError_ExpectLockException)
{
    char* str;
    int result;

    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    result = TwinConfiguration_GetBaselineCustomChecksFileHash(&str);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_UpdateWithLockError_ExpectLockException)
{
    unsigned int num;
    char* string;
    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(IGNORED_PTR_ARG, DUMMY_JSON));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, "desired"));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(mockedReader, IGNORED_PTR_ARG));


    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationUintValueFromJson(mockedReader, MAX_MESSAGE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationTimeValueFromJson(mockedReader, SNAPSHOT_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationBoolValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_GetConfigurationStringValueFromJson(mockedReader, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, IGNORED_PTR_ARG)).SetReturn(TWIN_CONF_NOT_EXIST);
    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_ERROR).IgnoreAllArguments();
    STRICT_EXPECTED_CALL(TimeUtils_GetCurrentTime()).SetReturn(0);
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(mockedReader));

    int result = TwinConfiguration_Update(DUMMY_JSON, true);
    ASSERT_ARE_EQUAL(int, TWIN_LOCK_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_UpdateWithUnlockError_ExpectLockException)
{
      ValidateTwinConfigurationUpdate(true /*isComplete*/, true /*injectUnlockError*/);
}

TEST_FUNCTION(TwinConfiguration_GetLastTwinUpdateData_ExpectSuccess){
    ValidateTwinConfigurationUpdate(true /*isComplete*/, false /*injectUnlockError*/);
    TwinConfigurationUpdateResult result = { 0 };
    TwinConfiguration_GetLastTwinUpdateData(&result);

    ASSERT_ARE_EQUAL(int, dummyTime, result.lastUpdateTime);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result.lastUpdateResult);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.eventPriorities);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.highPriorityMessageFrequency);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.lowPriorityMessageFrequency);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.maxLocalCacheSize);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.maxMessageSize);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.snapshotFrequency);
    ASSERT_ARE_EQUAL(int, CONFIGURATION_OK, result.configurationBundleStatus.baselineCustomChecksEnabled);
    ASSERT_ARE_EQUAL(char_ptr, CONFIGURATION_OK, result.configurationBundleStatus.baselineCustomChecksFilePath);
    ASSERT_ARE_EQUAL(char_ptr, CONFIGURATION_OK, result.configurationBundleStatus.baselineCustomChecksFileHash);
}

TEST_FUNCTION(TwinConfiguration_GetSerializedTwinConfiguration_ExpectSuccess) {
    
    umock_c_reset_all_calls();
    uint32_t outSize;
    char* out;
    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetReturn(LOCK_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteUintConfigurationToJson(IGNORED_PTR_ARG, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteUintConfigurationToJson(IGNORED_PTR_ARG, MAX_MESSAGE_SIZE_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteStringConfigurationToJson(IGNORED_PTR_ARG, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteStringConfigurationToJson(IGNORED_PTR_ARG, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteStringConfigurationToJson(IGNORED_PTR_ARG, SNAPSHOT_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteBoolConfigurationToJson(IGNORED_PTR_ARG, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteStringConfigurationToJson(IGNORED_PTR_ARG, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfigurationUtils_WriteStringConfigurationToJson(IGNORED_PTR_ARG, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, IGNORED_NUM_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPrioritiesJson(IGNORED_PTR_ARG)).SetReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetReturn(JSON_WRITER_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, &out, &outSize));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(Unlock(IGNORED_PTR_ARG)).SetReturn(LOCK_OK);

    TwinConfigurationResult result = TwinConfiguration_GetSerializedTwinConfiguration(&out, &outSize);
        ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    ASSERT_ARE_EQUAL(int, 10, outSize);
    ASSERT_IS_TRUE(strcmp("123456789", out) == 0);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(TwinConfiguration_GetSerializedTwinConfiguration_ExpectFail) {
    
    umock_c_negative_tests_init();
    uint32_t outSize;
    char* out;
    STRICT_EXPECTED_CALL(Lock(IGNORED_PTR_ARG)).SetFailReturn(LOCK_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteInt(IGNORED_PTR_ARG, MAX_MESSAGE_SIZE_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(true);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(true);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(TimeUtils_MillisecondsToISO8601DurationString(IGNORED_NUM_ARG, IGNORED_PTR_ARG, IGNORED_NUM_ARG)).SetFailReturn(true);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteString(IGNORED_PTR_ARG, SNAPSHOT_FREQUENCY_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Init(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(TwinConfigurationEventCollectors_GetPrioritiesJson(IGNORED_PTR_ARG)).SetFailReturn(TWIN_OK);
    STRICT_EXPECTED_CALL(JsonObjectWriter_WriteObject(IGNORED_PTR_ARG, EVENT_PROPERTIES_KEY, IGNORED_NUM_ARG)).SetFailReturn(JSON_WRITER_EXCEPTION);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Serialize(IGNORED_PTR_ARG, &out, &outSize));
    STRICT_EXPECTED_CALL(Unlock(IGNORED_PTR_ARG)).SetFailReturn(LOCK_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectWriter_Deinit(IGNORED_PTR_ARG));

  
    umock_c_negative_tests_snapshot();

    for (int i = 0; i < umock_c_negative_tests_call_count(); i++) {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        TwinConfigurationResult result = TwinConfiguration_GetSerializedTwinConfiguration(&out, &outSize);
        ASSERT_IS_TRUE(TWIN_OK != result);
    }

    umock_c_negative_tests_deinit();    
}

TEST_FUNCTION(TwinConfiguration_Update_MalformedJson_ConfigStayIntact){
    
    TwinConfigurationResult result = TwinConfiguration_Init();
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);    
    ValidateDefaultTwinConfigurationParameters();

    umock_c_reset_all_calls();

    JsonObjectReaderHandle readerHandle;
    STRICT_EXPECTED_CALL(JsonObjectReader_InitFromString(&readerHandle, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(readerHandle, "desired"));
    STRICT_EXPECTED_CALL(JsonObjectReader_StepIn(readerHandle, IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadInt(readerHandle, MAX_LOCAL_CACHE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadInt(readerHandle, MAX_MESSAGE_SIZE_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, LOW_PRIORITY_MESSAGE_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, SNAPSHOT_FREQUENCY_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, BASELINE_CUSTOM_CHECKS_ENABLED_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_ReadString(readerHandle, BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY, IGNORED_PTR_ARG)).SetReturn(JSON_READER_PARSE_ERROR);
    STRICT_EXPECTED_CALL(JsonObjectReader_Deinit(readerHandle));

    result = TwinConfigurationEventCollectors_Update(readerHandle);
    ASSERT_ARE_EQUAL(int, TWIN_OK, result);
    
    ValidateDefaultTwinConfigurationParameters();
}


END_TEST_SUITE(twin_configuration_ut)
