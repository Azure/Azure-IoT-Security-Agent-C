// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_charptr.h"

#include <limits.h>
#include "utils.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

BEGIN_TEST_SUITE(utils_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_charptr_register_types();
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(Utils_ConvertStringToInteger_IntWithDecimalBase_ExpectSuccess)
{
    int result = 0;
    bool success = false;

    success = Utils_ConvertStringToInteger("10", 10, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 10, result);

    success = Utils_ConvertStringToInteger("-10", 10, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, -10, result);

    success = Utils_ConvertStringToInteger("0", 10, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 0, result);

    // int max
    success = Utils_ConvertStringToInteger("2147483647", 10, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, INT_MAX, result);

    // overflow
    success = Utils_ConvertStringToInteger("2147483648", 10, &result);
    ASSERT_IS_FALSE(success);

    // underflow
    success = Utils_ConvertStringToInteger("-2147483649", 10, &result);
    ASSERT_IS_FALSE(success);

    // number and then string
    //FIXME: do we want this?
    success = Utils_ConvertStringToInteger("10foo", 10, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 10, result);
}

TEST_FUNCTION(Utils_ConvertStringToInteger_IntWithHexadecimalBase_ExpectSuccess)
{
    int result = 0;
    bool success = false;

    success = Utils_ConvertStringToInteger("0x10", 16, &result);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 0x10, result);
}

TEST_FUNCTION(Utils_ConvertStringToInteger_NotANumber_ExpectFailure)
{
    int result = 0;
    bool success = true;

    success = Utils_ConvertStringToInteger("foo", 10, &result);
    ASSERT_IS_FALSE(success);

    success = Utils_ConvertStringToInteger("", 10, &result);
    ASSERT_IS_FALSE(success);

    success = Utils_ConvertStringToInteger(NULL, 10, &result);
    ASSERT_IS_FALSE(success);

    success = Utils_ConvertStringToInteger("foo10", 10, &result);
    ASSERT_IS_FALSE(success);
}

TEST_FUNCTION(Utils_TrimLastOccurance_ExpectSuccess)
{
    char* inputString = strdup("tryout");

    Utils_TrimLastOccurance(inputString, 'b');
    ASSERT_ARE_EQUAL(char_ptr, inputString, "tryout");
    free(inputString);

    inputString = strdup("tryoutbutnotreally");
    Utils_TrimLastOccurance(inputString, 'b');
    ASSERT_ARE_EQUAL(char_ptr, inputString, "tryout");
    free(inputString);

    inputString = strdup("astringwithoutthefirstletter");
    Utils_TrimLastOccurance(inputString, 'a');
    ASSERT_ARE_EQUAL(char_ptr, inputString, "");
    free(inputString);

    inputString = strdup("for the list timez");
    Utils_TrimLastOccurance(inputString, 'z');
    ASSERT_ARE_EQUAL(char_ptr, inputString, "for the list time");
    free(inputString);
}

TEST_FUNCTION(Utils_ConvertIntegerToString_ExpectSuccess)
{
    int result = 0;
    bool success = false;
    char output[100];
    int outputSize = sizeof(output);
    success = Utils_IntegerToString(10, output, &outputSize);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 2, outputSize);
    ASSERT_ARE_EQUAL(char_ptr, "10", output);
    outputSize = sizeof(output);
    memset(output, 0, outputSize);
    success = Utils_IntegerToString(-345, output, &outputSize);
    ASSERT_IS_TRUE(success);
    ASSERT_ARE_EQUAL(int, 4, outputSize);
    ASSERT_ARE_EQUAL(char_ptr, "-345", output);
    outputSize = 1;
    memset(output, 0, sizeof(output));
    success = Utils_IntegerToString(10, output, &outputSize);
    ASSERT_IS_FALSE(success);
}

TEST_FUNCTION(Utils_IsPrefixOf_ExpectSuccess)
{
    ASSERT_IS_TRUE(Utils_IsPrefixOf("boom", strlen("boom"), "boom", strlen("boom")));
    ASSERT_IS_TRUE(Utils_IsPrefixOf("boom", strlen("boom"), "boomshak", strlen("boomshak")));
    ASSERT_IS_FALSE(Utils_IsPrefixOf("boom", strlen("boom"), "shakboom", strlen("shakboom")));
    ASSERT_IS_FALSE(Utils_IsPrefixOf("boomshak", strlen("boomshak"), "boom", strlen("boom")));
}

TEST_FUNCTION(Utils_AreStringsEqual_ExpectSuccess)
{
    ASSERT_IS_FALSE(Utils_AreStringsEqual(NULL, 5, NULL, 7, true));
    ASSERT_IS_FALSE(Utils_AreStringsEqual(NULL, 5, NULL, 7, true));

    ASSERT_IS_TRUE(Utils_AreStringsEqual("boom", strlen("boom"), "boom", strlen("boom"), true));
    ASSERT_IS_FALSE(Utils_AreStringsEqual("boom", strlen("boom"), "boomshak", strlen("boomshak"), true));
    ASSERT_IS_FALSE(Utils_AreStringsEqual("boom", strlen("boom"), "shakboom", strlen("shakboom"), true));

    ASSERT_IS_TRUE(Utils_AreStringsEqual("boom", strlen("boom"), "boom", strlen("boom"), false));
    ASSERT_IS_FALSE(Utils_AreStringsEqual("boom", strlen("boom"), "boomshak", strlen("boomshak"), false));
    ASSERT_IS_FALSE(Utils_AreStringsEqual("boom", strlen("boom"), "shakboom", strlen("shakboom"), false));

    ASSERT_IS_TRUE(Utils_AreStringsEqual("boom", strlen("boom"), "bOoM", strlen("bOoM"), false));
    ASSERT_IS_FALSE(Utils_AreStringsEqual("boom", strlen("boom"), "bOoM", strlen("bOoM"), true));
}

TEST_FUNCTION(Utils_UnsafeAreStringsEqual_ExpectSuccess)
{
    ASSERT_IS_TRUE(Utils_UnsafeAreStringsEqual("boom", "boom", true));
    ASSERT_IS_TRUE(Utils_UnsafeAreStringsEqual("boom", "boom", false));

    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("boom", "bOoM", true));
    ASSERT_IS_TRUE(Utils_UnsafeAreStringsEqual("boom", "bOoM", false));
    
    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("boom", "aa", true));
    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("BOOM", "aa", false));

    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("boom", "aaaa", true));
    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("BOOM", "aaaa", false));

    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("boom", "oiwerlsf", true));
    ASSERT_IS_FALSE(Utils_UnsafeAreStringsEqual("BOOM", "oiwerlsf", false));
}

TEST_FUNCTION(Utils_CopyString_ExpectSuccess)
{
    char dummyMsg[] = "this is a message";
    char dest[100] = "";
    
    bool result = Utils_CopyString(dummyMsg, sizeof(dummyMsg), (char*) dest, sizeof(dest));
    ASSERT_IS_TRUE(result);
    ASSERT_ARE_EQUAL(char_ptr, dummyMsg, dest);

    result = Utils_CopyString(dummyMsg, sizeof(dummyMsg), (char*) dest, sizeof(dummyMsg) - 1);
    ASSERT_IS_FALSE(result);
}

TEST_FUNCTION(Utils_ConcatenateToString_ExpectSuccess)
{
    char dummyMsg[] = "this is a message";
    char buffer[100] = "";
    char* bufferPtr = buffer;
    uint32_t bufferSize = sizeof(buffer);
    
    bool result = Utils_ConcatenateToString(&bufferPtr, &bufferSize, "%s %d %d %d", dummyMsg, 1, 2, 33);
    ASSERT_IS_TRUE(result);
    ASSERT_ARE_EQUAL(char_ptr, "this is a message 1 2 33", buffer);
    ASSERT_ARE_EQUAL(void_ptr, buffer + 24, bufferPtr);
    ASSERT_ARE_EQUAL(int, sizeof(buffer) - 24, bufferSize);

    bufferSize = 10;
    result = Utils_ConcatenateToString(&bufferPtr, &bufferSize, "%s %d %d %d", dummyMsg, 1, 2, 33);
    ASSERT_IS_FALSE(result);
}

TEST_FUNCTION(Utils_CreateString_ExpectSuccess)
{
    ActionResult result;
    char* dest;
    
    // test initialization from NULL
    result = Utils_DuplicateString(&dest, NULL);
    ASSERT_ARE_EQUAL(int, ACTION_OK, result);
    ASSERT_IS_TRUE(NULL == dest);

    char* input = "this is a message";
    result = Utils_DuplicateString(&dest, input);
    ASSERT_ARE_EQUAL(int, ACTION_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, input, dest);
    if (dest != NULL) {
        free(dest);
        dest = NULL;
    }

    if (dest != NULL) {
        free(dest);
        dest = NULL;
    }
}

TEST_FUNCTION(Utils_HexStringToByteArray_ExpectFail)
{
    char* hexString = "DEADBEEF";
    unsigned char buffer[10];
    uint32_t size = 2;
    bool result = Utils_HexStringToByteArray(hexString, buffer, &size);
    ASSERT_IS_FALSE(result);

    hexString = "DEADBEE";
    size = 10;
    result = Utils_HexStringToByteArray(hexString, buffer, &size);
    ASSERT_IS_FALSE(result);

    hexString = "Really not hex";
    size = 14;
    result = Utils_HexStringToByteArray(hexString, buffer, &size);
    ASSERT_IS_FALSE(result);
}

TEST_FUNCTION(Utils_HexStringToByteArray_ExpectSucess)
{
    char* hexString = "deadBEEF";
    unsigned char buffer[10];
    uint32_t size = 5;
    bool result = Utils_HexStringToByteArray(hexString, buffer, &size);
    ASSERT_IS_TRUE(result);
    ASSERT_ARE_EQUAL(int, 4, size);

    ASSERT_ARE_EQUAL(char, 222, *(buffer));
    ASSERT_ARE_EQUAL(char, 173, *(buffer+1));
    ASSERT_ARE_EQUAL(char, 190, *(buffer+2));
    ASSERT_ARE_EQUAL(char, 239, *(buffer+3));
}

TEST_FUNCTION(Utils_IsStringBlank_ExpectSuccess)
{
    ASSERT_IS_TRUE(Utils_IsStringBlank(NULL));
    ASSERT_IS_TRUE(Utils_IsStringBlank(""));
    ASSERT_IS_TRUE(Utils_IsStringBlank(" "));
    ASSERT_IS_FALSE(Utils_IsStringBlank("a"));
    ASSERT_IS_FALSE(Utils_IsStringBlank(" a "));
}

TEST_FUNCTION(Utils_IsStringNumeric_ExpectSuccess)
{
    ASSERT_IS_TRUE(Utils_IsStringNumeric("56"));
    ASSERT_IS_FALSE(Utils_IsStringNumeric(NULL));
    ASSERT_IS_FALSE(Utils_IsStringNumeric(" 546 "));
    ASSERT_IS_FALSE(Utils_IsStringNumeric("123abc123"));
}

TEST_FUNCTION(Utils_Substring_ExpectSuccess)
{
    char* src = NULL;
    char* dest = NULL;
    Utils_Substring("Hello", &dest, 1, 1);
    ASSERT_ARE_EQUAL(char_ptr, "ell", dest);
    ASSERT_IS_FALSE(Utils_Substring(src, &dest, 4, 1));
    ASSERT_IS_FALSE(Utils_Substring(NULL, &dest, 1, 2));
    free(dest);
    free(src);
}

TEST_FUNCTION(Utils_StringFormat_ExpectSuccess)
{
    ActionResult result;
    char* str = NULL;

    result = Utils_StringFormat(NULL, &str);
    ASSERT_ARE_EQUAL(char_ptr, NULL, str);
    ASSERT_ARE_EQUAL(int, ACTION_FAILED, result);

    result = Utils_StringFormat("a=%s", &str, "a");
    ASSERT_ARE_EQUAL(char_ptr, "a=a", str);
    free(str);
    str = NULL;

    result = Utils_StringFormat("a=%s", &str, "a", "b");
    ASSERT_ARE_EQUAL(char_ptr, "a=a", str);
    free(str);
    str = NULL;

    result = Utils_StringFormat("a=%s, b=%s",  &str, "a", "b");
    ASSERT_ARE_EQUAL(char_ptr, "a=a, b=b", str);
    free(str);
    str = NULL;
}

END_TEST_SUITE(utils_ut)
