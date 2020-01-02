// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "testrunnerswitcher.h"
#include "macro_utils.h"

#include "umock_c.h"
#include "umocktypes_bool.h"
#include "umocktypes_charptr.h"
#include "umock_c_negative_tests.h"
#include "utils.h"

#define ENABLE_MOCKS
#include "audit_mocks.h"
#include "mocks.h"
#include "os_utils/process_info_handler.h"
#undef ENABLE_MOCKS

#include <unistd.h>

#include "os_utils/linux/audit/audit_control.h"

static TEST_MUTEX_HANDLE test_serialize_mutex;
static TEST_MUTEX_HANDLE g_dllByDll;
 MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)

static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    char temp_str[256];
    (void)snprintf(temp_str, sizeof(temp_str), "umock_c reported error :%s",  MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
    ASSERT_FAIL(temp_str);
}

int Mocked_uname(struct utsname* buf) {
    const char* machine = "x86_64";
    strncpy(buf->machine, machine, strlen(machine));
    return 0;
}

BEGIN_TEST_SUITE(audit_control_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
     

    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    umocktypes_bool_register_types();
    umocktypes_charptr_register_types();
    REGISTER_UMOCK_ALIAS_TYPE(AuditControlResultValues, int);
    REGISTER_UMOCK_ALIAS_TYPE(long int, long);
    REGISTER_GLOBAL_MOCK_HOOK(uname, Mocked_uname);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    REGISTER_GLOBAL_MOCK_HOOK(uname, NULL);
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
     
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    umock_c_reset_all_calls();
}

TEST_FUNCTION(AuditControl_Init_ExpectSuccess)
{
    AuditControl audit;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(audit_open()).SetReturn(1);

    AuditControlResultValues result = AuditControl_Init(&audit);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_OK, result);
    AuditControl_Deinit(&audit);
}

TEST_FUNCTION(AuditControl_Init_SetToRootFAiled_Expectfailure)
{
    AuditControl audit;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(false);
    AuditControlResultValues result = AuditControl_Init(&audit);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_Init_Expectfailure)
{
    AuditControl audit;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(audit_open()).SetReturn(-1);
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG));

    AuditControlResultValues result = AuditControl_Init(&audit);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_EXCEPTION, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_Deinit_ExpectSuccess)
{
    AuditControl audit;

    STRICT_EXPECTED_CALL(ProcessInfoHandler_ChangeToRoot(IGNORED_PTR_ARG)).SetReturn(true);
    STRICT_EXPECTED_CALL(audit_open()).SetReturn(1);
    STRICT_EXPECTED_CALL(uname(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(audit_close(1));
    STRICT_EXPECTED_CALL(ProcessInfoHandler_Reset(IGNORED_PTR_ARG));

    AuditControlResultValues result = AuditControl_Init(&audit);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_OK, result);
    AuditControl_Deinit(&audit);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_AddRule_64BitHost_ExpectSuccess)
{
    AuditControl audit;
    audit.audit = 7;
    audit.cpuArchitectureFilter = "arch=b64";

    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_rule_syscallbyname_data(IGNORED_PTR_ARG, "msg")).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_add_rule_data(audit.audit, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)).SetReturn(1);

    const char* testSyscalls[] = {"msg"};
    AuditControlResultValues result = AuditControl_AddRule(&audit, testSyscalls, 1, NULL);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_AddRule_Non64BitHost_ExpectSuccess)
{
    AuditControl audit;
    audit.audit = 7;
    audit.cpuArchitectureFilter = "arch=b64";

    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_rule_syscallbyname_data(IGNORED_PTR_ARG, "msg")).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_add_rule_data(audit.audit, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)).SetReturn(1);

    const char* testSyscalls[] = {"msg"};
    AuditControlResultValues result = AuditControl_AddRule(&audit, testSyscalls, 1, NULL);

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_AddRule_ExtraFilter_ExpectSuccess)
{
    AuditControl audit;
    audit.audit = 7;
    audit.cpuArchitectureFilter = "arch=b64";

    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_rule_syscallbyname_data(IGNORED_PTR_ARG, "msg")).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, "a=b", AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetReturn(0);
    STRICT_EXPECTED_CALL(audit_add_rule_data(audit.audit, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)).SetReturn(1);

    const char* testSyscalls[] = {"msg"};
    AuditControlResultValues result = AuditControl_AddRule(&audit, testSyscalls, 1, "a=b");

    ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_OK, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());
}

TEST_FUNCTION(AuditControl_AddRule_Expectfailure)
{
    AuditControl audit;
    audit.audit = 7;
    audit.cpuArchitectureFilter = "arch=b64";

    umock_c_negative_tests_init();

    STRICT_EXPECTED_CALL(audit_rule_syscallbyname_data(IGNORED_PTR_ARG, "msg")).SetFailReturn(1);
    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetFailReturn(1);
    STRICT_EXPECTED_CALL(audit_rule_fieldpair_data(IGNORED_PTR_ARG, "donald=duck", AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK)).SetFailReturn(1);
    STRICT_EXPECTED_CALL(audit_add_rule_data(audit.audit, IGNORED_PTR_ARG, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)).SetFailReturn(1);

    umock_c_negative_tests_snapshot();

    for (int i = 0; i < umock_c_negative_tests_call_count(); i++) {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(i);

        if (i == 2) {
            // skip the sysconf mock
            continue;
        }

        const char* testSyscalls[] = {"msg"};
        AuditControlResultValues result = AuditControl_AddRule(&audit, testSyscalls, 1, "donald=duck");
        ASSERT_ARE_EQUAL(int, AUDIT_CONTROL_EXCEPTION, result);
    }

    umock_c_negative_tests_deinit();
}

END_TEST_SUITE(audit_control_ut)
