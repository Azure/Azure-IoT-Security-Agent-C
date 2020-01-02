// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os_utils/linux/audit/audit_control.h"
#include "utils.h"
#include "logger.h"

#include <auparse.h>
#include <libaudit.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>

const char AUDIT_CONTROL_ON_SUCCESS_FILTER[] = "success=1";
const char AUDIT_CONTROL_TYPE_EXECVE[] = "execve";
const char AUDIT_CONTROL_TYPE_EXECVEAT[] = "execveat";
const char AUDIT_CONTROL_TYPE_CONNECT[] = "connect";
const char AUDIT_CONTROL_TYPE_ACCEPT[] = "accept";

/**
 * @brief Construct a cpu archtiecture filter for auditctl in the format of: "arch=$(uname -m)".
 * 
 * @param   cpuArchitectureFilter   Out param. The result string.
 * 
 * @return true on success.
 */
static bool getCpuArchitectureFilter(char** cpuArchitectureFilter);

AuditControlResultValues AuditControl_Init(AuditControl* auditControl) {
    AuditControlResultValues result = AUDIT_CONTROL_OK;

    memset(auditControl, 0, sizeof(*auditControl));
    auditControl->processInfoWasSet = false;

    if (!ProcessInfoHandler_ChangeToRoot(&auditControl->processInfo)) {
        result = AUDIT_CONTROL_EXCEPTION;
        goto cleanup;
    }
    auditControl->processInfoWasSet = true;

    auditControl->audit = audit_open();
    if (auditControl->audit < 0) {
        result = AUDIT_CONTROL_EXCEPTION;
        goto cleanup;
    }

    if (!getCpuArchitectureFilter(&auditControl->cpuArchitectureFilter)) {
        Logger_Error("Could not determine CPU architecture.");
        result = AUDIT_CONTROL_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (result != AUDIT_CONTROL_OK) {
        AuditControl_Deinit(auditControl);
    }
    return result;
}

void AuditControl_Deinit(AuditControl* auditControl) {
    if (auditControl->audit > 0) {
        audit_close(auditControl->audit);
    }

    if (auditControl->processInfoWasSet) {
        ProcessInfoHandler_Reset(&auditControl->processInfo);
        auditControl->processInfoWasSet = false;
    }

    if (auditControl->cpuArchitectureFilter != NULL) {
        free(auditControl->cpuArchitectureFilter);
        auditControl->cpuArchitectureFilter = NULL;
    }
}

AuditControlResultValues AuditControl_AddRule(AuditControl* auditControl, const char** msgTypeArray, size_t msgTypeArraySize, const char* extraFilter) {
    AuditControlResultValues result = AUDIT_CONTROL_OK;
    struct audit_rule_data* rule = NULL;
    char* msgTypeCopy = NULL;
    char* extraFilterCopy = NULL;

    rule = malloc(sizeof(struct audit_rule_data));
    memset(rule, 0, sizeof(struct audit_rule_data));

    int flags = AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK;

    if (audit_rule_fieldpair_data(&rule, auditControl->cpuArchitectureFilter, flags) != 0) { 
        result = AUDIT_CONTROL_EXCEPTION;
        goto cleanup;
    }

    for (int i=0; i<msgTypeArraySize; i++) {
        if (Utils_CreateStringCopy(&msgTypeCopy, msgTypeArray[i]) == false) {
            result = AUDIT_CONTROL_EXCEPTION;
            goto cleanup;
        }
        
        if ((audit_rule_syscallbyname_data(rule, msgTypeCopy)) < 0) {
            result = AUDIT_CONTROL_EXCEPTION;
            goto cleanup;
        }
    }
    if (extraFilter != NULL) {
        if (Utils_CreateStringCopy(&extraFilterCopy, extraFilter) == false) {
            result = AUDIT_CONTROL_EXCEPTION;
            goto cleanup; 
        }
        if (audit_rule_fieldpair_data(&rule, extraFilterCopy, flags) != 0) { 
            result = AUDIT_CONTROL_EXCEPTION;
            goto cleanup;    
        }
    }

    if (audit_add_rule_data(auditControl->audit, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) <= 0) { 
        result = AUDIT_CONTROL_EXCEPTION;
        goto cleanup;    
    }

cleanup:
    if (extraFilterCopy != NULL) {
        free(extraFilterCopy);
    }

    if (msgTypeCopy != NULL) {
        free(msgTypeCopy);
    }

    if (rule != NULL) {
        free(rule);
    }

    return result;
}

static bool getCpuArchitectureFilter(char** cpuArchitectureFilter) {
    struct utsname utsnameBuffer = {0};
    if (cpuArchitectureFilter == NULL) {
        return false;
    }

    if (uname(&utsnameBuffer)) {
        return false;
    }

    return (Utils_StringFormat("arch=%s", cpuArchitectureFilter, utsnameBuffer.machine) == ACTION_OK);
}
