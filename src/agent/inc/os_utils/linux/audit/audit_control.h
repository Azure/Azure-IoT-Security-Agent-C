// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef AUDIT_CONTROL_H
#define AUDIT_CONTROL_H

#include <auparse.h>
#include <stdbool.h>
#include <stdint.h>

#include "macro_utils.h"
#include "umock_c_prod.h"

#include "os_utils/process_info_handler.h"

typedef struct _AuditControl {

    int audit;
    ProcessInfo processInfo;
    bool processInfoWasSet;
    char* cpuArchitectureFilter;

} AuditControl;

typedef enum _AuditControlResultValues {

    AUDIT_CONTROL_OK,
    AUDIT_CONTROL_EXCEPTION
    
} AuditControlResultValues;

extern const char AUDIT_CONTROL_ON_SUCCESS_FILTER[];
extern const char AUDIT_CONTROL_TYPE_EXECVE[];
extern const char AUDIT_CONTROL_TYPE_EXECVEAT[];
extern const char AUDIT_CONTROL_TYPE_CONNECT[];
extern const char AUDIT_CONTROL_TYPE_ACCEPT[];

/**
 * @brief Initiates a new instance of audit control
 * 
 * @param   auditControl     The audit instance we want to initiate.
 * 
 * @return AUDIT_CONTROL_OK on success or an appropriate error. 
 */
MOCKABLE_FUNCTION(, AuditControlResultValues, AuditControl_Init, AuditControl*, auditControl);

/**
 * @brief Deinitiate the given audit control instance.
 * 
 * @param   auditControl     The audit instance we want to deinitiate.
 */
MOCKABLE_FUNCTION(, void, AuditControl_Deinit, AuditControl*, auditControl);

/**
 * @brief Adds a new rule.
 * 
 * @param   auditControl        The audit instance.
 * @param   msgTypeArray        The message type array for the new rules.
 * @param   msgTypeArraySize    The message type array size for the new rules.
 * @param   architecture        Flag which indicates whether the new rule should support 32bit, 64bit or agnostic.
 * @param   extraFilter         Extra filter for this rule. Use NULL if sude flag is not required.
 * 
 * @return AUDIT_CONTROL_OK on success or an appropriate error. 
 */
MOCKABLE_FUNCTION(, AuditControlResultValues, AuditControl_AddRule, AuditControl*, auditControl, const char**, msgTypeArray, size_t, msgTypeArraySize, const char*, extraFilter);

#endif //AUDIT_CONTROL_H