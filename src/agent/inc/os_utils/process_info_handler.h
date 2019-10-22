// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef PROCESS_INFO_HANDLER_H
#define PROCESS_INFO_HANDLER_H

#include <stdbool.h>
#include <sys/types.h>

#include "macro_utils.h"
#include "umock_c_prod.h"

typedef struct _ProcessInfo {

    uid_t effectiveUid;
    bool wasSet;

} ProcessInfo;

/**
 * @brief Switch the real and effective user id.
 * 
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, ProcessInfoHandler_SwitchRealAndEffectiveUsers);

/**
 * @brief Sets the current process privileges to root privileges.
 * 
 * @param   processInfo     A process info stucrt. This struct should be used in case of reset.
 * 
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, ProcessInfoHandler_ChangeToRoot, ProcessInfo*, processInfo);

/**
 * @brief Reset the process privileges to its origin.
 * 
 * @param   processInfo     A process info stucrt. The same one that was used in the ChangeToRoot function.
 * 
 * @return true on success, false otherwise.
 */
MOCKABLE_FUNCTION(, bool, ProcessInfoHandler_Reset, ProcessInfo*, processInfo);

#endif //PROCESS_INFO_HANDLER_H