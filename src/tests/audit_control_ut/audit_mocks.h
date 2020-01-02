// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "macro_utils.h"
#include "umock_c_prod.h"

#include <libaudit.h>
#include <sys/utsname.h>

MOCKABLE_FUNCTION(, int, audit_open);
MOCKABLE_FUNCTION(, void, audit_close, int, fd);
MOCKABLE_FUNCTION(, int, audit_rule_syscallbyname_data, struct audit_rule_data*, rule, const char*, scall);
MOCKABLE_FUNCTION(, int, audit_rule_fieldpair_data, struct audit_rule_data**, rulep, const char*, pair, int, flags);
MOCKABLE_FUNCTION(, int, audit_add_rule_data, int, fd, struct audit_rule_data*, rule, int, flags, int, action);
MOCKABLE_FUNCTION(, int, uname, struct utsname*, buf);
