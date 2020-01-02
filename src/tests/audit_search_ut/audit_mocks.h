// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "macro_utils.h"
#include "umock_c_prod.h"

#include <auparse.h>

MOCKABLE_FUNCTION(, int, ausearch_add_timestamp_item, auparse_state_t*, au, const char*, op, time_t, sec, unsigned int, milli, ausearch_rule_t, how);
MOCKABLE_FUNCTION(, auparse_state_t*, auparse_init, ausource_t, source, const void*, b)
MOCKABLE_FUNCTION(, int, ausearch_add_item, auparse_state_t*, au, const char*, field, const char*, op, const char*, value, ausearch_rule_t, how);
MOCKABLE_FUNCTION(, int, ausearch_add_expression, auparse_state_t*, au, const char*, expression, char**, error, ausearch_rule_t, how);
MOCKABLE_FUNCTION(, int, ausearch_set_stop, auparse_state_t*, au, austop_t, where);
MOCKABLE_FUNCTION(, void, auparse_destroy, auparse_state_t*, au);
MOCKABLE_FUNCTION(, int, ausearch_next_event, auparse_state_t*, au);
MOCKABLE_FUNCTION(, const au_event_t*, auparse_get_timestamp, auparse_state_t*, au);
MOCKABLE_FUNCTION(, int, auparse_next_event, auparse_state_t*, au);
MOCKABLE_FUNCTION(, int, auparse_first_record, auparse_state_t*, au);
MOCKABLE_FUNCTION(, const char*, auparse_get_record_text, auparse_state_t*, au);
MOCKABLE_FUNCTION(, int, auparse_next_record, auparse_state_t*, au);
MOCKABLE_FUNCTION(, int, ausearch_add_interpreted_item, auparse_state_t*, au, const char*, field, const char*, op, const char*, value, ausearch_rule_t, how);
