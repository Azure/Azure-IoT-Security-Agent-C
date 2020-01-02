// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef CONNECTION_CREATE_COLLECTOR_H
#define CONNECTION_CREATE_COLLECTOR_H

#include <stdbool.h>

#include "macro_utils.h"
#include "umock_c_prod.h"

#include "collectors/generic_event.h"
#include "synchronized_queue.h"

/**
 * @brief enum all inbound and outbound conneciton created the last time this function was called, 
 * create a message for each connection creation and insert them into the queue.
 * 
 * @param   queue  The queue to insert the mesages to.
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, EventCollectorResult, ConnectionCreateEventCollector_GetEvents, SyncQueue*, queue);

/**
 * @brief initializes the connection event collector
 * 
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, EventCollectorResult, ConnectionCreateEventCollector_Init);

/**
 * @brief deinitializes the connection event collector
 */
MOCKABLE_FUNCTION(, void, ConnectionCreateEventCollector_Deinit);

#endif //CONNECTION_CREATE_COLLECTOR_H