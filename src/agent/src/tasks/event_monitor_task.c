// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "tasks/event_monitor_task.h"

#include <stdlib.h>
#include <stdint.h>

#include "collectors/agent_configuration_error_collector.h"
#include "collectors/agent_telemetry_collector.h"
#include "collectors/collector.h"
#include "collectors/connection_create_collector.h"
#include "collectors/diagnostic_event_collector.h"
#include "collectors/firewall_collector.h"
#include "collectors/linux/baseline_collector.h"
#include "collectors/listening_ports_collector.h"
#include "collectors/local_users_collector.h"
#include "collectors/process_creation_collector.h"
#include "collectors/system_information_collector.h"
#include "collectors/user_login_collector.h"
#include "internal/time_utils.h"
#include "local_config.h"
#include "logger.h"
#include "twin_configuration_event_collectors.h"
#include "twin_configuration.h"

/**
 * @brief Monitors all the periodic events in the system.
 * 
 * @param   task    The monitor task.
 * 
 * @return true on success, false otherwise.
 */
static bool EventMonitorTask_MonitorPeriodicEvents(EventMonitorTask* task);

/**
 * @brief Monitors all the triggered events in the system.
 * 
 * @param   task    The monitor task.
 * 
 * @return true on success, false otherwise.
 */
static bool EventMonitorTask_MonitorTriggeredEvents(EventMonitorTask* task);

/**
 * @brief Monitor a singke event type.
 * 
 * @param   task              The monitor task.
 * @param   eventType         The type of the collected event.
 * @param   collectFunction    The event collection function.
 *
 * @return true on success, false otherwise.
 */
static bool EventMonitorTask_MonitorSingleEvents(EventMonitorTask* task, TwinConfigurationEventType eventType, EventCollectorFunc collectFunction);

/**
 * @brief Initializes the collecots.
 *
 * @return true on success, false otherwise.
 */
static bool EventMonitorTask_InitCollectors();

/**
 * @brief deinitializes the collecots.
 */
static void EventMonitorTask_DeinitCollectors();


bool EventMonitorTask_Init(EventMonitorTask* task, SyncQueue* highPriorityQueue, SyncQueue* lowPriorityQueue, SyncQueue* operationalEventsQueue) {
    task->operationalEventsQueue = operationalEventsQueue;
    task->highPriorityQueue = highPriorityQueue;
    task->lowPriorityQueue = lowPriorityQueue;
    task->lastPeriodicExecution = 0;
    task->lastTriggeredExecution = 0;

    return EventMonitorTask_InitCollectors();
}

void EventMonitorTask_Deinit(EventMonitorTask* task) {
    task->highPriorityQueue = NULL;
    task->lowPriorityQueue = NULL;

    EventMonitorTask_DeinitCollectors();
}

void EventMonitorTask_Execute(EventMonitorTask* task) {

    uint32_t periodicFrequency = 0;
    if (TwinConfiguration_GetSnapshotFrequency(&periodicFrequency) != TWIN_OK) {
        return;
    }
    
    time_t currentTime = TimeUtils_GetCurrentTime();
    // time is in seconds so we convert it to milliseconds here
    uint32_t timeDiff = TimeUtils_GetTimeDiff(currentTime, task->lastPeriodicExecution);

    if (timeDiff >= periodicFrequency) {
        task->lastPeriodicExecution = currentTime;
        EventMonitorTask_MonitorPeriodicEvents(task);
    }

    timeDiff = TimeUtils_GetTimeDiff(currentTime, task->lastTriggeredExecution);
    if (timeDiff >= LocalConfiguration_GetTriggeredEventInterval()) {
        task->lastTriggeredExecution = currentTime;
        EventMonitorTask_MonitorTriggeredEvents(task);
    }
}

static bool EventMonitorTask_MonitorPeriodicEvents(EventMonitorTask* task) {
    //FIXME: add all periodic events
    Logger_Debug("Collect telemetry");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_OPERATIONAL_EVENT, AgentTelemetryCollector_GetEvents)){
        return false;
    }

    Logger_Debug("Collect local users.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_LOCAL_USERS, LocalUsersCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect system info.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_SYSTEM_INFORMATION, SystemInformationCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect listening ports.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_LISTENING_PORTS, ListeningPortCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect firewall configuration.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_FIREWALL_CONFIGURATION, FirewallCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect baseline events.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_BASELINE, BaselineCollector_GetEvents)) {
        return false;
    }

    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_DIAGNOSTIC, DiagnosticEventCollector_GetEvents)) {
        return false;
    }

    return true;
}

static bool EventMonitorTask_MonitorTriggeredEvents(EventMonitorTask* task) {
    //FIXME: add all triggered events
    Logger_Debug("Collect configuration error events");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_OPERATIONAL_EVENT, AgentConfigurationErrorCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect process create.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_PROCESS_CREATE, ProcessCreationCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect login.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_USER_LOGIN, UserLoginCollector_GetEvents)) {
        return false;
    }

    Logger_Debug("Collect connection create.");
    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_CONNECTION_CREATE, ConnectionCreateEventCollector_GetEvents)) {
        return false;
    }

    if (!EventMonitorTask_MonitorSingleEvents(task, EVENT_TYPE_DIAGNOSTIC, DiagnosticEventCollector_GetEvents)) {
        return false;
    }

    return true;
}

static bool EventMonitorTask_MonitorSingleEvents(EventMonitorTask* task, TwinConfigurationEventType eventType, EventCollectorFunc collectFunction) {
    TwinConfigurationEventPriority priority = 0;

    if (TwinConfigurationEventCollectors_GetPriority(eventType, &priority) != TWIN_OK) {
        return false;
    }

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    if (priority == EVENT_PRIORITY_OPERATIONAL){
        result = collectFunction(task->operationalEventsQueue);
    } else if (priority == EVENT_PRIORITY_HIGH) {
        result = collectFunction(task->highPriorityQueue);
    } else if (priority == EVENT_PRIORITY_LOW) {
        result = collectFunction(task->lowPriorityQueue);
    }

    if (result == EVENT_COLLECTOR_OK) {
        Logger_Debug("collection finished successfully.");
    } else {
        Logger_Debug("collection failed.");
    }
    return true;
}

bool EventMonitorTask_InitCollectors() {
    if (ProcessCreationCollector_Init() != EVENT_COLLECTOR_OK) {
        return false;
    }

    if (ConnectionCreateEventCollector_Init() != EVENT_COLLECTOR_OK) {
        return false;
    }

    return true;
}

void EventMonitorTask_DeinitCollectors() {
    ProcessCreationCollector_Deinit();
    ConnectionCreateEventCollector_Deinit();
}