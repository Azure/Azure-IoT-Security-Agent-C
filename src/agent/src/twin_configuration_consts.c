// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "twin_configuration_consts.h"
#define EVENT_PRIO_PREFIX "eventPriority"
#define EVENT_AGG_ENABLED_PREFIX "aggregationEnabled"
#define EVENT_AGG_INTERVAL_PREFIX "aggregationInterval"
#define BASELINE_CUSTOM_CHECKS_PREFIX "baselineCustomChecks"

/* ===== Twin configuration Schema =====*/
const char* LOW_PRIORITY_MESSAGE_FREQUENCY_KEY = "lowPriorityMessageFrequency";
const char* HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY = "highPriorityMessageFrequency";
const char* MAX_LOCAL_CACHE_SIZE_KEY = "maxLocalCacheSizeInBytes";
const char* MAX_MESSAGE_SIZE_KEY = "maxMessageSizeInBytes";
const char* SNAPSHOT_FREQUENCY_KEY = "snapshotFrequency";
const char* HUB_RESOURCE_ID_KEY = "hubResourceId";
const char* EVENT_PROPERTIES_KEY = "eventPriorities";

/* ===== Event priorities schema =====*/
const char* PROCESS_CREATE_PRIORITY_KEY = EVENT_PRIO_PREFIX"ProcessCreate";
const char* LISTENING_PORTS_PRIORITY_KEY = EVENT_PRIO_PREFIX"ListeningPorts";
const char* SYSTEM_INFORMATION_PRIORITY_KEY = EVENT_PRIO_PREFIX"SystemInformation";
const char* LOCAL_USERS_PRIORITY_KEY = EVENT_PRIO_PREFIX"LocalUsers";
const char* LOGIN_PRIORITY_KEY = EVENT_PRIO_PREFIX"Login";
const char* CONNECTION_CREATE_PRIORITY_KEY = EVENT_PRIO_PREFIX"ConnectionCreate";
const char* FIREWALL_CONFIGURATION_PRIORITY_KEY = EVENT_PRIO_PREFIX"FirewallConfiguration";
const char* BASELINE_PRIORITY_KEY = EVENT_PRIO_PREFIX"OSBaseline";
const char* DIAGNOSTIC_PRIORITY_KEY = EVENT_PRIO_PREFIX"Diagnostic";
const char* OPERATIONAL_EVENT_KEY = EVENT_PRIO_PREFIX"Operational";

/* ===== Event Aggregation Schema =====*/
const char* PROCESS_CREATE_AGGREGATION_ENABLED_KEY = EVENT_AGG_ENABLED_PREFIX"ProcessCreate";
const char* PROCESS_CREATE_AGGREGATION_INTERVAL_KEY = EVENT_AGG_INTERVAL_PREFIX"ProcessCreate";
const char* CONNECTION_CREATE_AGGREGATION_ENABLED_KEY = EVENT_AGG_ENABLED_PREFIX"ConnectionCreate";
const char* CONNECTION_CREATE_AGGREGATION_INTERVAL_KEY = EVENT_AGG_INTERVAL_PREFIX"ConnectionCreate";

/* ===== Baseline custom checks configuration =====*/
const char* BASELINE_CUSTOM_CHECKS_ENABLED_KEY = BASELINE_CUSTOM_CHECKS_PREFIX"Enabled";
const char* BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY = BASELINE_CUSTOM_CHECKS_PREFIX"FilePath";
const char* BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY = BASELINE_CUSTOM_CHECKS_PREFIX"FileHash";