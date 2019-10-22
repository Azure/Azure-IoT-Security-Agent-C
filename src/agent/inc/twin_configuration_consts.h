// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TWIN_CONFIGURATION_CONSTS_H
#define TWIN_CONFIGURATION_CONSTS_H

/* ===== Twin configuration Schema =====*/
extern const char* LOW_PRIORITY_MESSAGE_FREQUENCY_KEY;
extern const char* HIGH_PRIORITY_MESSAGE_FREQUENCY_KEY;
extern const char* MAX_LOCAL_CACHE_SIZE_KEY;
extern const char* MAX_MESSAGE_SIZE_KEY;
extern const char* SNAPSHOT_FREQUENCY_KEY;
extern const char* HUB_RESOURCE_ID_KEY;
extern const char* EVENT_PROPERTIES_KEY;

/* ===== Event priorities schema =====*/
extern const char* PROCESS_CREATE_PRIORITY_KEY;
extern const char* LISTENING_PORTS_PRIORITY_KEY;
extern const char* SYSTEM_INFORMATION_PRIORITY_KEY;
extern const char* LOCAL_USERS_PRIORITY_KEY;
extern const char* LOGIN_PRIORITY_KEY;
extern const char* CONNECTION_CREATE_PRIORITY_KEY;
extern const char* FIREWALL_CONFIGURATION_PRIORITY_KEY;
extern const char* BASELINE_PRIORITY_KEY;
extern const char* DIAGNOSTIC_PRIORITY_KEY;
extern const char* OPERATIONAL_EVENT_KEY;

/* ===== Event Aggregation Schema =====*/
extern const char* PROCESS_CREATE_AGGREGATION_ENABLED_KEY;
extern const char* PROCESS_CREATE_AGGREGATION_INTERVAL_KEY;
extern const char* CONNECTION_CREATE_AGGREGATION_ENABLED_KEY;
extern const char* CONNECTION_CREATE_AGGREGATION_INTERVAL_KEY;

/* ===== Baseline custom checks configuration =====*/
extern const char* BASELINE_CUSTOM_CHECKS_ENABLED_KEY;
extern const char* BASELINE_CUSTOM_CHECKS_FILE_PATH_KEY;
extern const char* BASELINE_CUSTOM_CHECKS_FILE_HASH_KEY;

#endif //TWIN_CONFIGURATION_CONSTS_H