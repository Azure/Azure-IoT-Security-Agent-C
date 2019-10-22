// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TWIN_CONFIGURATION_DEFS_H
#define TWIN_CONFIGURATION_DEFS_H

/**
 * All the result types of the TwinConfiguration functions
 */
typedef enum _TwinConfigurationResult {
    TWIN_OK,
    TWIN_CONF_NOT_EXIST,
    TWIN_LOCK_EXCEPTION,
    TWIN_PARSE_EXCEPTION,
    TWIN_MEMORY_EXCEPTION,
    TWIN_EXCEPTION
} TwinConfigurationResult;

/**
 * reprsent the status of a twin configuration
 */
typedef enum _TwinConfigurationStatus {
    CONFIGURATION_OK,
    CONFIGURATION_TYPE_MISMATCH,
} TwinConfigurationStatus;

/**
 * reprsent the status of a twin configuration bundle
 */
typedef struct _TwinConfigurationBundleStatus {
    TwinConfigurationStatus maxLocalCacheSize;
    TwinConfigurationStatus maxMessageSize;
    TwinConfigurationStatus lowPriorityMessageFrequency;
    TwinConfigurationStatus highPriorityMessageFrequency;
    TwinConfigurationStatus snapshotFrequency;
    TwinConfigurationStatus eventPriorities;
    TwinConfigurationStatus baselineCustomChecksEnabled;
    TwinConfigurationStatus baselineCustomChecksFilePath;
    TwinConfigurationStatus baselineCustomChecksFileHash;
 } TwinConfigurationBundleStatus;

 typedef enum _TwinConfigurationEventType {

    EVENT_TYPE_BASELINE,
    EVENT_TYPE_CONNECTION_CREATE,
    EVENT_TYPE_FIREWALL_CONFIGURATION,
    EVENT_TYPE_LISTENING_PORTS,
    EVENT_TYPE_LOCAL_USERS,
    EVENT_TYPE_PROCESS_CREATE,
    EVENT_TYPE_SYSTEM_INFORMATION,
    EVENT_TYPE_USER_LOGIN,
    EVENT_TYPE_DIAGNOSTIC,
    EVENT_TYPE_OPERATIONAL_EVENT

} TwinConfigurationEventType;

#endif //TWIN_CONFIGURATION_DEFS_H
