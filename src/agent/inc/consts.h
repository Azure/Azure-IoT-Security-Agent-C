// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef CONSTS_H
#define CONSTS_H

#include <stdint.h>
#include <stdbool.h>

/**
 * Agent's name
 */
extern const char AGENT_NAME[];

/**
 * Agent's version
 */
extern const char AGENT_VERSION[];

/**
 * Agent's message scheme version
 */
extern const char DEFAULT_MESSAGE_SCHEMA_VERSION[];

/**
 * Agent's message max local cache size
 */
extern uint32_t DEFAULT_MAX_LOCAL_CACHE_SIZE;

/**
 * Agent's max message size
 */
extern uint32_t DEFAULT_MAX_MESSAGE_SIZE;

/**
 * Agent's low priority frequency
 */
extern uint32_t DEFAULT_LOW_PRIORITY_MESSAGE_FREQUENCY;

/**
 * Agent's high priority frequency
 */
extern uint32_t DEFAULT_HIGH_PRIORITY_MESSAGE_FREQUENCY;

/**
 * Agent's snapshot frequency
 */
extern uint32_t DEFAULT_SNAPSHOT_FREQUENCY;

/**
 * Baseline custom checks enabled
 */
extern const bool DEFAULT_BASELINE_CUSTOM_CHECKS_ENABLED;

/**
 * Baseline custom checks file path
 */
extern const char* DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH;

/**
 * Baseline custom checks file hash
 */
extern const char* DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH;

/**
 * The scheduler interval
 */
extern const uint32_t SCHEDULER_INTERVAL;

/**
 * The twin updates scheduler interval
 */
extern const uint32_t TWIN_UPDATE_SCHEDULER_INTERVAL;

/**
 * The configuration file to load from
 */
extern const char CONFIGURATION_FILE[];

/**
 * message billing multiple as denoted by Azure IoT hub
 */
extern const uint32_t MESSAGE_BILLING_MULTIPLE;

/**
 * Protocols name
 */
extern const char* TCP_PROTOCOL;

extern const char* TCP6_PROTOCOL;

extern const char* UDP_PROTOCOL;

extern const char* UDP6_PROTOCOL;

extern const char* RAW_PROTOCOL;

extern const char* RAW6_PROTOCOL;

extern const uint32_t NUM_OF_PROTOCOLS;

extern const char* PROTOCOL_TYPES[];

#endif //CONSTS_H