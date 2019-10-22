// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include "consts.h"
#include "internal/time_utils_consts.h"

const char AGENT_NAME[] = "ASCIoTAgent";

const char AGENT_VERSION[] = "0.0.5";

const char DEFAULT_MESSAGE_SCHEMA_VERSION[] = "1.0";

uint32_t DEFAULT_MAX_LOCAL_CACHE_SIZE = 10 * 1024 * 1024; // 10MB

uint32_t DEFAULT_MAX_MESSAGE_SIZE = 200 * 1024;

uint32_t DEFAULT_LOW_PRIORITY_MESSAGE_FREQUENCY = 5 * MILLISECONDS_IN_AN_HOUR;

uint32_t DEFAULT_HIGH_PRIORITY_MESSAGE_FREQUENCY = 7 * MILLISECONDS_IN_A_MINUTE;

uint32_t DEFAULT_SNAPSHOT_FREQUENCY = 13 * MILLISECONDS_IN_AN_HOUR;

const bool DEFAULT_BASELINE_CUSTOM_CHECKS_ENABLED = false;

const char* DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_PATH = NULL;

const char* DEFAULT_BASELINE_CUSTOM_CHECKS_FILE_HASH = NULL;

const uint32_t SCHEDULER_INTERVAL = 1 * 1000;

const uint32_t TWIN_UPDATE_SCHEDULER_INTERVAL = 10 * 1000;

const uint32_t MESSAGE_BILLING_MULTIPLE = 4 * 1024;

const char CONFIGURATION_FILE[] = "/LocalConfiguration.json";

const char* TCP_PROTOCOL = "tcp";

const char* TCP6_PROTOCOL = "tcp6";

const char* UDP_PROTOCOL= "udp";

const char* UDP6_PROTOCOL= "udp6";

const char* RAW_PROTOCOL= "raw6";

const char* RAW6_PROTOCOL= "raw6";

const char* PROTOCOL_TYPES[] = {"tcp", "tcp6", "udp", "udp6", "raw", "raw6"};

const uint32_t NUM_OF_PROTOCOLS = 6;