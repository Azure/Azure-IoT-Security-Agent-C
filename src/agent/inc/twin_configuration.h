// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TWIN_CONFIGURATION_H
#define TWIN_CONFIGURATION_H

#include <stdbool.h>
#include <stdint.h>

#include "macro_utils.h"
#include "umock_c_prod.h"

#include "internal/time_utils.h"
#include "twin_configuration_consts.h"
#include "twin_configuration_defs.h"

typedef struct _TwinConfigurationUpdateResult {
    time_t lastUpdateTime;
    TwinConfigurationResult lastUpdateResult;
    TwinConfigurationBundleStatus configurationBundleStatus;
} TwinConfigurationUpdateResult;

/**
 * @brief   initialize the global configuration with default values
 * 
 * @return  TWIN_OK     on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_Init);

/**
 * @brief   updates the global configuration from a given json
 * 
 * @param   json        the json to update from
 * @param   complete    Indicates whether the diven json is complete twin configuration or partial.
 * 
 * @return  TWIN_OK     on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_Update, const char*, json, bool, complete);

/**
 * @brief   deinitiate the given twin configuration (free its memory)
 */
MOCKABLE_FUNCTION(, void, TwinConfiguration_Deinit);

/**
 * @brief   gets maxLocalCacheSize from the twin configuration, thread safe
 * 
 * @param   maxLocalCacheSize       out param
 * 
 * @return  TWIN_OK                 on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetMaxLocalCacheSize, uint32_t*, maxLocalCacheSize);

/**
 * @brief   gets maxMessageSize from the twin configuration, thread safe
 * 
 * @param   maxMessageSize  out param
 * 
 * @return  TWIN_OK         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetMaxMessageSize, uint32_t*, maxMessageSize);

/**
 * @brief   gets lowPriorityMessageFrequency from the twin configuration, thread safe
 * 
 * @param   lowPriorityMessageFrequency     out param
 * 
 * @return  TWIN_OK                         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetLowPriorityMessageFrequency, uint32_t*, lowPriorityMessageFrequency);

/**
 * @brief   gets highPriorityMessageFrequency from the twin configuration, thread safe
 * 
 * @param   highPriorityMessageFrequency    out param
 * 
 * @return  TWIN_OK                         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetHighPriorityMessageFrequency, uint32_t*, highPriorityMessageFrequency);

/**
 * @brief   gets snapshotFrequency from the twin configuration, thread safe
 * 
 * @param   snapshotFrequency   out param
 * 
 * @return  TWIN_OK             on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetSnapshotFrequency, uint32_t*, snapshotFrequency);

/**
 * @brief   gets baselineCustomChecksEnabled from the twin configuration, thread safe
 * 
 * @param   baselineCustomChecksEnabled out param
 * 
 * @return  TWIN_OK                     on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetBaselineCustomChecksEnabled, bool*, baselineCustomChecksEnabled);

/**
 * @brief   gets baselineCustomChecksFilePath from the twin configuration, thread safe
 * 
 * @param   baselineCustomChecksFilePath    out param
 * 
 * @return  TWIN_OK                         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetBaselineCustomChecksFilePath, char**, baselineCustomChecksFilePath);

/**
 * @brief   gets baselineCustomChecksFileHash from the twin configuration, thread safe
 * 
 * @param   baselineCustomChecksFileHash    out param
 * 
 * @return  TWIN_OK                         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetBaselineCustomChecksFileHash, char**, baselineCustomChecksFileHash);

/**
 * @brief   gets serialized twin configuration
 * 
 * @param   twin   out param the serialized twin
 * @param   size   out param the serialized twin size
 * 
 * @return  TWIN_OK         on success or an error code upon failure
 */
MOCKABLE_FUNCTION(, TwinConfigurationResult, TwinConfiguration_GetSerializedTwinConfiguration, char**,  twin, uint32_t*, size);

/**
 * @brief   gets the result of the last twin update
 * 
 * @param   outResult   Out param, result of last update
 */
MOCKABLE_FUNCTION(, void, TwinConfiguration_GetLastTwinUpdateData, TwinConfigurationUpdateResult*, outResult);
#endif //TWIN_CONFIGURATION_H