// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TIME_UTILS_CONSTS_H
#define TIME_UTILS_CONSTS_H

#define DURATION_MAX_LENGTH 19

#define MILLISECONDS_IN_A_SECOND    1000U
#define MILLISECONDS_IN_A_MINUTE    (MILLISECONDS_IN_A_SECOND * 60U)
#define MILLISECONDS_IN_AN_HOUR     (MILLISECONDS_IN_A_MINUTE * 60U)
#define MILLISECONDS_IN_A_DAY       (MILLISECONDS_IN_AN_HOUR * 24U)
#define MILLISECONDS_IN_A_WEEK      (MILLISECONDS_IN_A_DAY * 7U)
#define MILLISECONDS_IN_A_MONTH     (MILLISECONDS_IN_A_DAY * 30U)
#define MILLISECONDS_IN_A_YEAR      (MILLISECONDS_IN_A_DAY * 365U)

#define MAX_YEARS_IN_UINT32         (UINT32_MAX / MILLISECONDS_IN_A_YEAR)
#define MAX_MONTHS_IN_UINT32        (UINT32_MAX / MILLISECONDS_IN_A_MONTH)
#define MAX_WEEKS_IN_UINT32         (UINT32_MAX / MILLISECONDS_IN_A_WEEK)
#define MAX_DAYS_IN_UINT32          (UINT32_MAX / MILLISECONDS_IN_A_DAY)
#define MAX_HOURS_IN_UINT32         (UINT32_MAX / MILLISECONDS_IN_AN_HOUR)
#define MAX_MINUTES_IN_UINT32       (UINT32_MAX / MILLISECONDS_IN_A_MINUTE)
#define MAX_SECONDS_IN_UINT32       (UINT32_MAX / MILLISECONDS_IN_A_SECOND)

#endif //TIME_UTILS_CONSTS_H