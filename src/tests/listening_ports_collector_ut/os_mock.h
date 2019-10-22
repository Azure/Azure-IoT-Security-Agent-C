// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "macro_utils.h"
#include "umock_c_prod.h"

#include <stdio.h>
#include <dirent.h>


MOCKABLE_FUNCTION(, FILE* ,fopen, const char*, path, const char*, mode);
MOCKABLE_FUNCTION(, FILE* ,popen, const char*, path, const char*, mode);
MOCKABLE_FUNCTION(, char*, fgets, char*, s, int, size, FILE*, stream);
MOCKABLE_FUNCTION(, int, pclose, FILE*, stream);
MOCKABLE_FUNCTION(, int, feof, FILE*, stream);
MOCKABLE_FUNCTION(, int, ferror, FILE*, stream);
MOCKABLE_FUNCTION(, DIR*, opendir, const char*, path);
MOCKABLE_FUNCTION(, int, closedir, DIR*, dir);
MOCKABLE_FUNCTION(, struct dirent*, readdir, DIR*, dirp);
