// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os_utils/linux/audit/audit_search.h"

#include <errno.h>
#include <libaudit.h>
#include <stdlib.h>
#include <string.h>

#include "internal/time_utils.h"
#include "logger.h"
#include "os_utils/file_utils.h"
#include "utils.h"

static const char AUDIT_SEARCH_CRITERIA_TYPE_NAME[] = "type";
static const char AUDIT_SEARCH_CRITERIA_SYSCALL_NAME[] = "syscall";
static const char AUDIT_USER_AUTH_NAME[] = "USER_AUTH";
static const char AUDIT_USER_AUTH_SEARECH_RULE[] = "(type r= USER_AUTH) && (exe i!= \"/usr/bin/sudo\") && (exe i!= \"/bin/sudo\")";

/**
 * @brief Converts an enum to a string.
 * 
 * @param   AuditSearchCriteria    a search criteria.
 * 
 * @returns the string represntation of the search criteria enum.
 */
const char* AuditSearch_ConvertCriteriaToString(AuditSearchCriteria searchCriteria);

/**
 * @brief Adds a timestamp checkpoint to the search.
 * 
 * @param   auditSearch     The search instance.
 * 
 * @return AUDIT_SEARCH_OKin case the checkpoint was added or the checkpoint file does not exist, otherwise AUDIT_SEARCH_EXCEPTION is returned.
 */
AuditSearchResultValues AuditSearch_AddCheckpointToSearch(AuditSearch* auditSearch);

AuditSearchResultValues AuditSearch_Init(AuditSearch* auditSearch, AuditSearchCriteria searchCriteria, const char* messageType, const char* checkpointFile) {
    const char* oneMessageTypeType[1];
    oneMessageTypeType[0] = messageType;
    return AuditSearch_InitMultipleSearchCriteria(auditSearch, searchCriteria, oneMessageTypeType, 1, checkpointFile);
}

AuditSearchResultValues AuditSearch_InitMultipleSearchCriteria(AuditSearch* auditSearch, AuditSearchCriteria searchCriteria, const char** messageTypes, uint32_t messageTypesCount, const char* checkpointFile) {
    
    memset(auditSearch, 0, sizeof(*auditSearch));
    auditSearch->firstSearch = true;
    AuditSearchResultValues result = AUDIT_SEARCH_OK;

    if (!ProcessInfoHandler_ChangeToRoot(&auditSearch->processInfo)) {
        Logger_Warning("Can not set privileges to root.");
        result = AUDIT_SEARCH_EXCEPTION;
        goto cleanup;
    }

    auditSearch->audit = auparse_init(AUSOURCE_LOGS, NULL);
    if (auditSearch->audit == NULL) {
        Logger_Warning("Can not initiate auparse.");
        result = AUDIT_SEARCH_EXCEPTION;
        goto cleanup;
    }

    /*
     * Notice that the order of the rules is important! 
     * If we want to have a rule like (type1 || type2 || type3) && timestamps
     * we first have to create all the types condition and only then the timestamp.
     * This is because when audit evalutes the expression it always first evaluates each of
     * the sub expressions (by the order of addition) and then the final op.
     * So basically we will get ((type1 || type2) || type3) && timestamp
     */
    for (uint32_t i = 0; i < messageTypesCount; ++i) {
        ausearch_rule_t currentRule = AUSEARCH_RULE_OR;
        if (i == 0) {
            currentRule = AUSEARCH_RULE_CLEAR;
        }
       /*
        * We want to monitor only local login operations but auditd "USER_AUTH" type includes sudo commands too.
        * The following expression makes sure to include only login operations and ignore sudo commands.
        */
        if (searchCriteria == AUDIT_SEARCH_CRITERIA_TYPE && strcmp(messageTypes[i], AUDIT_USER_AUTH_NAME) == 0) {
            char *error = NULL;
            const char *expression = AUDIT_USER_AUTH_SEARECH_RULE;
            if (ausearch_add_expression(auditSearch->audit, expression, &error, currentRule) == -1) {
                result = AUDIT_SEARCH_EXCEPTION;
                goto cleanup;
            }
        } else if (searchCriteria == AUDIT_SEARCH_CRITERIA_SYSCALL) {
            // Compare syscalls only by name, to avoid syscall number arch differences 
            if (ausearch_add_interpreted_item(auditSearch->audit, AuditSearch_ConvertCriteriaToString(searchCriteria), "=", messageTypes[i], currentRule) == -1) {
                result = AUDIT_SEARCH_EXCEPTION;
                goto cleanup;
            }
        } else {
            if (ausearch_add_item(auditSearch->audit, AuditSearch_ConvertCriteriaToString(searchCriteria), "=", messageTypes[i], currentRule) == -1) {
                result = AUDIT_SEARCH_EXCEPTION;
                goto cleanup;
            }
        }
    }
    
    if (checkpointFile != NULL){
        if (!(Utils_CreateStringCopy(&auditSearch->checkpointFile, checkpointFile))) {
            result = AUDIT_SEARCH_EXCEPTION;
            goto cleanup;
        }

        if (AuditSearch_AddCheckpointToSearch(auditSearch) != AUDIT_SEARCH_OK) {
            result = AUDIT_SEARCH_EXCEPTION;
            goto cleanup;
        }
    }

    if (ausearch_set_stop(auditSearch->audit, AUSEARCH_STOP_EVENT) == -1) {
        result = AUDIT_SEARCH_EXCEPTION;
        goto cleanup;
    }
  
    auditSearch->searchTime = TimeUtils_GetCurrentTime();

cleanup:
    if (result != AUDIT_SEARCH_OK) {
        AuditSearch_Deinit(auditSearch);
    }
    return result;
}

void AuditSearch_Deinit(AuditSearch* auditSearch) {
    if (auditSearch->checkpointFile != NULL) {
        free(auditSearch->checkpointFile);
        auditSearch->checkpointFile = NULL;
    }
    
    if (auditSearch->audit != NULL) {
        auparse_destroy(auditSearch->audit);
        auditSearch->audit = NULL;
    }

    if (!ProcessInfoHandler_Reset(&auditSearch->processInfo)) {
        Logger_Warning("Can not set privileges back to user.");
    }
}

AuditSearchResultValues AuditSearch_AddCheckpointToSearch(AuditSearch* auditSearch) {
    time_t timeval;
    FileResults result = FileUtils_ReadFile(auditSearch->checkpointFile, &timeval, sizeof(timeval), false);
    if (result == FILE_UTILS_OK) {
        if (ausearch_add_timestamp_item(auditSearch->audit, ">", timeval, 0, AUSEARCH_RULE_AND) == -1) {
            return AUDIT_SEARCH_EXCEPTION;
        } 
    } else if (result == FILE_UTILS_ERROR ) {
        return AUDIT_SEARCH_EXCEPTION;
    }
    return AUDIT_SEARCH_OK;
}

AuditSearchResultValues AuditSearch_GetNext(AuditSearch* auditSearch) {
    int result = 0;

    if (!auditSearch->firstSearch) {
        result = auparse_next_event(auditSearch->audit);
        if (result == -1) {
            return AUDIT_SEARCH_EXCEPTION;
        }

        if (result == 0) {
            return AUDIT_SEARCH_NO_MORE_DATA;
        }
    }

    auditSearch->firstSearch = false;
    result = ausearch_next_event(auditSearch->audit);
    if (result == -1) {
        return AUDIT_SEARCH_EXCEPTION;
    }

    if (result == 0) {
        return AUDIT_SEARCH_NO_MORE_DATA;
    }

    return AUDIT_SEARCH_HAS_MORE_DATA;
}

AuditSearchResultValues AuditSearch_SetCheckpoint(AuditSearch* auditSearch) {
    if (FileUtils_WriteToFile(auditSearch->checkpointFile, &auditSearch->searchTime, sizeof(auditSearch->searchTime)) != FILE_UTILS_OK) {
        return AUDIT_SEARCH_EXCEPTION; 
    }

    return AUDIT_SEARCH_OK;
}

AuditSearchResultValues AuditSearch_GetEventTime(AuditSearch* auditSearch, uint32_t* timeInSeconds) {
    const au_event_t* eventTime = auparse_get_timestamp(auditSearch->audit);
    if (eventTime == NULL) {
        return AUDIT_SEARCH_EXCEPTION;
    }

    *timeInSeconds = eventTime->sec;
    return AUDIT_SEARCH_OK;
}

AuditSearchResultValues AuditSearch_ReadInt(AuditSearch* auditSearch, const char* fieldName, int* output) {
    int result = auparse_first_record(auditSearch->audit);
    if (result == -1) {
        return AUDIT_SEARCH_EXCEPTION;
    } else if (result == 0) {
        return AUDIT_SEARCH_NO_DATA;
    }

    return AuditSearchUtils_ReadInt(auditSearch, fieldName, output);
}

AuditSearchResultValues AuditSearch_ReadString(AuditSearch* auditSearch, const char* fieldName, const char** output) {
    int result = auparse_first_record(auditSearch->audit);
    if (result == -1) {
        return AUDIT_SEARCH_EXCEPTION;
    } else if (result == 0) {
        return AUDIT_SEARCH_NO_DATA;
    }

    return AuditSearchUtils_ReadString(auditSearch, fieldName, output);
}

AuditSearchResultValues AuditSearch_InterpretString(AuditSearch* auditSearch, const char* fieldName, const char** output) {
    int result = auparse_first_record(auditSearch->audit);
    if (result == -1) {
        return AUDIT_SEARCH_EXCEPTION;
    } else if (result == 0) {
        return AUDIT_SEARCH_NO_DATA;
    }
    return AuditSearchUtils_InterpretString(auditSearch, fieldName, output);
}

AuditSearchResultValues AuditSearch_LogEventText(AuditSearch* auditSearch) {
    const char* output = NULL;
    int result = auparse_first_record(auditSearch->audit);
    if (result == 0) {
        return AUDIT_SEARCH_NO_DATA;
    }

    do {
        if (result == -1) {
            return AUDIT_SEARCH_EXCEPTION;
        } 

        output = auparse_get_record_text(auditSearch->audit);
        if (output == NULL) {
            return AUDIT_SEARCH_EXCEPTION;
        }
        Logger_Debug("%s", output);

        result = auparse_next_record(auditSearch->audit);
    } while (result != 0);

    return AUDIT_SEARCH_OK;
}


const char* AuditSearch_ConvertCriteriaToString(AuditSearchCriteria searchCriteria) {
    switch (searchCriteria) {
        case AUDIT_SEARCH_CRITERIA_TYPE: return (const char*) AUDIT_SEARCH_CRITERIA_TYPE_NAME;
        case AUDIT_SEARCH_CRITERIA_SYSCALL: return (const char*) AUDIT_SEARCH_CRITERIA_SYSCALL_NAME;
        default: return (const char*) AUDIT_SEARCH_CRITERIA_TYPE_NAME;
    }
}