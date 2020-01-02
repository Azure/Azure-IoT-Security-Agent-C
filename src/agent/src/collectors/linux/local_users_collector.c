// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "collectors/local_users_collector.h"

#include <stdlib.h>

#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "logger.h"
#include "message_schema_consts.h"
#include "os_utils/groups_iterator.h"
#include "os_utils/users_iterator.h"
#include "utils.h"


#define MAX_ID_AS_STRING_LENGTH 11

/**
 * @brief Adds a list of all groups for a given user.
 *
 * @param   usersIterator     The user iterator whos current user we want to use.
 * @param   parentObj         The parent object to which we want to add the new generated list.
 *
 * @return true on success, false otherwise. In case of failure the parent object will be unchanged.
 */
static bool LocalUsersCollector_AddGroupsForUser(UsersIteratorHandle usersIterator, JsonObjectWriterHandle parentObj);

/**
 * @brief Adds a signel user to the given parent object.
 *
 * @param   usersIterator     The user iterator whos current user we want to use.
 * @param   parentObj         The parent object to which we want to add the user.
 *
 * @return true on success, false otherwise. In case of failure the parent object will be unchanged.
 */
static bool LocalUsersCollector_AddSingleUser(UsersIteratorHandle usersIterator, JsonArrayWriterHandle parentObj);

/**
 * @brief Calculates the size of the combined group ids and combined group names
 *
 * @param   groupsIterator           The groups iterator to use.
 * @param   combinedGroupNamesSize   Out param. The final length needed for the combined group names.
 * @param   combinedGroupIdsSize     Out param. The final length needed for the combined group ids.
 *
 * @return true on success, false otherwise.
 */
static bool LocalUsersCollector_CalculateSizeOfGroups(GroupsIteratorHandle groupsIterator, uint32_t* combinedGroupNamesSize, uint32_t* combinedGroupIdsSize);

/**
 * @brief Generates the string representing the groupNames and a string representing the groupIds.
 *
 * @param   groupsIterator           The groups iterator to use.
 * @param   combinedGroupNames    Out param. Will contain the groupNames representation. Should b pre-allocated by the size returned from LocalUsersCollector_CalculateSizeOfGroups.
 * @param   combinedGroupIds      Out param. Will contain the groupIds representation. Should b pre-allocated by the size returned from LocalUsersCollector_CalculateSizeOfGroups.
 *
 * @return true on success, false otherwise.
 */
static bool LocalUsersCollector_GenerateGroupNamesAndIds(GroupsIteratorHandle groupsIterator, char* combinedGroupNames, char* combinedGroupIds);

/**
 * @brief Apeend a value to the delimiter combined string
 *
 * @param   combinedValue       The combined value.
 * @param   isFirst             Flag which indicates whether this is the first value.
 * @param   currentPosition     In-Out param. On input - poision to append the value to.
 *                              On output - the next available position in the combined string
 * @param   value               The value to append.
 * @param   delimiterLength     The length of the delimiter (in bytes).
 */
static void LocalUsersCollector_AppendValueName(char* combinedValue, bool isFirst, uint32_t* currentPosition, const char* value, uint32_t delimiterLength);

static void LocalUsersCollector_AppendValueName(char* combinedValue, bool isFirst, uint32_t* currentPosition, const char* value, uint32_t delimiterLength) {
    if (!isFirst) {
        memcpy(&combinedValue[*currentPosition], LOCAL_USERS_PAYLOAD_DELIMITER, delimiterLength);
        *currentPosition += delimiterLength;
    }

    uint32_t currentValueSize = strlen(value);
    memcpy(&combinedValue[*currentPosition], value, currentValueSize);
    *currentPosition += currentValueSize;
}

static bool LocalUsersCollector_CalculateSizeOfGroups(GroupsIteratorHandle groupsIterator, uint32_t* combinedGroupNamesSize, uint32_t* combinedGroupIdsSize) {

    // delimiters + null terminator
    uint32_t numOfGroups = GroupsIterator_GetGroupsCount(groupsIterator);
    *combinedGroupNamesSize = strlen(LOCAL_USERS_PAYLOAD_DELIMITER) * (numOfGroups - 1) + 1;
    *combinedGroupIdsSize = strlen(LOCAL_USERS_PAYLOAD_DELIMITER) * (numOfGroups - 1) + 1;

    while (GroupsIterator_HasNext(groupsIterator)) {
        if (!GroupsIterator_Next(groupsIterator)) {
            return false;
        }

        *combinedGroupNamesSize += strlen(GroupsIterator_GetName(groupsIterator));

        char idAsString[MAX_ID_AS_STRING_LENGTH] = "";
        int32_t idAsStringSize = MAX_ID_AS_STRING_LENGTH;
        if (!Utils_IntegerToString(GroupsIterator_GetId(groupsIterator), idAsString, &idAsStringSize)) {
            return false;
        }
        *combinedGroupIdsSize += idAsStringSize;
    }

    return true;
}

static bool LocalUsersCollector_GenerateGroupNamesAndIds(GroupsIteratorHandle groupsIterator, char* combinedGroupNames, char* combinedGroupIds) {
    uint32_t currentNamesPosition = 0;
    uint32_t currentIdsPosition = 0;
    uint32_t delimiterLength = strlen(LOCAL_USERS_PAYLOAD_DELIMITER);
    bool isFirst = true;

    while (GroupsIterator_HasNext(groupsIterator)) {
        if (!GroupsIterator_Next(groupsIterator)) {
            return false;
        }

        const char* currentNameValue = GroupsIterator_GetName(groupsIterator);
        LocalUsersCollector_AppendValueName(combinedGroupNames, isFirst, &currentNamesPosition, currentNameValue, delimiterLength);

        char idAsString[MAX_ID_AS_STRING_LENGTH] = "";
        int32_t isAsStringSize = MAX_ID_AS_STRING_LENGTH;
        if (!Utils_IntegerToString(GroupsIterator_GetId(groupsIterator), idAsString, &isAsStringSize)) {
            return false;
        }
        LocalUsersCollector_AppendValueName(combinedGroupIds, isFirst, &currentIdsPosition, idAsString, delimiterLength);

        if (isFirst) {
           isFirst = false;
        }
    }

    return true;
}

static bool LocalUsersCollector_AddGroupsForUser(UsersIteratorHandle usersIterator, JsonObjectWriterHandle parentObj) {
    bool success = true;

    GroupsIteratorHandle groupsIterator = NULL;
    char* combinedGroupNames = NULL;
    char* combinedGroupIds = NULL;

    if (UsersIterator_CreateGroupsIterator(usersIterator, &groupsIterator) != USER_ITERATOR_OK) {
        success = false;
        goto cleanup;
    }

    uint32_t combinedGroupNamesSize = 0;
    uint32_t combinedGroupIdsSize = 0;
    if (!LocalUsersCollector_CalculateSizeOfGroups(groupsIterator, &combinedGroupNamesSize, &combinedGroupIdsSize)) {
        success = false;
        goto cleanup;
    }
    GroupsIterator_Reset(groupsIterator);

    combinedGroupNames = malloc(combinedGroupNamesSize);
    if (combinedGroupNames == NULL) {
        success = false;
        goto cleanup;
    }
    memset(combinedGroupNames, 0, combinedGroupNamesSize);

    combinedGroupIds = malloc(combinedGroupIdsSize);
    if (combinedGroupIds == NULL) {
        success = false;
        goto cleanup;
    }
    memset(combinedGroupIds, 0, combinedGroupIdsSize);

    if (!LocalUsersCollector_GenerateGroupNamesAndIds(groupsIterator, combinedGroupNames, combinedGroupIds)) {
        success = false;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(parentObj, LOCAL_USERS_GROUP_NAMES_KEY, combinedGroupNames) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(parentObj, LOCAL_USERS_GROUP_IDS_KEY, combinedGroupIds) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

cleanup:
    if (groupsIterator != NULL) {
        GroupsIterator_Deinit(groupsIterator);
    }

    if (combinedGroupIds != NULL) {
        free(combinedGroupIds);
    }

    if (combinedGroupNames != NULL) {
        free(combinedGroupNames);
    }

    return success;
}

static bool LocalUsersCollector_AddSingleUser(UsersIteratorHandle usersIterator, JsonArrayWriterHandle parentObj) {
    bool success = true;

    JsonObjectWriterHandle userObject = NULL;
    if (JsonObjectWriter_Init(&userObject) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(userObject, LOCAL_USERS_USER_NAME_KEY, UsersIterator_GetUsername(usersIterator)) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

    char userIdStr[33] = {0};
    int32_t userIdStrSize = sizeof(userIdStr);
    if(UsersIterator_GetUserId(usersIterator, userIdStr, &userIdStrSize) != USER_ITERATOR_OK)
    {
        success = false;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(userObject, LOCAL_USERS_USER_ID_KEY, userIdStr) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

    if (!LocalUsersCollector_AddGroupsForUser(usersIterator, userObject)) {
        Logger_Debug("Failed adding groups for user %s.", UsersIterator_GetUsername(usersIterator));
        //FIXME: do we wnt to send the data without any groups?
    }

    if (JsonArrayWriter_AddObject(parentObj, userObject) != JSON_WRITER_OK) {
        success = false;
        goto cleanup;
    }

cleanup:
    if (userObject != NULL) {
        JsonObjectWriter_Deinit(userObject);
    }

    return success;
}

EventCollectorResult LocalUsersCollector_GetEvents(SyncQueue* queue) {

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle usersEventWriter = NULL;
    UsersIteratorHandle usersIterator = NULL;
    JsonArrayWriterHandle usersPayloadArray = NULL;
    char* messageBuffer = NULL;

    if (JsonObjectWriter_Init(&usersEventWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (GenericEvent_AddMetadata(usersEventWriter, EVENT_PERIODIC_CATEGORY, LOCAL_USERS_NAME, EVENT_TYPE_SECURITY_VALUE, LOCAL_USERS_PAYLOAD_SCHEMA_VERSION) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonArrayWriter_Init(&usersPayloadArray) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (UsersIterator_Init(&usersIterator) != USER_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    UserIteratorResults iteratorResult = UsersIterator_GetNext(usersIterator);
    while (iteratorResult == USER_ITERATOR_HAS_NEXT) {
        if (!LocalUsersCollector_AddSingleUser(usersIterator, usersPayloadArray)) {
            Logger_Debug("Failed adding user %s.", UsersIterator_GetUsername(usersIterator));
            //FIXME: do we want to iterate over the next user or do we want to stop?
        }
        iteratorResult = UsersIterator_GetNext(usersIterator);
    }
    if (iteratorResult != USER_ITERATOR_STOP) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    result = GenericEvent_AddPayload(usersEventWriter, usersPayloadArray);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

    uint32_t messageBufferSize = 0;
    if (JsonObjectWriter_Serialize(usersEventWriter, &messageBuffer, &messageBufferSize) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (SyncQueue_PushBack(queue, messageBuffer, messageBufferSize) != QUEUE_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:

    if (result != EVENT_COLLECTOR_OK) {
        if (messageBuffer !=  NULL) {
            free(messageBuffer);
        }
    }

    if (usersIterator != NULL) {
        UsersIterator_Deinit(usersIterator);
    }

    if (usersPayloadArray != NULL) {
        JsonArrayWriter_Deinit(usersPayloadArray);
    }

    if (usersEventWriter != NULL) {
        JsonObjectWriter_Deinit(usersEventWriter);
    }

    return result;
}
