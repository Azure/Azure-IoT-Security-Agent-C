// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "collectors/listening_ports_collector.h"

#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <regex.h>

#include "collectors/generic_event.h"
#include "json/json_array_writer.h"
#include "json/json_object_writer.h"
#include "message_schema_consts.h"
#include "os_utils/listening_ports_iterator.h"
#include "azure_c_shared_utility/map.h"
#include "utils.h"
#include "consts.h"


#define MAX_RECORD_VALUE_LENGTH 128
#define MAX_GROUP_SIZE 32
static const char* INODE_REGEX = "socket:\\[(.*?)\\]";
static const char* PROC_DIR_NAME = "/proc/";
static const char* LIST_PROCESS_INODES_COMMAND = "ls -l /proc/%s/fd";

/**
 * @brief Adds the ports payload to the object writer.
 *
 * @param   listeningPortsEventWriter   The parent object writer to writes the paload to.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_AddPorts(JsonObjectWriterHandle listeningPortsEventWriter);

/**
 * @brief Adds the ports payload to the object writer.
 *
 * @param   listeningPortsEventWriter   The parent object writer to writes the paload to.
 * @param   protocolType                The type of the protocol.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_AddPortsByType(JsonArrayWriterHandle listeningPortsPayloadArray, const char* protocolType, MAP_HANDLE inodesMap);

/**
 * @brief Adds a single netstat revord to the payload array
 *
 * @param   listeningPortsPayloadArray  The json array writer of the payloads
 * @param   portsIterator               The ports iterator
 * @param   protocolType                The tyoe of the ports.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_AddSingleRecord(JsonArrayWriterHandle listeningPortsPayloadArray, ListeningPortsIteratorHandle portsIterator, const char* protocolType, MAP_HANDLE inodesMaps);

/**
 * @brief Adds extra details on ports to the object writer
 *
 * @param   portsIterator               The ports iterator
 * @param   extraDetails                The json writer of the extraDetails.
 * @param   inodesMap                   A map that maps inode to processId.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_PopulateExtraDetails(ListeningPortsIteratorHandle portsIterator, JsonObjectWriterHandle extraDetails, MAP_HANDLE inodesMap);

/**
 * @brief Adds the processId to the extraDetails payload array
 *
 * @param   portsIterator               The ports iterator
 * @param   extraDetails                The json writer of the extraDetails.
 * @param   value                       The buffer for the processId.
 * @param   inodesMap                   A map that maps inode to processId.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_AddPidToExtraDetails(ListeningPortsIteratorHandle portsIterator, JsonObjectWriterHandle extraDetails, char* value, MAP_HANDLE inodesMap);

/**
 * @brief Populates the given map with key value pairs: inode -> pid
 *
 * @param   MAP_HANDLE inodesMap        The map object to populate.
 *
 * @return EVENT_COLLECTOR_OK on success, EVENT_COLLECTOR_EXCEPTION otherwise.
 */
EventCollectorResult ListeningPortCollector_PopulateInodesMap(MAP_HANDLE inodesMap);

/**
 * @brief Search's for an inode in the given record.
 *
 * @param   record                      The ports iterator
 * @param   output                      The buffer to write the inode to.
 * @param   regex                       The regular expression for inode searching.
 *
 * @return true on success, false otherwise.
 */
bool ListeningPortCollector_SearchInode(char* record, char** output, const char* regex);

bool ListeningPortCollector_SearchInode(char* record, char** output, const char* regex){

    regex_t regexCompiled = { 0 };
    regmatch_t groupArray[2] = {};
    bool result = true;

    if (regcomp(&regexCompiled, regex, REG_ICASE|REG_EXTENDED) != 0){
        result = false;
    }

    if (regexec(&regexCompiled, record, 2, groupArray, 0) == 0){
       record[groupArray[1].rm_eo] = 0;
       result = (Utils_StringFormat("%s", output, (record + groupArray[1].rm_so)) == ACTION_OK);
    }

    regfree(&regexCompiled);

    return result;
}


bool ListeningPortCollector_PopulateProcessToInodesMap(MAP_HANDLE inodesMap, char* pid){

    char* command = NULL;
    FILE* fp = NULL;
    char record[MAX_RECORD_VALUE_LENGTH] = { 0 };
    char* inode = NULL;
    bool result = true;

    if (Utils_StringFormat(LIST_PROCESS_INODES_COMMAND, &command, pid) != ACTION_OK){
        result = false;
        goto cleanup;
    }
    fp = popen(command, "r");
    if (fp== NULL){
        result = false;
        goto cleanup;
    }

    while (fgets(record, MAX_RECORD_VALUE_LENGTH, fp) != NULL){
        if (!ListeningPortCollector_SearchInode(record, &inode, INODE_REGEX)){
            result = false;
            goto cleanup;
        }
        if (inode != NULL){
            MAP_RESULT mapResult = Map_Add(inodesMap, inode, pid);
            if (mapResult != MAP_OK && mapResult != MAP_KEYEXISTS){
                result = false;
                goto cleanup;
            }
            free(inode);
            inode = NULL;
        }
    }

cleanup:
    if (fp != NULL){
        pclose(fp);
    }
    if (command != NULL){
        free(command);
    }
    if (inode != NULL){
        free(inode);
    }
    return result;
}


EventCollectorResult ListeningPortCollector_AddPortsByType(JsonArrayWriterHandle listeningPortsPayloadArray, const char* protocolType, MAP_HANDLE inodesMap) {

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    ListeningPortsIteratorHandle portsIterator = NULL;

    if (ListenintPortsIterator_Init(&portsIterator, protocolType) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    ListeningPortsIteratorResults iteratorResult = ListenintPortsIterator_GetNext(portsIterator);
    while (iteratorResult == LISTENING_PORTS_ITERATOR_HAS_NEXT) {

        if (ListeningPortCollector_AddSingleRecord(listeningPortsPayloadArray, portsIterator, protocolType, inodesMap) != EVENT_COLLECTOR_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }

        iteratorResult = ListenintPortsIterator_GetNext(portsIterator);
    }

    if (iteratorResult != LISTENING_PORTS_ITERATOR_NO_MORE_DATA) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (portsIterator != NULL) {
        ListenintPortsIterator_Deinit(portsIterator);
    }
    return result;
}

EventCollectorResult ListeningPortCollector_AddSingleRecord(JsonArrayWriterHandle listeningPortsPayloadArray, ListeningPortsIteratorHandle portsIterator, const char* protocolType, MAP_HANDLE inodesMap) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle payloadWriter = NULL;
    JsonObjectWriterHandle extraDetails = NULL;

    if (JsonObjectWriter_Init(&payloadWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_Init(&extraDetails) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonObjectWriter_WriteString(payloadWriter, LISTENING_PORTS_PROTOCOL_KEY, protocolType) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    char value[MAX_RECORD_VALUE_LENGTH] = "";
    if (ListenintPortsIterator_GetLocalAddress(portsIterator, value, sizeof(value)) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(payloadWriter, LISTENING_PORTS_LOCAL_ADDRESS_KEY, value) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    memset(value, 0, sizeof(value));
    if (ListenintPortsIterator_GetLocalPort(portsIterator, value, sizeof(value)) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(payloadWriter, LISTENING_PORTS_LOCAL_PORT_KEY, value) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    memset(value, 0, sizeof(value));
    if (ListenintPortsIterator_GetRemoteAddress(portsIterator, value, sizeof(value)) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(payloadWriter, LISTENING_PORTS_REMOTE_ADDRESS_KEY, value) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    memset(value, 0, sizeof(value));
    if (ListenintPortsIterator_GetRemotePort(portsIterator, value, sizeof(value)) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    if (JsonObjectWriter_WriteString(payloadWriter, LISTENING_PORTS_REMOTE_PORT_KEY, value) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (ListeningPortCollector_PopulateExtraDetails(portsIterator, extraDetails, inodesMap) != LISTENING_PORTS_ITERATOR_OK){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }
    uint32_t size = 0;
    if (JsonObjectWriter_GetSize(extraDetails, &size) == JSON_WRITER_OK && size > 0){
        if (JsonObjectWriter_WriteObject(payloadWriter, EXTRA_DETAILS_KEY, extraDetails) != JSON_WRITER_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
    }

    if (JsonArrayWriter_AddObject(listeningPortsPayloadArray, payloadWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

cleanup:
    if (payloadWriter != NULL) {
        JsonObjectWriter_Deinit(payloadWriter);
    }
    if (extraDetails != NULL) {
        JsonObjectWriter_Deinit(extraDetails);
    }

    return result;
}


EventCollectorResult ListeningPortCollector_PopulateExtraDetails(ListeningPortsIteratorHandle portsIterator, JsonObjectWriterHandle extraDetails, MAP_HANDLE inodesMap) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    char value[MAX_RECORD_VALUE_LENGTH] = "";

    if (ListeningPortCollector_AddPidToExtraDetails(portsIterator, extraDetails, value, inodesMap) != EVENT_COLLECTOR_OK){
        result = EVENT_COLLECTOR_EXCEPTION;
    }

    return result;
}

EventCollectorResult ListeningPortCollector_AddPidToExtraDetails(ListeningPortsIteratorHandle portsIterator, JsonObjectWriterHandle extraDetails, char* value, MAP_HANDLE inodesMap) {
    EventCollectorResult result = EVENT_COLLECTOR_OK;

    if (ListenintPortsIterator_GetPid(portsIterator, value, sizeof(value), inodesMap) != LISTENING_PORTS_ITERATOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
    }

    if (strcmp(value,"") != 0){
        if (JsonObjectWriter_WriteString(extraDetails, LISTENING_PORTS_PID_KEY, value) != JSON_WRITER_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
        }
    }

    return result;
}

EventCollectorResult ListeningPortCollector_PopulateInodesMap(MAP_HANDLE inodesMap) {
    //generate a map: inode-> pid
    EventCollectorResult result = EVENT_COLLECTOR_OK;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    
    dir = opendir(PROC_DIR_NAME);
    if (dir == NULL){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (Utils_IsStringNumeric(entry->d_name)){
            if (!ListeningPortCollector_PopulateProcessToInodesMap(inodesMap, entry->d_name)){
                result = EVENT_COLLECTOR_EXCEPTION;
                goto cleanup;
            }
        }
    }

cleanup:
    if (dir != NULL){
        closedir(dir);
    }
    return result;
}


EventCollectorResult ListeningPortCollector_AddPorts(JsonObjectWriterHandle listeningPortsEventWriter) {

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonArrayWriterHandle listeningPortsPayloadArray = NULL;
    MAP_HANDLE inodesMap = Map_Create(NULL);

    if (inodesMap == NULL){
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (ListeningPortCollector_PopulateInodesMap(inodesMap) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (JsonArrayWriter_Init(&listeningPortsPayloadArray) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    for(size_t i=0; i < NUM_OF_PROTOCOLS; i++){
        if (ListeningPortCollector_AddPortsByType(listeningPortsPayloadArray, PROTOCOL_TYPES[i], inodesMap) != EVENT_COLLECTOR_OK) {
            result = EVENT_COLLECTOR_EXCEPTION;
            goto cleanup;
        }
    }

    result = GenericEvent_AddPayload(listeningPortsEventWriter, listeningPortsPayloadArray);
    if (result != EVENT_COLLECTOR_OK) {
        goto cleanup;
    }

cleanup:
    if (listeningPortsPayloadArray != NULL) {
        JsonArrayWriter_Deinit(listeningPortsPayloadArray);
    }
    Map_Destroy(inodesMap);
    return result;
}

EventCollectorResult ListeningPortCollector_GetEvents(SyncQueue* queue) {

    EventCollectorResult result = EVENT_COLLECTOR_OK;
    JsonObjectWriterHandle listeningPortsEventWriter = NULL;
    char* messageBuffer = NULL;

    if (JsonObjectWriter_Init(&listeningPortsEventWriter) != JSON_WRITER_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (GenericEvent_AddMetadata(listeningPortsEventWriter, EVENT_PERIODIC_CATEGORY, LISTENING_PORTS_NAME, EVENT_TYPE_SECURITY_VALUE, LISTENING_PORTS_PAYLOAD_SCHEMA_VERSION) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    if (ListeningPortCollector_AddPorts(listeningPortsEventWriter) != EVENT_COLLECTOR_OK) {
        result = EVENT_COLLECTOR_EXCEPTION;
        goto cleanup;
    }

    uint32_t messageBufferSize = 0;
    if (JsonObjectWriter_Serialize(listeningPortsEventWriter, &messageBuffer, &messageBufferSize) != JSON_WRITER_OK) {
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

    if (listeningPortsEventWriter != NULL) {
        JsonObjectWriter_Deinit(listeningPortsEventWriter);
    }

    return result;
}