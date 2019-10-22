// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os_utils/listening_ports_iterator.h"

#include <arpa/inet.h> //inet_ntop
#include <netdb.h> //sockadd_in
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "utils.h"

#define MAX_NET_ADDR_LENGTH 128 
#define MAX_NET_PORT_LENGTH 20 
#define MAX_LINE_LENGTH 8192 
#define MAX_INODE_LENGTH 20
#define MAX_PROC_FILE_NAME_LENGTH 20

static const char* PROC_LINE_FORMAT = "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %*s %*s %*s %*s %*s %s %*s\n";
static const char ANY_PORT[] = "*";
static const char* PORTS_PROC_FILE = "/proc/net/%s";

typedef struct _ListeningPortsIterator {

    FILE* procFile;
    char localAddress[MAX_NET_ADDR_LENGTH];
    int localPort;
    char remoteAddress[MAX_NET_ADDR_LENGTH];
    int remotePort;
    char inode[MAX_INODE_LENGTH];
    
} ListeningPortsIterator;

/**
 * @brief Convert the given port to string and adds it to the dest buffer.
 *          The buffer should be pre-allocated and have enough space for the serialized port.
 *  
 * @param   port            The port to serialize.
 * @param   buffer          The buffer to serialize the port to.
 * @param   bufferLength    The length of the given buffer.
 * 
 * @return LISTENING_PORTS_ITERATOR_OK on success, LISTENING_PORTS_ITERATOR_EXCEPTION otherwise.
 */
ListeningPortsIteratorResults ListenintPortsIterator_GetPort(int port, char* buffer, uint32_t bufferLength);

/**
 * @bried serialize the given address (with the /proc/net format) to a human readable ip format.
 *          The dest buffer should be pre-allocated and have enough space for the serialized port.
 * 
 * @param   srcAddress          The address with the given /proc/net format.
 * @param   destAddress         The buffer to write the human readabl format to.
 * @param   destAddressLength   The length of the dest address buffer.
 * 
 * @return LISTENING_PORTS_ITERATOR_OK on success, LISTENING_PORTS_ITERATOR_EXCEPTION otherwise.
 */
ListeningPortsIteratorResults ListeningPortsIterator_GetAddress(const char* srcAddress, char* destAddress, uint32_t destAddressLength);

ListeningPortsIteratorResults ListenintPortsIterator_Init(ListeningPortsIteratorHandle* iterator, const char* protocolType) {
    ListeningPortsIteratorResults result = LISTENING_PORTS_ITERATOR_OK;

    ListeningPortsIterator* iteratorObj = malloc(sizeof(ListeningPortsIterator));
    if (iteratorObj == NULL) {
        result = LISTENING_PORTS_ITERATOR_EXCEPTION;
        goto cleanup;
    }
    memset(iteratorObj, 0, sizeof(ListeningPortsIterator));
    char proc_file_name[MAX_PROC_FILE_NAME_LENGTH];
    snprintf(proc_file_name, MAX_PROC_FILE_NAME_LENGTH, PORTS_PROC_FILE, protocolType);
    iteratorObj->procFile = fopen(proc_file_name, "r");
   
    if (iteratorObj->procFile == NULL) {
        result = LISTENING_PORTS_ITERATOR_EXCEPTION;
        goto cleanup;
    }

    char currentLine[MAX_LINE_LENGTH] = { 0 };
    // skip the first line (headers line)
    if (fgets(currentLine, sizeof(currentLine), iteratorObj->procFile) == NULL && ferror(iteratorObj->procFile)) {
        result = LISTENING_PORTS_ITERATOR_EXCEPTION;
    }
    
cleanup:
    *iterator = (ListeningPortsIteratorHandle)iteratorObj;

    if (result != LISTENING_PORTS_ITERATOR_OK) {
        if (iteratorObj != NULL) {
            ListenintPortsIterator_Deinit(*iterator);
        }
    }
    return result;
}

void ListenintPortsIterator_Deinit(ListeningPortsIteratorHandle iterator) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
     if (iteratorObj != NULL) {
        if (iteratorObj->procFile != NULL) {
            fclose(iteratorObj->procFile);
        }
        free(iteratorObj);
    }
}

ListeningPortsIteratorResults ListenintPortsIterator_GetNext(ListeningPortsIteratorHandle iterator) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    bool foundRecord = false;

    if (feof(iteratorObj->procFile) != 0) {
        return LISTENING_PORTS_ITERATOR_NO_MORE_DATA;
    }

    char currentLine[MAX_LINE_LENGTH] = { 0 };
    if (fgets(currentLine, sizeof(currentLine), iteratorObj->procFile) == NULL) {
        if (feof(iteratorObj->procFile) != 0) {
            return LISTENING_PORTS_ITERATOR_NO_MORE_DATA;
        }
        return LISTENING_PORTS_ITERATOR_EXCEPTION;
    }

    int portState = 0;
    int scanResult = sscanf(currentLine, PROC_LINE_FORMAT, iteratorObj->localAddress, &iteratorObj->localPort, iteratorObj->remoteAddress, &iteratorObj->remotePort, &portState, &iteratorObj->inode);
    if (scanResult != 6) {
        return LISTENING_PORTS_ITERATOR_EXCEPTION;
    }

    return LISTENING_PORTS_ITERATOR_HAS_NEXT;
}

ListeningPortsIteratorResults ListenintPortsIterator_GetLocalAddress(ListeningPortsIteratorHandle iterator, char* address, uint32_t addresLength) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    return ListeningPortsIterator_GetAddress(iteratorObj->localAddress, address, addresLength);
}

ListeningPortsIteratorResults ListenintPortsIterator_GetLocalPort(ListeningPortsIteratorHandle iterator, char* port, uint32_t portLength) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    return ListenintPortsIterator_GetPort(iteratorObj->localPort, port, portLength);
}

ListeningPortsIteratorResults ListenintPortsIterator_GetRemoteAddress(ListeningPortsIteratorHandle iterator, char* address, uint32_t addresLength) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    return ListeningPortsIterator_GetAddress(iteratorObj->remoteAddress, address, addresLength);
}

ListeningPortsIteratorResults ListenintPortsIterator_GetRemotePort(ListeningPortsIteratorHandle iterator, char* port, uint32_t portLength) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    return ListenintPortsIterator_GetPort(iteratorObj->remotePort, port, portLength);
}

ListeningPortsIteratorResults ListenintPortsIterator_GetPid(ListeningPortsIteratorHandle iterator, char* pid, uint32_t pidLength, MAP_HANDLE inodesMap) {
    ListeningPortsIterator* iteratorObj = (ListeningPortsIterator*)iterator;
    const char* iteratorPid = Map_GetValueFromKey(inodesMap, iteratorObj->inode);
    if(iteratorPid == NULL){
        return LISTENING_PORTS_ITERATOR_OK;
    }
    if (!Utils_CopyString(iteratorPid, strlen(iteratorPid), pid, pidLength)) {
        return LISTENING_PORTS_ITERATOR_EXCEPTION;
    }
    return LISTENING_PORTS_ITERATOR_OK;
}

ListeningPortsIteratorResults ListeningPortsIterator_GetAddress(const char* srcAddress, char* destAddress, uint32_t destAddressLength) {
    struct sockaddr_storage tmpAddress;
    struct sockaddr_in* socketAddress = (struct sockaddr_in*)&tmpAddress;
    int scanResult = sscanf(srcAddress, "%X", (int*)&(socketAddress->sin_addr.s_addr));
    if (scanResult != 1) {
        return LISTENING_PORTS_ITERATOR_EXCEPTION;
    }
    if (inet_ntop(AF_INET, &(socketAddress->sin_addr), destAddress, destAddressLength) == NULL) {
        return LISTENING_PORTS_ITERATOR_EXCEPTION;
    }
    return LISTENING_PORTS_ITERATOR_OK;
}

ListeningPortsIteratorResults ListenintPortsIterator_GetPort(int port, char* buffer, uint32_t bufferLength) {
    char srcPortFromInteger[MAX_NET_PORT_LENGTH] = "";
    char* srcPort = srcPortFromInteger;
    int32_t srcPortLength = MAX_NET_PORT_LENGTH;

    if (port == 0) {
        srcPort = (char*)ANY_PORT;
        srcPortLength = strlen(ANY_PORT);
    } else {
        if (!Utils_IntegerToString(port, srcPort, &srcPortLength)) {
            return LISTENING_PORTS_ITERATOR_EXCEPTION;
        }
    }

    if (Utils_CopyString(srcPort, srcPortLength, buffer, bufferLength)) {
        return LISTENING_PORTS_ITERATOR_OK;
    }
    return LISTENING_PORTS_ITERATOR_EXCEPTION;
}
