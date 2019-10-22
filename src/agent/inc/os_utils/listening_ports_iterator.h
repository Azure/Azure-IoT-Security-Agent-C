// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef LISTENING_PORTS_ITERATOR_H
#define LISTENING_PORTS_ITERATOR_H

#include <stdbool.h>
#include <stdint.h>

#include "macro_utils.h"
#include "umock_c_prod.h"
#include "azure_c_shared_utility/map.h"

typedef enum _ListeningPortsIteratorResults {

    LISTENING_PORTS_ITERATOR_OK,
    LISTENING_PORTS_ITERATOR_HAS_NEXT,
    LISTENING_PORTS_ITERATOR_NO_MORE_DATA,
    LISTENING_PORTS_ITERATOR_EXCEPTION

} ListeningPortsIteratorResults;


typedef struct ListeningPortsIterator* ListeningPortsIteratorHandle;

/**
 * @brief Initiates a listenint ports iterator.
 *
 * @param   iterator    Out param. The newly allocated iterator.
 * @param   protocolType        The type of the protocol.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_Init, ListeningPortsIteratorHandle*, iterator, const char*, protocolType);

/**
 * @brief Deinitiate the given iterator.
 *
 * @param   iterator    The iterator instance.
 */
MOCKABLE_FUNCTION(, void, ListenintPortsIterator_Deinit, ListeningPortsIteratorHandle, iterator);

/**
 * @brief Progess the iterator to the next item
 *
 * @param   iterator    The iterator instance.
 *
 * @return LISTENING_POTTS_ITERATOR_HAS_NEXT if there is a next item, LISTENING_POTTS_ITERATOR_NO_MORE_DATA if the iterator reached the
 *          end or LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_GetNext, ListeningPortsIteratorHandle, iterator);

/**
 * @brief Gets the local address of the curent item in the iterator.
 *
 * @param   iterator        The iterator instance.
 * @param   address         Buffer that will contain the address
 * @param   addresLength    The length of the address.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_GetLocalAddress, ListeningPortsIteratorHandle, iterator, char*, address, uint32_t, addresLength);

/**
 * @brief Gets the local port of the curent item in the iterator.
 *
 * @param   iterator      The iterator instance.
 * @param   port          Buffer that will contain the port
 * @param   portLength    The length of the port buffer.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_GetLocalPort, ListeningPortsIteratorHandle, iterator, char*, port, uint32_t, portLength);

/**
 * @brief Gets the remote address of the curent item in the iterator.
 *
 * @param   iterator        The iterator instance.
 * @param   address         Buffer that will contain the address
 * @param   addresLength    The length of the address.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_GetRemoteAddress, ListeningPortsIteratorHandle, iterator, char*, address, uint32_t, addresLength);

/**
 * @brief Gets the remote port of the curent item in the iterator.
 *
 * @param   iterator      The iterator instance.
 * @param   port          Buffer that will contain the port
 * @param   portLength    The length of the port buffer.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(, ListeningPortsIteratorResults, ListenintPortsIterator_GetRemotePort, ListeningPortsIteratorHandle, iterator, char*, port, uint32_t, portLength);

/**
 * @brief Gets the process id of the curent item in the iterator.
 *
 * @param   iterator     The iterator instance.
 * @param   pid          Buffer that will contain the processId
 * @param   pidLength    The length of the port buffer.
 *
 * @return LISTENING_POTTS_ITERATOR_OK on success, LISTENING_POTTS_ITERATOR_EXCEPTION otherwise.
 */
MOCKABLE_FUNCTION(,ListeningPortsIteratorResults, ListenintPortsIterator_GetPid, ListeningPortsIteratorHandle, iterator, char*, pid, uint32_t, pidLength, MAP_HANDLE, inodesMap);

#endif //LISTENING_PORTS_ITERATOR_H