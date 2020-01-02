// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "collectors/generic_event.h"
#include "synchronized_queue.h"
#include "test_defs.h"

const char PROCESS_CREATE_MOCKED_MESSAGE_1[] = "{\"Category\": \"Triggered\", \"IsOperational\": false, \"Name\": \"ProcessCreate\", \"PayloadSchemaVersion\": \"1.0\", \"Id\":  \"08c2c0c1-007b-4388-88b3-0809888bc4e7\", \"TimestampLocal\": \"2018-12-25 07:15:57UTC\", \"TimestampUTC\": \"2018-12-25 07:15:57GMT\", \"Payload\": [ { \"Executable\": \"/usr/sbin/nscd\", \"CommandLine\": \"worker_nscd 0\", \"UserId\": 112, \"ProcessId\": 7273, \"ParentProcessId\": 1365 } ] }";
const char PROCESS_CREATE_MOCKED_MESSAGE_2[] = "{\"Category\": \"Triggered\", \"IsOperational\": false, \"Name\": \"ProcessCreate\", \"PayloadSchemaVersion\": \"1.0\", \"Id\": \"a639f185-fc1f-45da-8e3b-5565fa6098c9\", \"TimestampLocal\": \"2018-12-25 07:15:48UTC\", \"TimestampUTC\": \"2018-12-25 07:15:48GMT\", \"Payload\": [ { \"Executable\": \"/bin/dash\", \"CommandLine\": \"/bin/sh -c iptables --version\", \"UserId\": 0, \"ProcessId\": 7258, \"ParentProcessId\": 1923 } ] }";
const char PROCESS_CREATE_MOCKED_MESSAGE_3[] = "{\"Category\": \"Triggered\", \"IsOperational\": false, \"Name\": \"ProcessCreate\", \"PayloadSchemaVersion\": \"1.0\", \"Id\":  \"6a7a926b-50dc-4031-923d-aa7a0d5144c9\", \"TimestampLocal\": \"2018-12-25 07:15:48UTC\", \"TimestampUTC\": \"2018-12-25 07:15:48GMT\", \"Payload\": [ { \"Executable\": \"/bin/bash\", \"CommandLine\": \"/bin/bash -c sudo ausearch -sc connect  input-logs  --checkpoint /var/tmp/OutboundConnEventGeneratorCheckpoint\", \"UserId\": 1002, \"ProcessId\": 7256, \"ParentProcessId\": 29037 } ] }";
const char LISTENING_PORTS_MESSAGE_1[] = "{\"Category\": \"Periodic\", \"IsOperational\": false, \"Name\": \"ListeningPorts\", \"PayloadSchemaVersion\": \"1.0\", \"Id\": \"710fe408-c468-442e-ae3a-3228827271b5\", \"TimestampLocal\": \"2018-12-25 07:11:27UTC\", \"TimestampUTC\": \"2018-12-25 07:11:27GMT\", \"Payload\": [ { \"Protocol\": \"tcp\", \"LocalAddress\": \"0.0.0.0\", \"LocalPort\": \"25324\", \"RemoteAddress\": \"0.0.0.0\", \"RemotePort\": \"*\" }, { \"Protocol\": \"tcp\", \"LocalAddress\": \"0.0.0.0\", \"LocalPort\": \"22\", \"RemoteAddress\": \"0.0.0.0\", \"RemotePort\": \"*\" }, { \"Protocol\": \"tcp\", \"LocalAddress\": \"10.0.0.4\", \"LocalPort\": \"59941\", \"RemoteAddress\": \"137.117.83.38\", \"RemotePort\": \"5671\" }, {\"Protocol\": \"tcp\", \"LocalAddress\": \"10.0.0.4\", \"LocalPort\": \"52128\", \"RemoteAddress\": \"137.117.83.38\", \"RemotePort\": \"8883\" } ] }";
const char LISTENING_PORTS_MESSAGE_2[] = "{\"Category\": \"Periodic\", \"IsOperational\": false, \"Name\": \"ListeningPorts\", \"PayloadSchemaVersion\": \"1.0\", \"Id\": \"5d7696b9-eb7d-4b78-b129-53cdce75458d\", \"TimestampLocal\": \"2018-12-25 07:12:27UTC\", \"TimestampUTC\": \"2018-12-25 07:12:27GMT\", \"Payload\": [ { \"Protocol\": \"tcp\", \"LocalAddress\": \"0.0.0.0\", \"LocalPort\": \"1234\", \"RemoteAddress\": \"0.0.0.0\", \"RemotePort\": \"*\" }, { \"Protocol\": \"tcp\", \"LocalAddress\": \"0.0.0.0\", \"LocalPort\": \"80\", \"RemoteAddress\": \"0.0.0.0\", \"RemotePort\": \"*\" }, { \"Protocol\": \"tcp\", \"LocalAddress\": \"10.0.0.4\", \"LocalPort\": \"59941\", \"RemoteAddress\": \"137.117.83.38\", \"RemotePort\": \"5412\" }, {\"Protocol\": \"tcp\", \"LocalAddress\": \"10.0.0.4\", \"LocalPort\": \"28361\", \"RemoteAddress\": \"137.117.83.38\", \"RemotePort\": \"8883\" } ] }";

uint32_t processCreateMessageCounter = 0;
uint32_t listeningPortsMessageCounter = 0;

EventCollectorResult ProcessCreationCollector_GetEvents(SyncQueue* queue) {
    if (processCreateMessageCounter == 0) {
        SyncQueue_PushBack(queue, strdup(PROCESS_CREATE_MOCKED_MESSAGE_1), strlen(PROCESS_CREATE_MOCKED_MESSAGE_1) + 1);
        processCreateMessageCounter++;
    } else if (processCreateMessageCounter == 1) {
        SyncQueue_PushBack(queue, strdup(PROCESS_CREATE_MOCKED_MESSAGE_2), strlen(PROCESS_CREATE_MOCKED_MESSAGE_2));
        processCreateMessageCounter++;
    } else if (processCreateMessageCounter == 2) {
        SyncQueue_PushBack(queue, strdup(PROCESS_CREATE_MOCKED_MESSAGE_3), strlen(PROCESS_CREATE_MOCKED_MESSAGE_3));
        processCreateMessageCounter++;
    }
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ListeningPortCollector_GetEvents(SyncQueue* queue) {
    if (listeningPortsMessageCounter == 0) {
        SyncQueue_PushBack(queue, strdup(LISTENING_PORTS_MESSAGE_1), strlen(LISTENING_PORTS_MESSAGE_1));
        listeningPortsMessageCounter++;
    } else if (listeningPortsMessageCounter == 1) {
        SyncQueue_PushBack(queue, strdup(LISTENING_PORTS_MESSAGE_2), strlen(LISTENING_PORTS_MESSAGE_2));
        listeningPortsMessageCounter++;
    }
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult AgentConfigurationErrorCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult AgentTelemetryCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult BaselineCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ConnectionCreateEventCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult FirewallCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult LocalUsersCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult SystemInformationCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult UserLoginCollector_GetEvents(SyncQueue* queue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult DiagnosticEventCollector_Init(SyncQueue* eventsQueue) {
    return EVENT_COLLECTOR_OK;
}
void DiagnosticEventCollector_Deinit() {
    // left empty
}

EventCollectorResult DiagnosticEventCollector_GetEvents(SyncQueue* priorityQueue) {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ProcessCreationCollector_Init() {
    return EVENT_COLLECTOR_OK;
}

EventCollectorResult ConnectionCreateEventCollector_Init() {
    return EVENT_COLLECTOR_OK;
}

void ProcessCreationCollector_Deinit() { }

void ConnectionCreateEventCollector_Deinit() { }