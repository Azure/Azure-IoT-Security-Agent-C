# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

include("../../cmake_config/utilityFunctions.cmake")
include_directories(../../agent/inc)
include_directories(../../azure-iot-sdk-c/deps/parson)
add_definitions(-DDISABLE_LOGS)

set(theseTestsName schema_validation_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    schema_utils.c
    ../../agent/src/message_schema_consts.c
    ../../agent/src/message_serializer.c
    ../../agent/src/queue.c
    ../../agent/src/utils.c
    ../../agent/src/consts.c
    ../../agent/src/twin_configuration_consts.c
    ../../agent/src/twin_configuration.c
    ../../agent/src/twin_configuration_event_collectors.c
    ../../agent/src/twin_configuration_utils.c
    ../../agent/src/memory_monitor.c
    ../../agent/src/agent_telemetry_counters.c
    ../../agent/src/synchronized_queue.c
    ../../agent/src/collectors/diagnostic_event_collector.c
    ../../agent/src/collectors/agent_telemetry_collector.c
    ../../agent/src/collectors/agent_configuration_error_collector.c
    ../../agent/src/collectors/linux/connection_create_collector.c
    ../../agent/src/collectors/linux/generic_audit_event.c
    ../../agent/src/collectors/linux/user_login_collector.c
    ../../agent/src/collectors/linux/system_information_collector.c
    ../../agent/src/collectors/linux/listening_ports_collector.c
    ../../agent/src/collectors/linux/generic_event.c
    ../../agent/src/collectors/linux/firewall_collector.c
    ../../agent/src/collectors/linux/local_users_collector.c
    ../../agent/src/collectors/linux/process_creation_collector.c
    ../../agent/src/collectors/event_aggregator.c
    ../../agent/src/internal/time_utils.c
    ../../agent/src/internal/internal_memory_monitor.c
    ../../agent/src/json/json_reader.c
    ../../agent/src/json/json_object_reader.c
    ../../agent/src/json/json_object_writer.c
    ../../agent/src/json/json_array_reader.c
    ../../agent/src/json/json_array_writer.c
    ../../agent/src/os_utils/linux/correlation_manager.c
    ../../azure-iot-sdk-c/deps/parson/parson.c
    ../../azure-iot-sdk-c/c-utility/src/map.c
    ../../azure-iot-sdk-c/c-utility/src/xlogging.c
)

configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventDiagnostic_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityConnectedHardware_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityConnectionCreate_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityFirewallConfiguration_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityListeningPorts_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityLocalUsers_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityLogin_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityOSBaseline_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityProcessCreate_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecurityProcessTerminate_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventSecuritySystemInformation_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageEventTypeDefinitions_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageOperationalEventConfigurationError_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageOperationalEventDroppedEvents_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageOperationalEventMessageStatistics_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/messageRoot.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
configure_file(../../Azure-IoT-Security/security_message/schemas/message_v1_0.json ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

umockc_build_test_artifacts(${theseTestsName} ON)
