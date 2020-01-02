#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

include("../cmake_config/agentRules.cmake")

if(POLICY CMP0042)
    cmake_policy(SET CMP0042 NEW)
endif()

compileAsC99()

include_directories(${AGENT_HEADERS})
include_directories(${AZURE_IOT_SDK_HEADERS})
include_directories(${PARSON_HEADERS})
include_directories(${UMOCK_HEADERS})
include_directories(${TESTRUNNER_HEADERS})

set(agent_c_files
    ./src/agent_errors.c
    ./src/agent_telemetry_counters.c
    ./src/agent_telemetry_provider.c
    ./src/authentication_manager.c
    ./src/certificate_manager.c
    ./src/consts.c
    ./src/internal/internal_memory_monitor.c
    ./src/internal/time_utils.c
    ./src/iothub_adapter.c
    ./src/json/json_array_reader.c
    ./src/json/json_array_writer.c
    ./src/json/json_object_reader.c
    ./src/json/json_object_writer.c
    ./src/json/json_reader.c
    ./src/local_config.c
    ./src/logger.c
    ./src/main.c
    ./src/message_schema_consts.c
    ./src/message_serializer.c
    ./src/os_utils/linux/system_logger.c
    ./src/queue.c
    ./src/scheduler_thread.c
    ./src/security_agent.c
    ./src/synchronized_memory_monitor.c
    ./src/synchronized_queue.c
    ./src/tasks/event_monitor_task.c
    ./src/tasks/event_publisher_task.c
    ./src/tasks/update_twin_task.c
    ./src/twin_configuration_consts.c
    ./src/twin_configuration_event_collectors.c
    ./src/twin_configuration_utils.c
    ./src/twin_configuration.c
    ./src/utils.c
)

set(agent_h_files
    ./inc/agent_errors.h
    ./inc/agent_telemetry_counters.h
    ./inc/agent_telemetry_provider.h
    ./inc/authentication_manager.h
    ./inc/certificate_manager.h
    ./inc/consts.h
    ./inc/internal/internal_memory_monitor.h
    ./inc/internal/time_utils_consts.h
    ./inc/internal/time_utils.h
    ./inc/iothub_adapter.h
    ./inc/json/json_array_reader.h
    ./inc/json/json_array_writer.h
    ./inc/json/json_defs.h
    ./inc/json/json_object_reader.h
    ./inc/json/json_object_writer.h
    ./inc/local_config.h
    ./inc/logger.h
    ./inc/memory_monitor.h
    ./inc/message_schema_consts.h
    ./inc/message_serializer.h
    ./inc/os_utils/system_logger.h
    ./inc/queue.h
    ./inc/scheduler_thread.h
    ./inc/security_agent.h
    ./inc/synchronized_queue.h
    ./inc/tasks/event_monitor_task.h
    ./inc/tasks/event_publisher_task.h
    ./inc/tasks/update_twin_task.h
    ./inc/twin_configuration_consts.h
    ./inc/twin_configuration_defs.h
    ./inc/twin_configuration_event_collectors.h
    ./inc/twin_configuration_utils.h
    ./inc/twin_configuration.h
    ./inc/utils.h
)

# This is the linux collectors
set(agent_collectors_c_file
    ./src/collectors/agent_configuration_error_collector.c
    ./src/collectors/agent_telemetry_collector.c
    ./src/collectors/diagnostic_event_collector.c
    ./src/collectors/event_aggregator.c
    ./src/collectors/linux/baseline_collector.c
    ./src/collectors/linux/connection_create_collector.c
    ./src/collectors/linux/firewall_collector.c
    ./src/collectors/linux/generic_audit_event.c
    ./src/collectors/linux/generic_event.c
    ./src/collectors/linux/listening_ports_collector.c
    ./src/collectors/linux/local_users_collector.c
    ./src/collectors/linux/process_creation_collector.c
    ./src/collectors/linux/system_information_collector.c
    ./src/collectors/linux/user_login_collector.c
)

set(agent_collectors_h_file
    ./inc/collectors/agent_configuration_error_collector.h
    ./inc/collectors/agent_telemetry_collector.h
    ./inc/collectors/connection_create_collector.h
    ./inc/collectors/diagnostic_event_collector.h
    ./inc/collectors/event_aggregator.h
    ./inc/collectors/firewall_collector.h
    ./inc/collectors/generic_event.h
    ./inc/collectors/linux/baseline_collector.h
    ./inc/collectors/linux/generic_audit_event.h
    ./inc/collectors/listening_ports_collector.h
    ./inc/collectors/local_users_collector.h
    ./inc/collectors/process_creation_collector.h
    ./inc/collectors/system_information_collector.h
    ./inc/collectors/user_login_collector.h
)

set(agent_os_utils_c_file
    ./src/os_utils/linux/audit/audit_control.c
    ./src/os_utils/linux/audit/audit_search_record.c
    ./src/os_utils/linux/audit/audit_search_utils.c
    ./src/os_utils/linux/audit/audit_search.c
    ./src/os_utils/linux/correlation_manager.c
    ./src/os_utils/linux/file_utils.c
    ./src/os_utils/linux/groups_iterator.c
    ./src/os_utils/linux/iptables/iptables_def.c
    ./src/os_utils/linux/iptables/iptables_ip_utils.c
    ./src/os_utils/linux/iptables/iptables_iprange.c
    ./src/os_utils/linux/iptables/iptables_iterator.c
    ./src/os_utils/linux/iptables/iptables_multiport.c
    ./src/os_utils/linux/iptables/iptables_port_utils.c
    ./src/os_utils/linux/iptables/iptables_rules_iterator.c
    ./src/os_utils/linux/iptables/iptables_utils.c
    ./src/os_utils/linux/listening_ports_iterator.c
    ./src/os_utils/linux/os_utils.c
    ./src/os_utils/linux/process_info_handler.c
    ./src/os_utils/linux/process_utils.c
    ./src/os_utils/linux/system_logger.c
    ./src/os_utils/linux/users_iterator.c
)

set(agent_os_utils_h_file
    ./inc/os_utils/correlation_manager.h
    ./inc/os_utils/file_utils.h
    ./inc/os_utils/groups_iterator.h
    ./inc/os_utils/linux/audit/audit_control.h
    ./inc/os_utils/linux/audit/audit_search_record.h
    ./inc/os_utils/linux/audit/audit_search_utils.h
    ./inc/os_utils/linux/audit/audit_search.h
    ./inc/os_utils/linux/iptables/iptables_def.h
    ./inc/os_utils/linux/iptables/iptables_ip_utils.h
    ./inc/os_utils/linux/iptables/iptables_iprange.h
    ./inc/os_utils/linux/iptables/iptables_iterator.h
    ./inc/os_utils/linux/iptables/iptables_multiport.h
    ./inc/os_utils/linux/iptables/iptables_port_utils.h
    ./inc/os_utils/linux/iptables/iptables_rules_iterator.h
    ./inc/os_utils/linux/iptables/iptables_utils.h
    ./inc/os_utils/listening_ports_iterator.h
    ./inc/os_utils/os_utils.h
    ./inc/os_utils/process_info_handler.h
    ./inc/os_utils/process_utils.h
    ./inc/os_utils/system_logger.h
    ./inc/os_utils/users_iterator.h
)

add_executable(ASCIoTAgent
    ${agent_c_files}
    ${agent_h_files}
    ${agent_collectors_c_file}
    ${agent_collectors_h_file}
    ${agent_os_utils_c_file}
    ${agent_os_utils_h_file}
)

set_target_properties(ASCIoTAgent PROPERTIES COMPILE_DEFINITIONS _DEFAULT_SOURCE)

IF(CMAKE_BUILD_TYPE MATCHES RELEASE)
    set_property(TARGET ASCIoTAgent PROPERTY POSITION_INDEPENDENT_CODE TRUE)
endif()

if(use_amqp)
    target_link_libraries(ASCIoTAgent iothub_client_amqp_transport uamqp)
    add_definitions(-DUSE_AMQP)
endif()

if(use_mqtt)
    target_link_libraries(ASCIoTAgent iothub_client_mqtt_transport umqtt)
    add_definitions(-DUSE_MQTT)
endif()

target_link_libraries(ASCIoTAgent
    audit
    auparse
    iothub_client_http_transport
    iothub_client
    aziotsharedutil
    uuid
    pthread
    ssl
    crypto
    m
    ip4tc
)

add_custom_command(
        TARGET ASCIoTAgent POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/agent/config/LocalConfiguration.json
                ${CMAKE_BINARY_DIR}/agent/LocalConfiguration.json
        
        # add install directory
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_BINARY_DIR}/agent/ASCIoTAgent
                ${CMAKE_BINARY_DIR}/agent/Install/ASCIoTAgent
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/agent/config/LocalConfiguration.json
                ${CMAKE_BINARY_DIR}/agent/Install/LocalConfiguration.json
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/installation/InstallSecurityAgent.sh
                ${CMAKE_BINARY_DIR}/agent/Install/InstallSecurityAgent.sh
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/installation/ASCIoTAgent.service
                ${CMAKE_BINARY_DIR}/agent/Install/ASCIoTAgent.service        
                )
