# Broadband CM HAL Documentation

## Acronyms

- `HAL` \- Hardware Abstraction Layer
- `RDK-B` \- Reference Design Kit for Broadband Devices
- `OEM` \- Original Equipment Manufacture

## Description

The diagram below describes a high-level software architecture of the Broadband CM HAL module stack.

![Broadband CM HAL Architecture Diag](images/broadband_cm_hal_architecture.png)

Broadband CM HAL is an abstraction layer implemented to abstract the underlying Cable Modem hardware and interact with the underlying vendor software through a standard set of APIs. CM HAL provides interfaces for integrating WAN interfaces with RDK-B. CM related parameters are fetched through CM HAL APIs. Mainly CcspCMAgent, GW provisioning processes are linked to CM HAL.

## Component Runtime Execution Requirements

### Initialization and Startup

The below mentioned APIs initialize the Broadband CM HAL layers/code. Broadband CM client module should call the mentioned APIs initially during bootup/initialization.

- `cm_hal_InitDB()`

3rd party vendors will implement appropriately to meet operational requirements. This interface is expected to block if the hardware is not ready.


## Threading Model

The interface is not thread safe.

Any module which is invoking the API should ensure calls are made in a thread safe manner.

Vendors can create internal threads/events to meet their operation requirements.  These should be responsible to synchronize between the calls, events and cleaned up on closure.

## Process Model

All API's are expected to be called from multiple process.

## Memory Model

The client is responsible to allocate and de-allocate memory for necessary APIs as specified in API documentation.
Different 3rd party vendors allowed to allocate memory for internal operational requirements. In this case 3rd party implementations should be responsible to de-allocate internally.

TODO:
State a footprint requirement. Example: This should not exceed XXXX KB.

## Power Management Requirements

The HAL is not involved in any of the power management operation.
Any power management state transitions MUST not affect the operation of the HAL.

## Asynchronous Notification Model

There are no asynchronous notifications.

## Blocking calls

The APIs are expected to work synchronously and should complete within a time period commensurate with the complexity of the operation and in accordance with any relevant Broadband CM specification. Any calls that can fail due to the lack of a response from connected device should have a timeout period in accordance with any API documentation.
The upper layers will call this API from a single thread context, this API should not suspend.

TODO:
As we state that they should complete within a time period, we need to state what that time target is, and pull it from the spec if required. Define the timeout requirement.

## Internal Error Handling

All the Broadband CM HAL APIs should return error synchronously as a return argument. HAL is responsible to handle system errors(e.g. out of memory) internally.

## Persistence Model

There is no requirement for HAL to persist any setting information. The caller is responsible to persist any settings related to Broadband CM feature.


## Nonfunctional requirements

Following non functional requirement should be supported by the component.

## Logging and debugging requirements

The component should log all the error and critical informative messages, preferably using syslog, printf which helps to debug/triage the issues and understand the functional flow of the system.

The logging should be consistent across all HAL components.

If the vendor is going to log then it has to be logged in `xxx_vendor_hal.log` file name which can be placed in `/rdklogs/logs/` or `/var/tmp/` directory.

Logging should be defined with log levels as per Linux standard logging.


## Memory and performance requirements

The component should not contributing more to memory and CPU utilization while performing normal Broadband CM operations and commensurate with the operation required.


## Quality Control

Broadband CM HAL implementation should pass checks using any third party tools like `Coverity`, `Black duck`, `Valgrind` etc. without any issue to ensure quality.

There should not be any memory leaks/corruption introduced by HAL and underneath 3rd party software implementation.

## Licensing

Broadband CM HAL implementation is expected to released under the Apache License 2.0.

## Build Requirements

The source code should be able to be built under Linux Yocto environment and should be delivered as a shared library `libcm_mgnt.so`

## Variability Management

Changes to the interface will be controlled by versioning, vendors will be expected to implement to a fixed version of the interface, and based on SLA agreements move to later versions as demand requires.

Each API interface will be versioned using [Semantic Versioning 2.0.0](https://semver.org/), the vendor code will comply with a specific version of the interface.

## Platform or Product Customization

None

## Interface API Documentation

All HAL function prototypes and datatype definitions are available in `cm_hal.h` file.
1.  Components/Processes must include `cm_hal.h` to make use of Broadband CM HAL capabilities
2.  Components/Processes must include linker dependency for `libcm_mgnt`.

## Theory of operation and key concepts

Covered as per "Description" sections in the API documentation.

## Sequence Diagram

```mermaid
sequenceDiagram
participant Caller
participant CM HAL
participant Vendor
Note over Caller: Init once during bootup, Needed for Dependent API's. <br> Ignore this if caller doesn't have any Dependent API's
Caller->>CM HAL: cm_hal_InitDB()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_InitDB() return

Caller->>CM HAL: docsis_InitXXXX()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_InitXXXX() return

Caller->>CM HAL: docsis_getXXXX()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_getXXXX() return

Caller->>CM HAL: docsis_XXXXMddIpModeOverride()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_XXXXMddIpModeOverride() return

Caller->>CM HAL: docsis_XXXXUSChannelId()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_XXXXUSChannelId() return

Caller->>CM HAL: docsis_XXXXFreq()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_XXXXFreq() return

Caller->>CM HAL: docsis_XXXXLogItems()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_XXXXLogItems() return

Caller->>CM HAL: cm_hal_XXXXDHCPInfo()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_XXXXDHCPInfo() return

Caller->>CM HAL: cm_hal_GetXXXX()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_GetXXXX() return

Caller->>CM HAL: cm_hal_SetXXXX()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_SetXXXX() return

Caller->>CM HAL: cm_hal_Reboot_Ready/cm_hal_HTTPXXXX()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_Reboot_Ready/cm_hal_HTTPXXXX() return

Caller->>CM HAL: cm_hal_FWupdateAndFactoryReset/cm_hal_ReinitMac()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_FWupdateAndFactoryReset/cm_hal_ReinitMac() return

Caller->>CM HAL: docsis_LLDgetEnableStatus()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_LLDgetEnableStatus() return

Caller->>CM HAL: cm_hal_snmpv3_kickstart_initialize()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: cm_hal_snmpv3_kickstart_initialize() return

Caller->>CM HAL: docsis_IsEnergyDetected()
CM HAL->>Vendor: 
Vendor ->>CM HAL: 
CM HAL->>Caller: docsis_IsEnergyDetected() return
```
