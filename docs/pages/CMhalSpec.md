# CM HAL Documentation

## Version History


| Date | Comment | Version |
| --- | --- | --- |
| 2024-06-10 | Initial release. Cable Modem HAL header migrated to GitHub. | 1.0.0 |
| 2024-06-20 | Fixing Syntax Errors | 1.0.1 |
| 2026-08-24 | Specification rewritten to the canonical RDK-B HAL topic set: every declared function named in `API Surface`, the asynchronous-notification and device-management claims are corrected against `include/cm_hal.h`, and the placeholder identifiers in the sequence diagram are replaced with declared ones. | 1.0.1 |


## Acronyms

The expansions below cover the terms this document uses. Interface terminology follows `include/cm_hal.h`.

- `ACS`\- Auto Configuration Server
- `ANSC` \- Adaptive Network Security Configuration
- `API` \- Application Programming Interface
- `BPI` \- Baseline Privacy Interface, the `DOCSIS` link-layer security protocol
- `CA` \- Certificate Authority
- `CBC` \- Cipher Block Chaining
- `CLI` \- Command Line Interface
- `CM` \- Cable Modem
- `CM HAL` \- Cable Modem Hardware Abstraction Layer, the interface this document specifies
- `CMTS` \- Cable Modem Termination System, the head-end a modem registers with
- `CPE` \- Customer Premises Equipment 
- `DHCP` \- Dynamic Host Configuration Protocol
- `DOCSIS` \- Data Over Cable Service Interface Specification
- `DS` \- Downstream, the direction from the network toward the modem
- `DSG` \- Downstream Service Group
- `DSOFDM` \- Downstream Orthogonal Frequency Division Multiplexing
- `HAL` \- Hardware Abstraction Layer
- `HTTP` \- Hypertext Transfer Protocol
- `IP` \- Internet Protocol
- `IPv4` \- Internet Protocol version 4
- `IPv6` \- Internet Protocol version 6
- `LED` \- Light Emitting Diode, the indicator the download path flashes
- `LKF` \- Low-Level Kernel Filtering
- `LLD` \- Low Latency DOCSIS
- `LPA` \- Local Profile Assistant
- `MAC` \- Media Access Control
- `MDD` \- MAC Domain Descriptor
- `MIB` \- Management Information Base
- `NCP` \- Network Control Protocol
- `OFDM` \- Orthogonal Frequency Division Multiplexing
- `OFDMA` \- Orthogonal Frequency Division Multiple Access
- `OSA` \- Open Systems Architecture
- `PHY` \- Physical layer
- `PLC` \- PHY Link Channel
- `QoS` \- Quality of Service
- `RDK-B` \- Reference Design Kit for Broadband
- `SCDMA` \- Synchronous Code Division Multiple Access
- `SNMP` \- Simple Network Management Protocol
- `SNR` \- Signal-to-Noise Ratio
- `TFTP` \- Trivial File Transfer Protocol
- `ToD` \- Time of Day
- `TLV` \- Type-Length-Value
- `UCD` \- Upstream Channel Descriptor
- `URL` \- Uniform Resource Locator
- `US` \- Upstream, the direction from the modem toward the network
- `USG` \- Upstream Service Group
- `USOFDMA` \- Upstream Orthogonal Frequency Division Multiple Access
- `WAN` \- Wide Area Network

## Description

The `CM HAL` (Cable Modem Hardware Abstraction Layer) module provides a standardized interface for managing and interacting with cable modems within the Reference Design Kit (RDK) environment. It acts as a bridge between higher-level applications and the underlying cable modem hardware, abstracting the complexities of different DOCSIS (Data Over Cable Service Interface Specification) versions and cable modem implementations.

**Key functionalities of the `CM HAL` include:**

- **Device Management:** Initializing and deinitializing the cable modem, managing its operational status (online/offline), and retrieving device information (e.g., model, firmware version).
- **DOCSIS Operations:** Configuring and managing `DOCSIS` channels and parameters, retrieving downstream and upstream channel information, and obtaining DOCSIS-related statistics.
Network Configuration: Setting and retrieving network parameters, such as IP addresses, subnet masks, and default gateways for the cable modem.
- **Event Notifications:** Providing notifications to applications about changes in the cable modem's operational status, channel configurations, or other relevant events.
- **Diagnostics:** Offering tools for diagnosing and troubleshooting issues with the cable modem, including retrieving error logs and signal quality information.
By abstracting the complexities of `DOCSIS` and cable modem hardware, the `CM HAL` simplifies the development of applications that rely on cable modem connectivity within the RDK ecosystem. It provides a consistent and reliable way to interact with cable modems across different platforms and configurations, facilitating seamless integration of cable modem capabilities into `RDK-B` devices.

The diagram below describes a high-level software architecture of the Broadband CM HAL module stack.

```mermaid

flowchart   
    stack["CcspCMAgent\n`RDKB Stack`"] --> contract["cm_hal.h\n`RDKB Contract`"];
    contract --> vendor_library["libcm_mgnt.so\n`Vendor-Delivery`"];
    vendor_library --> Vendor_Software;
    style stack fill:#0088ff;
    style contract fill:#0088ff;
    style vendor_library fill:#00ffee;
    style Vendor_Software fill:#00ffee;
```

**What this interface declares**, taken from the 51 function prototypes and the callback typedef in `include/cm_hal.h`:

- **Initialization:** `cm_hal_InitDB()` brings up the `HAL` and its dependencies; `docsis_InitDS()` and `docsis_InitUS()` prepare the downstream and upstream `PHY` layers and direct hardware access. 
- **Status and registration:** The modem's `DOCSIS` status as a formatted string, and the registration detail behind it: scanning, ranging, `TFTP` config-file download, data registration, `ToD` synchronisation, `BPI` state and network access.
- **Channel information and statistics:** Downstream and upstream channel parameters, active channel counts, error codeword counts, and the `DOCSIS 3.1` `DSOFDM` and `USOFDMA` channel and status tables.
- **Channel and frequency control:** The upstream channel identifier, the primary downstream start frequency and the `MDD` `IP` provisioning-mode override. With the `HTTP` download settings and the `MAC` re-initialisation threshold, these are the only values this interface lets a caller write.
- **Addressing information, read-only:** `DHCP` and `IPv6` `DHCP` information and the `CPE` list are retrieved, never set. **This interface declares no setter for an `IP` address, a subnet mask or a default gateway**; a caller that must change addressing does so outside this interface.
- **Firmware download and recovery:** `HTTP` download configuration, initiation and status polling, `LED` flashing during a download, reboot readiness, reboot, firmware update with factory reset, and `MAC`-layer re-initialisation with its threshold.
- **Diagnostics and identity:** The `DOCSIS` event log, certificate file path and status, four reset counters, market region, `SNMP` v3 kickstart initialisation and `DOCSIS` energy detection.
- **Asynchronous notification"** One callback, for diplexer variation - see `Asynchronous Notification Model`.

The interface is layered rather than monolithic: a caller may stay at the level of "is the modem online" through `docsis_getCMStatus()`, or descend to per-channel `DOCSIS 3.1` statistics, without changing how it links against the `HAL`. `API Surface` is the complete index of what is available at either level.

## Component Runtime Execution Requirements

This interface is delivered as a shared library the caller links against, and its lifetime is the lifetime of the calling process. The requirements in this block are the ones a caller can rely on and a vendor implementation must meet; each states the source it is taken from, which is either `include/cm_hal.h` or this specification's own statement of policy for the `CM HAL`.

### Initialization and Startup

During initialization and startup, the Broadband CM client module is required to invoke the following APIs in sequence:

- `cm_hal_InitDB()` - initializes the `HAL` and its dependencies. Its documented failure cases are the failure to create threads or to open files.
- `docsis_InitDS()` - prepares the global `PHY`-level data structures and direct hardware access for the downstream (`DS`) direction.
- `docsis_InitUS()` - the same for the upstream (`US`) direction.

`cm_hal_InitDB()` is expected to block if the hardware is not ready. It is the one exception to the non-blocking requirement stated under `Blocking calls`, and it is the reason a caller should perform initialization on a thread whose progress nothing else depends on.

Initialization is mandatory before any other operation: the `HAL` must be initialized before a caller reads status, configures channels or registers a notification handler. Nothing in `include/cm_hal.h` returns a distinct code for "not initialized", so a caller must not attempt to detect the condition from a return value - it must enforce the order itself.

### Threading Model

The interface is not required to be thread safe.

Vendors can implement internal threading and event mechanisms for operational purposes. These mechanisms must ensure thread safety when interacting with the provided interface. Additionally, they must guarantee cleanup of resources upon closure.

The consequence for a caller is concrete: two threads must not call into this interface concurrently unless the caller serialises them itself. **This interface does not specify which thread the diplexer variation callback is invoked on**, so a handler must serialise its own access to caller state rather than assume it runs on the registering thread.

### Process Model

This module is expected to be called from multiple process.

The requirement is to ensure that the module can handle concurrent calls effectively. The vendor needs to implement proper synchronization and scalability measures for robust performance.

### Memory Model

#### Caller Responsibilities

- Callers must assume full responsibility for managing any memory explicitly given to the module functions to populate. This includes proper allocation and de-allocation to prevent memory leaks.
- All strings used in this module must be zero-terminated. This ensures that string functions can accurately determine the length of the string and prevents buffer overflows when manipulating strings.
- Where the interface fixes a minimum buffer size, `include/cm_hal.h` states it on the declaration and the caller must honour it.
- Five functions invert the usual direction and hand back memory the **caller** must release: `docsis_GetDSChannel()` and `docsis_GetUSChannel()` return a dynamically allocated structure, and `docsis_GetDsOfdmChanTable()`, `docsis_GetUsOfdmaChanTable()` and `docsis_GetStatusOfdmaUsTable()` return a dynamically allocated array whose length they report through their entry-count argument. Failing to free these is a leak in the caller, not in the `HAL`.

#### Module Responsibilities

- Modules must allocate and de-allocate memory for their internal operations, ensuring efficient resource management.
- Modules are required to release all internally allocated memory upon closure to prevent resource leaks.
- All module implementations and caller code must strictly adhere to these memory management requirements for optimal performance and system stability. Unless otherwise stated specifically in the API documentation.

That final escape clause is not decorative: it is what the five caller-frees functions above rely on, and it is why a caller reads each declaration's own documentation in `include/cm_hal.h` before assuming who owns a buffer. Where the header says the caller must provide a pre-allocated structure - as it does for `docsis_GetDOCSISInfo()`, `docsis_GetErrorCodewords()`, `cm_hal_GetDHCPInfo()` and `cm_hal_GetIPv6DHCPInfo()` - the module allocates nothing on the caller's behalf.

### Power Management Requirements

 **This interface specifies no participation in power management.** A caller must not assume that the `HAL` is notified of a power-state transition, and must not treat any function here as a way to request one; the functions that come closest are recovery operations rather than power controls - `cm_hal_HTTP_Download_Reboot_Now()` reboots the device and `cm_hal_FWupdateAndFactoryReset()` updates firmware and resets to factory defaults, both described under `API Surface`.

### Asynchronous Notification Model

This interface declares exactly one asynchronous notification, and it is the diplexer variation callback. `cm_hal_DiplexerVariationCallback` is documented as the "type of the handler the CM HAL invokes when the diplexer settings change", which "the implementation invokes ... when the modem's diplexer band edges change", and it is installed by `cm_hal_Register_DiplexerVariationCallback()`.

Four properties of it bind a caller, all stated by the header:

- **Registration is one-way.** "The registered callback cannot be removed and should be provided during initialization." There is no unregister function, so a caller installs the handler once, during startup, and the handler must remain valid for the lifetime of the process.
- **The handler receives the settings by value.** It is passed a `CM_DIPLEXER_SETTINGS` structure holding the upstream and downstream diplexer upper band edges in `MHz`, so there is no lifetime question about the data itself.
- **The handler returns a status.** `RETURN_OK` on successful processing of the settings, `RETURN_ERR` on error - for example a failure to handle the settings change.
- **Registration may legitimately fail.** `RETURN_ERR` covers "not supported/implemented", including a stub implementation, which is why `Optional Components` treats the whole diplexer facility as optional.

### Blocking calls

The APIs are expected to work synchronously and should complete within a time period commensurate with the complexity of the operation and in accordance with any relevant Broadband CM specification. Any calls that can fail due to the lack of a response from connected device should have a timeout period in accordance with any API documentation.
This API is called from a single thread context, therefore it must not suspend.

Two departures from that rule are stated by the interface itself and are the ones a caller must plan around:

- `cm_hal_InitDB()` is expected to block if the hardware is not ready, as `Initialization and Startup` records.
- `docsis_ClearDocsisEventLog()` carries the opposite obligation in the other direction: the header states that the function "must not block or use blocking system calls", and describes the clearing as asynchronous, likely by sending a message to a driver event handler. A caller therefore has no completion signal for it beyond its return code.

### Internal Error Handling

**Synchronous Error Handling:** All Broadband CM HAL APIs must return errors synchronously as a return value. This ensures immediate notification of errors to the caller.

**Internal Error Reporting:** The HAL is responsible for reporting any internal system errors (e.g., out-of-memory conditions) through the return value.

**Focus on Logging for Errors:** For system errors, the HAL should prioritize logging the error details for further investigation and resolution. Recovery attempts at the interface level are not expected to be successful in these cases.

**The vocabulary is deliberately narrow, and a caller must read the return type before reading the return value.** `include/cm_hal.h` defines `RETURN_OK` as `0` and `RETURN_ERR` as `-1`, and most declarations here report only those two, so a caller learns that an operation failed but not why. Three shapes exist and they are not interchangeable:

| Return shape | Declarations | What a caller does with it |
| --- | --- | --- |
| A status code | 45 of the 51 declarations, plus the callback | Compare against `RETURN_OK` and `RETURN_ERR`. The reason for a failure is not reported; the header's own per-function text names the usual causes - null pointers, allocation failure, retrieval error - but the code does not distinguish them. |
| A value, not a status | `docsis_GetUSChannelId()` returns the channel identifier, `docsis_GetDownFreq()` returns the frequency, `docsis_GetDocsisEventLogItems()` returns the number of log entries it retrieved, and `cm_hal_Get_HTTP_Download_Status()` returns a download progress or error value | There is no error code to test. `docsis_GetDocsisEventLogItems()` is the well-behaved case: a count of zero is a meaningful answer. `cm_hal_Get_HTTP_Download_Status()` is the one value return that names its own failures, in the `400` - `407` and `500` range documented in `cm_hal.h`, and `0` means "not started" rather than "succeeded". For the remaining two the interface defines no sentinel, so a caller cannot distinguish a failed read from a genuine value and should treat the surrounding state as its only evidence. |
| Nothing at all | `docsis_SetUSChannelId()` and `docsis_SetStartFreq()` are declared `void` | The write cannot be confirmed through the call. A caller that must know whether it took effect reads the value back with `docsis_GetUSChannelId()` or `docsis_GetDownFreq()`. |

`docsis_LLDgetEnableStatus()` is the one function returning a three-way result: `ENABLE`, `DISABLE` or `RETURN_ERR`. Because `DISABLE` also covers a missing bootfile entry, only `RETURN_ERR` indicates a failed read.

### Persistence Model

There is no requirement for the HAL to persist any setting information.

That statement bounds the `HAL`, not the modem. Two consequences follow, and neither is resolved by `include/cm_hal.h`: **the interface does not state whether a value written through it survives a reboot** - the upstream channel identifier, the primary downstream start frequency, the `MAC` re-initialisation threshold and the `HTTP` download settings are all written without any documented persistence guarantee - and the values it reads from the modem's own provisioning, such as the `LLD` bootfile entry read by `docsis_LLDgetEnableStatus()`, are persisted by the provisioning system rather than by this interface. A caller that needs a setting to be durable must re-apply it after a restart.

## Non functional requirements

Following non functional requirement should be supported by the component. Each topic below states whether what it requires comes from this specification's own policy or from `include/cm_hal.h`.

### Logging and debugging requirements

The component is required to record all errors and critical informative messages to aid in identifying, debugging, and understanding the functional flow of the system. Logging should be implemented using the syslog method, as it provides robust logging capabilities suited for system-level software. The use of `printf` is discouraged unless `syslog` is not available.

All HAL components must adhere to a consistent logging process. When logging is necessary, it should be performed into the `cm_vendor_hal.log` file, which is located in the `/rdklogs/logs/` directory.

Logs must be categorized according to the following log levels, as defined by the Linux standard logging system, listed here in descending order of severity:

- **FATAL**: Critical conditions, typically indicating system crashes or severe failures that require immediate attention.
- **ERROR**: Non-fatal error conditions that nonetheless significantly impede normal operation.
- **WARNING**: Potentially harmful situations that do not yet represent errors.
- **NOTICE**: Important but not error-level events.
- **INFO**: General informational messages that highlight system operations.
- **DEBUG**: Detailed information typically useful only when diagnosing problems.
- **TRACE**: Very fine-grained logging to trace the internal flow of the system.

Each log entry should include a timestamp, the log level, and a message describing the event or condition. This standard format will facilitate easier parsing and analysis of log files across different vendors and components.

Logging carries more weight in this interface than in one with a richer error vocabulary: as `Internal Error Handling` records, most declarations report only `RETURN_OK` or `RETURN_ERR`, so the vendor log is where the reason for a failure has to be found.

### Memory and performance requirements

The component should not contributing more to memory and CPU utilization while performing normal Broadband CM operations and commensurate with the operation required.

**No memory footprint limit is specified for this interface.** Neither `include/cm_hal.h` nor this specification states a maximum resident size, a heap budget or a `CPU` share, so a vendor implementation is held to the proportionality requirement above rather than to a number. Where a caller needs a bound - on a memory-constrained platform, for instance - it must be agreed with the vendor outside this interface. The one memory obligation this interface does state precisely is ownership, under `Memory Model`.

### Quality Control

To maintain software quality, it is recommended that the CM HAL implementation is verified without any errors using third-party tools such as Coverity, Black Duck, Valgrind, etc.

Both HAL wrapper and 3rd party software implementations should prioritize robust memory management to guarantee leak-free and corruption-resistant operation.

### Licensing

Broadband CM HAL implementation is expected to released under the Apache License 2.0.

The full licence text is in `LICENSE`, with attribution in `NOTICE` and the copyright statement in `COPYING`; all three are linked into `docs/pages/` so the generated documentation carries them.

### Build Requirements

The source code should be capable of, but not be limited to, building under the Yocto distribution environment. The recipe should deliver a shared library named as `libcm_mgnt.so`.

A caller of that library:

1. must include `cm_hal.h` to make use of Broadband `CM HAL` capabilities;
2. must include a linker dependency for `libcm_mgnt`.

`libcm_mgnt.so` and the Yocto recipe are the only build artefacts this repository names; it declares no build manifest, no toolchain version and no compiler flag, so nothing further is stated here.

### Variability Management

The role of adjusting the interface, guided by versioning, rests solely within architecture requirements. Thereafter, vendors are obliged to align their implementation with a designated version of the interface. As per Service Level Agreement (`SLA`) terms, they may transition to newer versions based on demand needs.

Each API interface will be versioned using [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), the vendor code will comply with a specific version of the interface.


### Platform or Product Customization

**This interface defines no compile-time customization flags.** 

Product variation is instead expressed at runtime, and a caller reads it rather than compiling for it:

- `cm_hal_GetMarket()` reports the market region the modem is built for, for example `EURO` for Europe or `US` for the United States - a value whose spelling collides with the upstream abbreviation and means the country here.
- `docsis_GetDOCSISInfo()` reports the `DOCSIS` version the modem implements, which is what decides whether the `DOCSIS 3.1` tables under `Optional Components` have anything to return.
- `cm_hal_get_DiplexerSettings()` reports the diplexer band edges, which differ between regional plant designs.
- `docsis_LLDgetEnableStatus()` reports whether the modem's bootfile provisions Low Latency DOCSIS.


## Interface API Documentation

All `HAL` function prototypes and datatype definitions are available in the `cm_hal.h` file, grouped there as `CM_HAL_TYPES` for the data types and `CM_HAL_APIS` for the functions. The topics below describe how the interface is meant to be driven, index every declaration in it, and then show one complete exchange and the modem states a caller can observe. `Build Requirements` states what to include and link against.

### Theory of operation and key concepts

#### Object Lifecycles

- **Creation/Initialization:** The CM HAL interface is initialized using the `cm_hal_InitDB()` function. This function sets up the necessary database connections and initializes various subsystems required for further operations with the cable modem. The downstream and upstream `PHY` layers are then prepared by `docsis_InitDS()` and `docsis_InitUS()`.
- **Usage:** After initialization, the cable modem can be managed using various API functions that rely on the initialized state. These functions allow for configuring and querying modem parameters, managing downstream and upstream channels, handling events, and controlling operational states.
- **Destruction/Cleanup:** The CM HAL interface does not provide a specific function for system deinitialization. Applications are responsible for managing and freeing resources manually to prevent memory leaks - in particular the five allocations listed under `Caller Responsibilities` - and cleanup within the `HAL` is generally handled internally upon application termination. A caller cannot release and re-acquire the interface within one process, because there is nothing to release it with; the registered diplexer callback is bound by the same limitation, as `Asynchronous Notification Model` records.

#### Method Sequencing

- **Initialization is Mandatory:** The system must be initialized (`cm_hal_InitDB()`) before any other operations are performed. This ensures that all subsystems are properly configured.
- **Sequential Dependency:** While most functions can be called independently once initialization is complete, some operations logically depend on the state of the modem or previous API calls (e.g., configuring channels before retrieving channel-specific data).
- **Event Handling:** Functions such as `cm_hal_Register_DiplexerVariationCallback()` allow for dynamic event handling and should be set up early in the application lifecycle if needed, because the registration cannot be undone.
- **Write-then-read for the `void` setters:** `docsis_SetUSChannelId()` and `docsis_SetStartFreq()` report nothing, so a caller that needs confirmation reads the value back afterwards. `Internal Error Handling` gives the full return-shape breakdown.
- **Configure-then-start for a download:** the `HTTP` path is a sequence rather than a single call - set the `URL` and filename, optionally set the interface, initiate the download, then poll its status, and only then check reboot readiness and reboot.

#### State-Dependent Behavior

- **Implicit State Model:** The CM HAL interface operates under several implicit states:
  - **Uninitialized:** Before any initialization function has been called.
  - **Initialized:** The system has been initialized but may not yet be fully operational or connected to network services.
  - **Operational:** The modem is fully operational, and all functionality is available.
  - **Error states:** Various functions may return errors if the system is not in an appropriate state for the requested operation.
- **The modem's own state is observable but not controlled here.** `docsis_getCMStatus()` reports where the modem has reached in `DOCSIS` bring-up and `docsis_GetDOCSISInfo()` reports the same progress field by field; `State Diagram` tabulates both value sets and, because this interface states no transition model over them, draws no edges between them. A caller reads those values and polls for a change; the only sequence it can drive is the initialization order above, and the recovery operations - `cm_hal_ReinitMac()`, `cm_hal_HTTP_Download_Reboot_Now()` and `cm_hal_FWupdateAndFactoryReset()` - state no resulting modem status of their own.

### Data Structures and Defines

A caller of this interface constructs or interprets the types below. Every one is declared in `include/cm_hal.h` under the `CM_HAL_TYPES` group, and the field-level documentation is on the declaration itself; the tables here name each type, say where it is declared and what it represents, and leave the members to the header.

**Type aliases** \- Each is wrapped in `#ifndef`, so a caller that already defines the name keeps its own definition. They are what the function signatures in `API Surface` are written in.

| Alias | Underlying type |
| --- | --- |
| `CHAR` | `char` |
| `UCHAR` | `unsigned char` |
| `BOOLEAN` | `unsigned char` |
| `USHORT` | `unsigned short` |
| `UINT8` | `unsigned char` |
| `INT` | `int` |
| `UINT` | `unsigned int` |
| `LONG` | `long` |
| `ULONG` | `unsigned long` |

**Status and boolean constants** \- `Internal Error Handling` gives the semantics.

| Constant | Value | Represents |
| --- | --- | --- |
| `RETURN_OK` | `0` | Success, returned by the status-returning declarations. |
| `RETURN_ERR` | `-1` | Failure. The interface reports no reason alongside it. |
| `TRUE`, `FALSE` | `1`, `0` | The two values a `BOOLEAN` field or out-parameter carries. |
| `ENABLE`, `DISABLE` | `1`, `0` | The enablement result of `docsis_LLDgetEnableStatus`, which returns one of these or `RETURN_ERR`. |

**Bounds and the address type** \- the constants a caller sizes buffers and tables against.

| Constant | Represents |
| --- | --- |
| `OFDM_PARAM_STR_MAX_LEN` | Maximum length of an `OFDM` parameter string, `64`. |
| `IPV4_ADDRESS_SIZE` | Octets in an `IPv4` address, `4`. |
| `ANSC_IPV4_ADDRESS` | A macro expanding to an anonymous union of a `4`-octet array in dotted-decimal order and a `32`-bit value in network byte order. It is the type of the upgrade-server address in `CMMGMT_CM_DOCSIS_INFO` and of the addresses in the `DHCP` information structures. |
| `EVM_MAX_EVENT_TEXT` | Maximum length of the event text in `CMMGMT_CM_EventLogEntry_t`, `255`. |
| `MAX_KICKSTART_ROWS` | Maximum number of rows in `snmpv3_kickstart_table_t`, `5`. |


**Structures.** Seventeen are declared. The `Represents` column is the declaration's own summary.

| Structure | Represents |
| --- | --- |
| `CMMGMT_CM_DS_CHANNEL` | A downstream channel: identifier, frequency, power level, `SNR`, modulation, octet and error counts, and lock status. |
| `CMMGMT_CM_US_CHANNEL` | An upstream channel: identifier, frequency, transmit power, channel type, symbol rate, modulation and lock status. |
| `CMMGMT_CM_DOCSIS_INFO` | `DOCSIS`-related information for the modem: the registration progression tabulated under `State Diagram`, the config file name, attempt counters, `ToD` status, `BPI` state, network access, upgrade-server address, `CPE` allowance, upstream and downstream service-flow parameters including `QoS`, data rates and core version. |
| `CMMGMT_CM_ERROR_CODEWORDS` | Codeword error statistics: unerrored, correctable and uncorrectable counts. |
| `CMMGMT_CM_EventLogEntry_t` | One entry of the modem's event log: index, first and last timestamps, occurrence count, level, identifier and text. |
| `CMMGMT_DML_CM_LOG` | Configuration settings for modem logging. |
| `CMMGMT_DML_DOCSISLOG_FULL`| A single entry within a `DOCSIS` log. |
| `CMMGMT_CM_DHCP_INFO` | The modem's `DHCP` configuration. |
| `CMMGMT_CM_IPV6DHCP_INFO` | The modem's `IPv6` `DHCP` configuration. |
| `CMMGMT_DML_CPE_LIST` | A single `CPE` entry. |
| `DOCSIF31_CM_DS_OFDM_CHAN` | Parameters of a `DOCSIS 3.1` `OFDM` downstream channel. |
| `DOCSIF31_CM_US_OFDMA_CHAN` | Parameters of a `DOCSIS 3.1` `OFDMA` upstream channel. |
| `DOCSIF31_CMSTATUSOFDMA_US` | Status information for a `DOCSIS 3.1` `OFDMA` upstream channel, including its ranging state and whether the channel is muted. |
| `fixed_length_buffer_t` | A buffer of fixed length: a `USHORT` byte count and a pointer to the data. |
| `snmp_kickstart_row_t` | One row of an `SNMP` v3 kickstart configuration: a security name and a security number, each a `fixed_length_buffer_t`. |
| `snmpv3_kickstart_table_t` | An `SNMP` v3 kickstart configuration table: a row count and up to `MAX_KICKSTART_ROWS` row pointers. |
| `CM_DIPLEXER_SETTINGS` | Diplexer frequency settings: the upstream and downstream upper band edges in `MHz`. This is the structure the notification handler receives. |

**The callback typedef.** `cm_hal_DiplexerVariationCallback` is the one handler type this interface defines. It is installed by `cm_hal_Register_DiplexerVariationCallback`, it receives a `CM_DIPLEXER_SETTINGS` structure by value, and it returns `RETURN_OK` or `RETURN_ERR`. There is no matching unregister function; `Asynchronous Notification Model` states the obligations that follow.

### API Surface

This topic is the boundary between the two ways of reading this document. Everything above answers "what is this interface and how do I drive it"; from here on the document answers "exactly what is declared, and what happens when it fails". All **51** functions this interface declares are named below by exact identifier, grouped by functional area, mirroring the `CM_HAL_APIS` group in the header. Every one of them is declared in [include/cm_hal.h](../../include/cm_hal.h).

**Initialization \- 3 functions.** The sequence `Initialization and Startup` requires, in that order.

| API | Purpose |
| --- | --- |
| `cm_hal_InitDB` | Initializes the `HAL` and its dependencies; may block if the hardware is not ready. |
| `docsis_InitDS` | Initializes the downstream `PHY` layer and direct hardware access. |
| `docsis_InitUS` | Initializes the upstream `PHY` layer and direct hardware access. |

**Modem and DOCSIS status \- 2 functions.** The fast answer, and the detailed one behind it.

| API | Purpose |
| --- | --- |
| `docsis_getCMStatus` | Retrieves and formats the modem's `DOCSIS` status into a caller-supplied buffer of at least `40` bytes; the value set is enumerated under `State Diagram`. |
| `docsis_GetDOCSISInfo` | Retrieves the current `DOCSIS` registration status into a caller-allocated `CMMGMT_CM_DOCSIS_INFO` structure. |

**Channel information \- 5 functions.** Per-channel parameters and how many channels are in use.

| API | Purpose |
| --- | --- |
| `docsis_GetDSChannel` | Retrieves downstream channel information in a structure the `HAL` allocates and the caller frees. |
| `docsis_GetUsStatus` | Retrieves the status of one upstream channel, selected by index, into a caller-supplied structure. |
| `docsis_GetUSChannel` | Retrieves upstream channel information in a structure the `HAL` allocates and the caller frees. |
| `docsis_GetNumOfActiveTxChannels`| Reads how many upstream channels the current registration is using. |
| `docsis_GetNumOfActiveRxChannels` | Reads how many downstream channels the current registration is using. |

**DOCSIS 3.1 OFDM and OFDMA tables \- 3 functions.** Each allocates an array and reports its length; the caller frees it. `Optional Components` explains why the array may be empty.

| API | Purpose |
| --- | --- |
| `docsis_GetDsOfdmChanTable` | Retrieves the `DSOFDM` channel table as an allocated array of `DOCSIF31_CM_DS_OFDM_CHAN` entries. |
| `docsis_GetUsOfdmaChanTable` | Retrieves the `USOFDMA` channel table as an allocated array of `DOCSIF31_CM_US_OFDMA_CHAN` entries. |
| `docsis_GetStatusOfdmaUsTable` | Retrieves the `USOFDMA` channel status table as an allocated array of `DOCSIF31_CMSTATUSOFDMA_US` entries. |

**Channel and frequency control \- 4 functions.** The only pair in this interface where a setter reports nothing and its getter returns a bare value; `Internal Error Handling` and `Method Sequencing` both turn on that fact.

| API | Purpose |
| --- | --- |
| `docsis_GetUSChannelId` | Returns the upstream channel identifier within its `MAC` domain as a `UINT8` value, not a status code. |
| `docsis_SetUSChannelId` | Sets the upstream channel identifier within its `MAC` domain. Declared `void`, so it reports nothing. |
| `docsis_GetDownFreq` | Returns the current primary downstream channel frequency as a `ULONG` value, not a status code. |
| `docsis_SetStartFreq` | Sets the primary downstream channel frequency. Declared `void`, so it reports nothing. |

**Provisioning, MDD override and certificates \- 5 functions.** How the modem is provisioned with an `IP` mode, and the state of its certificate.

| API | Purpose |
| --- | --- |
| `docsis_GetMddIpModeOverride` | Reads the current `IP` provisioning-mode override status. |
| `docsis_SetMddIpModeOverride` | Sets the `IP` provisioning-mode override status. |
| `docsis_GetProvIpType` | Reads the provisioned `IP` type for the `WAN` interface. |
| `docsis_GetCert` | Reads the file path of the modem certificate. |
| `docsis_GetCertStatus`| Reads the modem certificate status. |

**Diagnostics: error codewords and event log \- 3 functions.**

| API | Purpose |
| --- | --- |
| `docsis_GetErrorCodewords` | Scans the active downstream channels and reports packet errors into a caller-allocated structure. |
| `docsis_GetDocsisEventLogItems` | Fills a caller-supplied array with up to a given number of event-log entries and **returns the number of entries retrieved**, not a status code. |
| `docsis_ClearDocsisEventLog` | Clears the event log asynchronously. The header requires this function not to block or use blocking system calls. |

**DHCP, CPE and market information \- 4 functions.** All read-only; see the addressing bullet under `Description`.

| API | Purpose |
| --- | --- |
| `cm_hal_GetDHCPInfo` | Reads the modem's `DHCP` information into a structure the caller allocates and frees. |
| `cm_hal_GetIPv6DHCPInfo` | Reads the modem's `IPv6` `DHCP` information into a structure the caller allocates and frees. |
| `cm_hal_GetCPEList` | Reads the list of connected `CPE` devices and their count; the caller allocates and frees both the list and the mode string, which is `router` or `bridge` and at most `100` bytes. |
| `cm_hal_GetMarket` | Reads the modem's market region, for example `EURO` for Europe or `US` for the United States. |

**HTTP firmware download \- 8 functions.** A configure-then-start-then-poll sequence rather than one call, as `Method Sequencing` describes.

| API | Purpose |
| --- | --- |
| `cm_hal_Set_HTTP_Download_Url` | Configures the download `URL` and image filename. Both buffers must be at least `200` bytes. |
| `cm_hal_Get_HTTP_Download_Url` | Reads back the configured download `URL` and filename, under the same buffer requirement. |
| `cm_hal_Set_HTTP_Download_Interface` | Selects the interface the download is to use. |
| `cm_hal_Get_HTTP_Download_Interface` | Reads back the interface the download is configured to use. |
| `cm_hal_HTTP_Download` | Initiates the download. |
| `cm_hal_Get_HTTP_Download_Status`| Reads the current download status; this is the interface's progress mechanism, in place of a notification. |
| `cm_hal_HTTP_Download_Reboot_Now` | Initiates a reboot, performing pre-reboot checks and updates. |
| `cm_hal_HTTP_LED_Flash` | Controls flashing of the `HTTP` `LED` indicator. |

**Reboot, factory reset and MAC re-initialization \- 5 functions.** The recovery operations, and the threshold that governs the automatic one. `cm_hal_FWupdateAndFactoryReset` takes a firmware location, so the firmware download safety requirements stated above the previous table bind it as well, and bind it more tightly.

| API | Purpose |
| --- | --- |
| `cm_hal_Reboot_Ready` | Reports whether the system is ready for a reboot. |
| `cm_hal_FWupdateAndFactoryReset` | Initiates a firmware update from a given `URL` and image name, followed by a factory reset. |
| `cm_hal_ReinitMac` | Resets the modem's `MAC` layer while preserving its channels. |
| `cm_hal_set_ReinitMacThreshold` | Sets the threshold at which `MAC`-layer re-initialization is triggered. |
| `cm_hal_get_ReinitMacThreshold` | Reads the `MAC`-layer re-initialization threshold. |

**Reset counters \- 4 functions.** Four separately maintained counters; the interface declares no way to clear them.

| API | Purpose |
| --- | --- |
| `cm_hal_Get_CableModemResetCount` | Reads how many times the modem has been reset. |
| `cm_hal_Get_LocalResetCount` | Reads how many of those resets were local. |
| `cm_hal_Get_DocsisResetCount` | Reads how many were `DOCSIS`-related. |
| `cm_hal_Get_ErouterResetCount` | Reads how many times the eRouter has been reset. |

**Security, energy detection and diplexer \- 5 functions.** Includes the interface's only notification registration.

| API | Purpose |
| --- | --- |
| `cm_hal_snmpv3_kickstart_initialize` | Initializes `SNMP` v3 security parameters from a kickstart table. |
| `docsis_IsEnergyDetected` | Reports whether `DOCSIS` energy is present, which is how a caller decides whether the `WAN` is connected. |
| `docsis_LLDgetEnableStatus` | Reports whether Low Latency `DOCSIS` is enabled, returning `ENABLE`, `DISABLE` or `RETURN_ERR`. |
| `cm_hal_get_DiplexerSettings` | Reads the current diplexer band-edge settings. |
| `cm_hal_Register_DiplexerVariationCallback` | Registers the handler invoked when the diplexer settings change. The registration cannot be undone, and `RETURN_ERR` may mean the platform does not implement the facility. |

The twelve groups hold `3`, `2`, `5`, `3`, `4`, `5`, `3`, `4`, `8`, `5`, `4` and `5` functions, which is `51` in total - every function the header declares, each named once. The callback type the last group registers is described under `Data Structures and Defines`.

### Sequence Diagram

The exchange below is the path `Method Sequencing` describes, with the three participants a `C` `HAL` has: the caller, the interface, and the vendor software behind it. Every function named is a declared identifier in `include/cm_hal.h`; where a step has a getter and a setter, both are named rather than abbreviated.

```mermaid
sequenceDiagram
participant Caller
participant CM HAL
participant Vendor

Note over Caller,CM HAL: Initialization Process
Caller->>CM HAL: cm_hal_InitDB()
CM HAL->>Vendor: Initialize database and dependencies
Vendor ->>CM HAL: Initialization complete
CM HAL->>Caller: RETURN_OK

Note over Caller,CM HAL: DOCSIS Initialization
Caller->>CM HAL: docsis_InitDS()
CM HAL->>Vendor: Initialize the downstream PHY layer
Vendor ->>CM HAL: Downstream initialized
CM HAL->>Caller: RETURN_OK
Caller->>CM HAL: docsis_InitUS()
CM HAL->>Vendor: Initialize the upstream PHY layer
Vendor ->>CM HAL: Upstream initialized
CM HAL->>Caller: RETURN_OK

Note over Caller,CM HAL: Notification registration, once and for the process lifetime
Caller->>CM HAL: cm_hal_Register_DiplexerVariationCallback(handler)
CM HAL->>Caller: RETURN_OK, or RETURN_ERR where unimplemented

Note over Caller,CM HAL: Normal Operation
Caller->>CM HAL: docsis_getCMStatus()
CM HAL->>Vendor: Read the modem registration state
Vendor ->>CM HAL: Status string
CM HAL->>Caller: RETURN_OK with the status buffer filled
Caller->>CM HAL: docsis_GetDOCSISInfo()
Caller->>CM HAL: docsis_GetDSChannel(), docsis_GetUSChannel()
CM HAL->>Caller: Allocated channel structures the caller must free
Caller->>CM HAL: docsis_GetNumOfActiveRxChannels(), docsis_GetNumOfActiveTxChannels()
Caller->>CM HAL: docsis_GetDsOfdmChanTable(), docsis_GetUsOfdmaChanTable(), docsis_GetStatusOfdmaUsTable()
Caller->>CM HAL: cm_hal_GetDHCPInfo(), cm_hal_GetIPv6DHCPInfo(), cm_hal_GetCPEList()
Caller->>CM HAL: docsis_GetErrorCodewords(), docsis_GetDocsisEventLogItems()
CM HAL->>Caller: Entry count returned directly, not a status code

Note over Caller,CM HAL: Provisioning override and channel control
Caller->>CM HAL: docsis_SetMddIpModeOverride()
CM HAL->>Vendor: Apply the IP provisioning mode override
Vendor ->>CM HAL: Applied
CM HAL->>Caller: RETURN_OK
Caller->>CM HAL: docsis_SetUSChannelId(), docsis_SetStartFreq()
CM HAL->>Vendor: Apply the channel identifier and start frequency
Caller->>CM HAL: docsis_GetUSChannelId(), docsis_GetDownFreq()
CM HAL->>Caller: Values read back, since the setters report nothing

Note over Caller,CM HAL: Energy detection
Caller->>CM HAL: docsis_IsEnergyDetected()
CM HAL->>Vendor: Detect DOCSIS energy
Vendor ->>CM HAL: Energy detection result
CM HAL->>Caller: RETURN_OK with the result flag set

Note over Caller,CM HAL: Firmware download and reboot
Caller->>CM HAL: cm_hal_Set_HTTP_Download_Url(), cm_hal_Set_HTTP_Download_Interface()
Caller->>CM HAL: cm_hal_HTTP_Download()
CM HAL->>Vendor: Start the image transfer
Caller->>CM HAL: cm_hal_HTTP_LED_Flash()
Caller->>CM HAL: cm_hal_Get_HTTP_Download_Status()
CM HAL->>Caller: Download progress, polled rather than pushed
Caller->>CM HAL: cm_hal_Reboot_Ready()
CM HAL->>Caller: RETURN_OK with the readiness flag set
Caller->>CM HAL: cm_hal_HTTP_Download_Reboot_Now()

Note over Caller,CM HAL: Recovery paths
Caller->>CM HAL: cm_hal_FWupdateAndFactoryReset()
CM HAL->>Vendor: Update firmware and reset to factory defaults
Caller->>CM HAL: cm_hal_set_ReinitMacThreshold()
Caller->>CM HAL: cm_hal_ReinitMac()
CM HAL->>Vendor: Reset the MAC layer, preserving channels
Vendor ->>CM HAL: Reinitialization done
CM HAL->>Caller: RETURN_OK

Note over Caller,CM HAL: SNMPv3 kickstart
Caller->>CM HAL: cm_hal_snmpv3_kickstart_initialize()
CM HAL->>Vendor: Initialize SNMPv3 security parameters
Vendor ->>CM HAL: SNMPv3 initialized
CM HAL->>Caller: RETURN_OK

Note over Caller,CM HAL: Asynchronous notification
Vendor ->>CM HAL: Diplexer settings change
CM HAL->>Caller: Registered handler invoked with CM_DIPLEXER_SETTINGS
Caller->>CM HAL: cm_hal_get_DiplexerSettings()
```

This is one path, not the whole interface. The declarations it does not walk - `docsis_GetUsStatus`, `docsis_GetProvIpType`, `docsis_GetCert`, `docsis_GetCertStatus`, `cm_hal_GetMarket`, `cm_hal_Get_HTTP_Download_Url`, `cm_hal_Get_HTTP_Download_Interface`, `cm_hal_get_ReinitMacThreshold`, `docsis_ClearDocsisEventLog`, `docsis_LLDgetEnableStatus`, `cm_hal_Get_CableModemResetCount`, `cm_hal_Get_LocalResetCount`, `cm_hal_Get_DocsisResetCount` and `cm_hal_Get_ErouterResetCount` - are queries a caller makes when it needs them rather than steps in a sequence, and every one of them is indexed under `API Surface`, which is the complete list.

### State Diagram

Two state vocabularies exist here and they are not the same thing. The interface's **own** lifecycle is short and *is* established by `include/cm_hal.h`, which chains the three initializers by pre-condition and post-condition. The **modem's** `DOCSIS` status is longer, is reported rather than driven, and is **not** a state machine: the declaration of `docsis_getCMStatus` states that "this interface reports these values but specifies neither which transitions between them are legal nor in what order they occur, so a caller must not infer a state machine from the list" (`cm_hal.h`). This topic therefore draws the first and tabulates the second.

**The `HAL` lifecycle, which the interface does establish.** Each edge below is a documented pre-condition or post-condition, not an inference: `cm_hal_InitDB` is a pre-condition of every other operation and no other function may be called before it returns `RETURN_OK`, on success `docsis_InitDS` may be called , `docsis_InitDS` requires `cm_hal_InitDB` to have returned `RETURN_OK`, and `docsis_InitUS` requires the same and completes the mandatory sequence, after which `cm_hal_InitDB`'s own contract leaves every other function callable.

```mermaid
stateDiagram-v2
    [*] --> Uninitialized
    Uninitialized --> DbInitialized : cm_hal_InitDB() returns RETURN_OK
    DbInitialized --> DsInitialized : docsis_InitDS() returns RETURN_OK
    DsInitialized --> FullyInitialized : docsis_InitUS() returns RETURN_OK
    FullyInitialized
```

`cm_hal_ReinitMac` **is deliberately not drawn as a transition.** It resets the modem's `MAC` layer while preserving the downstream and upstream channels; it does not de-initialize the `HAL`, so it moves no state on the diagram above. Nor does it establish a destination in the modem's vocabulary: its post-condition states that **this interface states no point at which the modem is usable again and provides no readiness notification, so a caller polls `docsis_getCMStatus`**, and on failure the `MAC` layer's state is explicitly unknown - the same post-condition records that the interface does not state what state the `MAC` layer is left. An edge would have to name a state the interface refuses to name.

**The modem's `DOCSIS` status is a value set, and no edges are drawn over it.** `docsis_getCMStatus` reports one of twenty-four zero-terminated strings, listed on its declaration. The declaration lists them without defining them individually, so the reading in the third column below is what each spelling names and nothing more; a caller that needs the phase itself defined takes that from the `DOCSIS` specification the modem implements, not from this interface. The interface defines no enumeration for these values, so a caller compares the buffer against these spellings exactly and **must tolerate a value it does not recognise rather than assume the set is closed**.

| Value | Group | What its spelling names |
| --- | --- | --- |
| `NOT_READY` | Bring-up | The modem is not yet ready. |
| `NOT_SYNCHRONIZED` | Bring-up | Downstream synchronisation has not been achieved. |
| `PHY_SYNCHRONIZED` | Bring-up | `PHY`-level synchronisation has been achieved. |
| `US_PARAMETERS_ACQUIRED` | Bring-up | The upstream parameters have been acquired. |
| `RANGING_COMPLETE` | Bring-up | Ranging has completed. |
| `DHCPV4_COMPLETE` | Bring-up | `DHCPv4` address acquisition has completed. |
| `DHCPV6_COMPLETE` | Bring-up | `DHCPv6` address acquisition has completed. Which of the two a modem reports depends on its provisioning mode, which `docsis_GetProvIpType` reads. |
| `TOD_ESTABLISHED` | Bring-up | Time of day has been established. |
| `SECURITY_ESTABLISHED` | Bring-up | Link-layer security has been established. |
| `CONFIG_FILE_DOWNLOAD_COMPLETE` | Bring-up | The configuration file has been downloaded. |
| `REGISTRATION_COMPLETE` | Bring-up | Registration has completed. |
| `OPERATIONAL` | Bring-up | The modem is operational. |
| `RANGING_IN_PROGRESS`, `DHCPV4_IN_PROGRESS`, `DHCPV6_IN_PROGRESS`, `REGISTRATION_IN_PROGRESS`, `EAE_IN_PROGRESS`, `DS_TOPOLOGY_RESOLUTION_IN_PROGRESS` | In progress | The named phase is under way rather than complete. Four of the six pair with a completion value above; early authentication and downstream topology resolution have no completion value in the set. |
| `BPI_INIT` | In progress | Baseline privacy initialization. |
| `ACCESS_DENIED` | Condition | Access was denied. |
| `FORWARDING_DISABLED` | Condition | Forwarding is disabled. |
| `RF_MUTE_ALL` | Condition | All `RF` transmission is muted. |
| `OTHER` | Not mapped | A state the implementation reports as none of the above. |
| `Unsupported status` | Not mapped | What an implementation reports for a state it cannot map onto the others. |


The same progress is readable field by field from `CMMGMT_CM_DOCSIS_INFO`, which `docsis_GetDOCSISInfo` fills. Each field takes one of the values named below, and **this interface states no transition model over them either**; the correspondence with the status values above is by phase name only, since the header states no mapping between the two.

| Field | Values it takes | Reports |
| --- | --- | --- |
| `DOCSISDownstreamScanning`, `DOCSISDownstreamRanging`, `DOCSISUpstreamScanning`, `DOCSISUpstreamRanging` | `NotStarted`, `InProgress`, `Complete` | Each of the four `PHY`-level bring-up phases, downstream then upstream. |
| `DOCSISTftpStatus` | `NotStarted`, `InProgress`, `DownloadComplete` | The configuration-file download; the file name lands in `DOCSISConfigFileName`. |
| `DOCSISDataRegComplete` | `InProgress`, `RegistrationComplete` | Data registration, the last phase named before the modem is operational. |
| `ToDStatus` | `NotStarted`, `Complete` | Time-of-day synchronisation. |
| `DOCSISDHCPAttempts`, `DOCSISTftpAttempts` | A count | How many attempts address acquisition and configuration download have taken. These are the only retry evidence the interface exposes. |

Two fields of that structure are **not** states and must not be read as a progression: `BPIState` and `NetworkAccess` are `BOOLEAN`, so they annotate whichever value the modem currently reports - whether link-layer privacy is established, and whether network access is permitted - rather than sitting in a sequence.