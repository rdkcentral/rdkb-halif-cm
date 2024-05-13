/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/*
 * The cm_hal module provides an interface for interacting with cable modems adhering to the DOCSIS (Data Over Cable Service Interface Specification) standard.
 *
 * For detailed information about DOCSIS 3.1, refer to the following specifications:
 * * Physical Layer Specification: https://account.cablelabs.com/server/alfresco/6f4e0e98-cea4-465b-af19-28b1143c3c4e
 * * Cable Modem Operations Support System Interface Specification: https://account.cablelabs.com/server/alfresco/3fb47021-ef6f-499f-a319-84fc2a0ccc0f
 */

#ifndef __CM_HAL_H__
#define __CM_HAL_H__
/*
 * TODO: Upgrade interface to support stdint
 */
#include <stdint.h>
#include <sys/time.h>

/**********************************************************************
               CONSTANT DEFINITIONS
**********************************************************************/
#define OFDM_PARAM_STR_MAX_LEN 64  /**< Maximum length of OFDM parameter */

#ifdef __cplusplus
extern "C"{
#endif


#ifndef CHAR
#define CHAR  char
#endif

#ifndef UCHAR
#define UCHAR unsigned char
#endif

#ifndef BOOLEAN
#define BOOLEAN  unsigned char
#endif

#ifndef USHORT
#define USHORT  unsigned short
#endif

#ifndef UINT8
/*
 * TODO: UINT8 is type uint8_t from stdint.h. Need to check if this is correct 
 */
#define UINT8 unsigned char
#endif

#ifndef INT
#define INT   int
#endif

#ifndef UINT
#define UINT  unsigned int
#endif

#ifndef LONG
#define LONG	long
#endif

#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef TRUE
#define TRUE     1
#endif

#ifndef FALSE
#define FALSE    0
#endif

#ifndef ENABLE
#define ENABLE   1
#endif

#ifndef DISABLE
#define DISABLE  0
#endif

/*
 * TODO: Move INT return codes to enum
 */
#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif

/**
 *
 * If the constant IPV4_ADDRESS_SIZE is not already defined, it is set to 4.
 * This ensures that the size of IPv4 addresses is standardized to 4 bytes throughout the code.
 */
#ifndef IPV4_ADDRESS_SIZE
#define  IPV4_ADDRESS_SIZE                          4
#endif

#ifndef ANSC_IPV4_ADDRESS
/* 
 *  TODO: IPV4 to IPV6 Transition
 *  - Many parts of the codebase still rely on IPv4 addresses for comparison and calculation.  
 *  - While transitioning to IPv6, it may be beneficial to refactor these areas to use a more flexible address representation that can handle both IPv4 and IPv6.
 */

#define ANSC_IPV4_ADDRESS \
    union { \
        /**!< Represents each octet (byte) of the IPv4 address in dotted-decimal format (e.g., {192, 168, 0, 100}). */
        unsigned char Dot[IPV4_ADDRESS_SIZE];  

        /**!< Stores the IPv4 address as a 32-bit integer in network byte order (big-endian). */
        uint32_t Value; 
    } 
#endif

/**
 * @defgroup CM_HAL Cable Modem HAL Interface
 * @brief Provides a standardized interface for interacting with cable modem hardware and software.
 *
 * This component enables communication between RDK-B (Reference Design Kit for Broadband) and cable modem implementations.
 *
 * @{
 * @defgroup CM_HAL_TYPES Data Types
 * @defgroup CM_HAL_APIS APIs
 * @}
 */

/**
 * @addtogroup CM_HAL_TYPES
 * @{
 */

/**********************************************************************
                STRUCTURE DEFINITIONS
**********************************************************************/

/**!< Represents a cable modem's downstream channel information. */
typedef struct _CMMGMT_CM_DS_CHANNEL {  
    ULONG ChannelID;  /**!< Unique channel identifier (typically sequential, starting at 1). */
    CHAR Frequency[64];   /**!< Channel's operating frequency (54 - 1002 MHz in DOCSIS 3.1). Example: "64400". */
    CHAR PowerLevel[64];  /**!< Channel power level (dBmV or similar). Typical range: -15 to +15 dBmV. Example: "-1.5". */   
    CHAR SNRLevel[64];    /**!< Channel signal-to-noise ratio (dB). DOCSIS 3.1 typical range: 20 - 40 dB. Example: "38". */ 
    CHAR Modulation[64];  /**!< Modulation type (e.g., "QPSK", "256-QAM", "1024-QAM", "OFDM"). */ 
    ULONG Octets;         /**!< Total octets received on this channel since reset (range depends on traffic). */
    ULONG Correcteds;     /**!< Count of corrected errors since reset (varies based on channel conditions). */  
    ULONG Uncorrectables; /**!< Count of uncorrectable errors since reset (high values indicate potential issues). */  
    CHAR LockStatus[64];  /**!< Channel lock status. Expected values: "Locked", "Unlocked", "Not Available". */   

} CMMGMT_CM_DS_CHANNEL, *CMMGMT_CM_DS_CHANNEL;
/* 
 * TODO: Coding Standard: 
 *  - Remove usage of `*PCMMGMT_CM_DS_CHANNEL` and `*PCMMGMT_CM_US_CHANNEL`.
 *  - Rename the struct to follow lowercase naming conventions (e.g., `cmgmt_cm_ds_channel`).
 */ 

/**!< Represents a cable modem's upstream channel information.  */
typedef struct _CMMGMT_CM_US_CHANNEL {
    ULONG ChannelID;      /**!< Unique channel identifier. */
    CHAR Frequency[64];   /**!< Upstream frequency (5 - 204 MHz). Example: "12750". */ 
    CHAR PowerLevel[64];  /**!< Transmit power level (45 - 61 dBmV). Example: "60". */
    CHAR ChannelType[64]; /**!< Channel type (e.g., "ATDMA", "SCDMA", "OFDMA"). */
    CHAR SymbolRate[64];  /**!< Symbol rate (symbols/second, varies with configuration). */
    CHAR Modulation[64];  /**!< Modulation type (up to "4096-QAM"). */
    CHAR LockStatus[64];  /**!< Lock status ("Locked" or "Unlocked"). */

} CMMGMT_CM_US_CHANNEL, *PCMMGMT_CM_US_CHANNEL;

/**!< Represents DOCSIS-related information for a cable modem. */
typedef struct _CMMGMT_CM_DOCSIS_INFO {
    CHAR DOCSISVersion[64];               /**!< DOCSIS version (e.g., "3.0", "3.1"). */
    CHAR DOCSISDownstreamScanning[64];    /**!< Downstream scanning status ("NotStarted", "InProgress", "Complete"). */
    CHAR DOCSISDownstreamRanging[64];     /**!< Downstream ranging status ("NotStarted", "InProgress", "Complete"). */
    CHAR DOCSISUpstreamScanning[64];      /**!< Upstream scanning status ("NotStarted", "InProgress", "Complete"). */
    CHAR DOCSISUpstreamRanging[64];       /**!< Upstream ranging status ("NotStarted", "InProgress", "Complete"). */
    CHAR DOCSISTftpStatus[64];            /**!< TFTP status for config download ("NotStarted", "InProgress", "DownloadComplete"). */
    CHAR DOCSISDataRegComplete[64];       /**!< Data registration status ("InProgress", "RegistrationComplete"). */
    ULONG DOCSISDHCPAttempts;             /**!< Number of DHCP attempts for IP acquisition (range depends on retries). */
    CHAR DOCSISConfigFileName[64];        /**!< Name of the downloaded DOCSIS config file. */ 
    ULONG DOCSISTftpAttempts;             /**!< Number of TFTP attempts for config download (range depends on retries). */
    CHAR ToDStatus[64];                   /**!< Time of Day sync status ("NotStarted", "Complete"). */
    BOOLEAN BPIState;                     /**!< Baseline Privacy Interface (BPI) security state (TRUE or FALSE). */
    BOOLEAN NetworkAccess;                /**!< Network access status for the modem (TRUE or FALSE). */
    ANSC_IPV4_ADDRESS UpgradeServerIP;    /**!< IP address of the firmware upgrade server. */
    ULONG MaxCpeAllowed;                  /**!< Maximum Customer Premises Equipment (CPE) allowed (typically 1 - 255). */
    CHAR UpstreamServiceFlowParams[64];   /**!< Upstream service flow parameters (including QoS). */
    CHAR DownstreamServiceFlowParams[64]; /**!< Downstream service flow parameters (including QoS). */
    CHAR DOCSISDownstreamDataRate[64];    /**!< Downstream data rate (bits per second, e.g., "10000"). */
    CHAR DOCSISUpstreamDataRate[64];      /**!< Upstream data rate (bits per second, e.g., "35000"). */
    CHAR CoreVersion[64];                 /**!< Modem firmware core version (e.g., "1.0"). */

} CMMGMT_CM_DOCSIS_INFO, *PCMMGMT_CM_DOCSIS_INFO; 

/**!< Represents codeword error statistics for a cable modem. */ 
typedef struct _CMMGMT_CM_ERROR_CODEWORDS {
    ULONG UnerroredCodewords;    /**!< Count of codewords received without detected errors. */
    ULONG CorrectableCodewords;  /**!< Count of codewords with errors that were corrected. */
    ULONG UncorrectableCodewords;/**!< Count of codewords with uncorrectable errors (indicating potential transmission issues). */
} CMMGMT_CM_ERROR_CODEWORDS, *PCMMGMT_CM_ERROR_CODEWORDS;
/**
 * TODO: Address the following within this code:
 *   - Correct capitalization in 'CMMGMT_CM_ERROR_CODEWORDS'.
 *   - Remove the redundant `*PCMMGMT_CM_ERROR_CODEWORDS` typedef.  
 */

#define EVM_MAX_EVENT_TEXT      255      /**< Maximum length of event text */

/**!< Represents a single entry within a cable modem's event log. */
typedef struct {
    UINT docsDevEvIndex;          /**!< Event index within the log (0 to UINT_MAX). */
    struct timeval docsDevEvFirstTime; /**!< Timestamp of the event's first occurrence. */
    struct timeval docsDevEvLastTime;  /**!< Timestamp of the event's most recent occurrence. */
    UINT docsDevEvCounts;         /**!< Total count of event occurrences (0 to UINT_MAX). */
    UINT docsDevEvLevel;          /**!< Event priority level (0 - 255). */
    UINT docsDevEvId;             /**!< Event identifier (0 to UINT_MAX). */
    CHAR docsDevEvText[EVM_MAX_EVENT_TEXT]; /**!< Textual description of the event. */

} CMMGMT_CM_EventLogEntry_t; 

/**!< Represents configuration settings for cable modem (CM) logging. */
typedef struct _CMMGMT_DML_CM_LOG {
    BOOLEAN EnableLog;      /**< Enables or disables cable modem logging. */
    BOOLEAN ClearDocsisLog; /**< Controls whether the DOCSIS log should be cleared. */

} CMMGMT_DML_CM_LOG, , *PCMMGMT_DML_CM_LOG;

/**
 * TODO: Address the following within this code:
 *   - Correct capitalization in 'CMMGMT_DML_CM_LOG'.
 *   - Remove the redundant `*PCMMGMT_DML_CM_LOG` typedef.  
 */

/**!< Represents a single entry within a DOCSIS log. */
typedef struct _CMMGMT_DML_DOCSISLOG_FULL {
    ULONG Index;         /**!< Index of the log entry within the full log. */
    ULONG EventID;       /**!< Unique identifier for the type of event logged. */   
    ULONG EventLevel;    /**!< Severity level of the event (e.g., error, warning, informational). */
    CHAR Time[64];       /**!< Timestamp of the event's occurrence. */
    CHAR Description[256];/**!< Textual description of the event. */

} CMMGMT_DML_DOCSISLOG_FULL, *PCMMGMT_DML_DOCSISLOG_FULL; 

/**
 * TODO: Correct CMMGMT_DML_DOCSISLOG_FULL, *PCMMGMT_DML_DOCSISLOG_FULL , no caps, and remove *PCMMGMT_DML_DOCSISLOG_FULL
 */

/**!< Represents a cable modem's DHCP configuration. */
typedef struct _CMMGMT_CM_DHCP_INFO {
    ANSC_IPV4_ADDRESS IPAddress;        /**!< IPv4 address assigned to the cable modem. */
    CHAR BootFileName[64];             /**!< Name of the boot configuration file. */
    ANSC_IPV4_ADDRESS SubnetMask;      /**!< Subnet mask for the modem's IP address. */
    ANSC_IPV4_ADDRESS Gateway;         /**!< Default gateway IP address. */
    ANSC_IPV4_ADDRESS TFTPServer;      /**!< IP address of the TFTP server. */
    CHAR TimeServer[64];               /**!< Hostname or IP of the time server. */
    INT TimeOffset;                    /**!< Time offset from UTC (in seconds). */
    ULONG LeaseTimeRemaining;          /**!< Remaining IP lease time (in seconds). */
    CHAR RebindTimeRemaining[64];      /**!< Remaining time for DHCP rebind (in seconds). */
    CHAR RenewTimeRemaining[64];       /**!< Remaining time for DHCP renewal (in seconds). */
    CHAR MACAddress[64];               /**!< Modem's MAC address (e.g., "00:1A:2B:11:22:33"). */
    CHAR DOCSISDHCPStatus[64];         /**!< Status of the DOCSIS DHCP process. */

} CMMGMT_CM_DHCP_INFO, *PCMMGMT_CM_DHCP_INFO; 

/**!< Represents a cable modem's IPv6 DHCP configuration. */
typedef struct _CMMGMT_CM_IPV6DHCP_INFO {
    CHAR IPv6Address[40];       /**!< IPv6 address assigned to the modem. */   
    CHAR IPv6BootFileName[64];  /**!< Name of the IPv6 boot configuration file. */
    CHAR IPv6Prefix[40];        /**!< IPv6 prefix assigned to the modem. */
    CHAR IPv6Router[40];        /**!< IPv6 address of the router. */
    CHAR IPv6TFTPServer[40];    /**!< IPv6 address of the TFTP server. */
    CHAR IPv6TimeServer[40];    /**!< IPv6 address or hostname of the time server. */
    ULONG IPv6LeaseTimeRemaining;  /**!< Remaining IPv6 lease time (in seconds). */  
    ULONG IPv6RebindTimeRemaining; /**!< Remaining time for IPv6 DHCP rebind (in seconds). */
    ULONG IPv6RenewTimeRemaining;  /**!< Remaining time for IPv6 DHCP renewal (in seconds). */

} CMMGMT_CM_IPV6DHCP_INFO, *PCMMGMT_CM_IPV6DHCP_INFO; 

/**!< Represents a single Customer Premises Equipment (CPE) entry. */
typedef struct _CMMGMT_DML_CPE_LIST {
    CHAR IPAddress[32];  /**< IP address of the CPE (e.g., "192.168.0.1"). */
    CHAR MACAddress[32]; /**< MAC address of the CPE (e.g., "AA:BB:CC:DD:EE:FF"). */

} CMMGMT_DML_CPE_LIST, *PCMMGMT_DML_CPE_LIST; 

/**
* @brief Represents parameters of a DOCSIS 3.1 OFDM downstream channel in a cable modem. 
* @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
*/ 
typedef struct _DOCSIF31_CM_DS_OFDM_CHAN {

    unsigned int ChannelId;           /**!< Downstream channel ID within a CMTS MAC interface. */
    unsigned int ChanIndicator;       /**!< Indicates channel role: primary (2), backup primary (3), non-primary (4). */
    unsigned int SubcarrierZeroFreq;  /**!< Center frequency (Hz) of subcarrier 0. */ 

    unsigned int FirstActiveSubcarrierNum; /**!< Index of the first non-excluded subcarrier (148 - 7895). */
    unsigned int LastActiveSubcarrierNum;  /**!< Index of the last non-excluded subcarrier (148 - 7895). */

    unsigned int NumActiveSubcarriers;   /**!< Count of active data subcarriers (excludes pilots, PLC). */ 

   /**! 
    * Max value depends on FFT mode (4K/8K) and subcarrier exclusions. 
    * See spec for details.
    */

    unsigned int SubcarrierSpacing;      /**!< Spacing between subcarriers (50 kHz for 4K mode, 25 kHz for 8K). */
    unsigned int CyclicPrefix;           /**!< Cyclic prefix length (in usec, multiple of 1/64 * 20us, see spec). */
    unsigned int RollOffPeriod;          /**!< Roll-off period (in usec, see spec for bandwidth/exclusion implications). */

    unsigned int PlcFreq;                /**!< Center frequency (Hz) of the PLC's lowest subcarrier. */
    unsigned int NumPilots;              /**!< Count of continuous pilots, from the OCD message. */
    unsigned int TimeInterleaverDepth;   /**!< Time interleaving depth, from the OCD message. */

    char averageSNR[OFDM_PARAM_STR_MAX_LEN];  /**!< Average downstream channel SNR. */
    char PowerLevel[OFDM_PARAM_STR_MAX_LEN];  /**!< Downstream channel power level (dBmV * 10). */

    unsigned long long PlcTotalCodewords;    /**!< Total PLC codewords received. */
    unsigned long long PlcUnreliableCodewords;/**!< PLC codewords failing LDPC syndrome check. */
    unsigned long long NcpTotalFields;       /**!< Total NCP fields received. */
    unsigned long long NcpFieldCrcFailures;  /**!< NCP fields failing CRC check. */

} DOCSIF31_CM_DS_OFDM_CHAN, *PDOCSIF31_CM_DS_OFDM_CHAN;

/**
* @brief Represents parameters of a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
* @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
*/ 
typedef struct _DOCSIF31_CM_US_OFDMA_CHAN {
    unsigned int ChannelId;         /**!< Upstream channel ID within a CMTS MAC interface. */
    unsigned int ConfigChangeCt;    /**!< Count of configuration changes (via the UCD message). */
    unsigned int SubcarrierZeroFreq;/**!< Lowest frequency (Hz) of the upstream channel. */

    unsigned int FirstActiveSubcarrierNum; /**!< Index of the first active subcarrier (range 74-3947). */
    unsigned int LastActiveSubcarrierNum;  /**!< Index of the last active subcarrier (range 74-3947). */
    unsigned int NumActiveSubcarriers;  /**!< Count of active data subcarriers (range 1-3800). */
    unsigned int SubcarrierSpacing;     /**!< Spacing between subcarriers (50 kHz for 2K, 25 kHz for 4K mode). */

    unsigned int CyclicPrefix;      /**!< Cyclic prefix length (in usec, see spec for values). */
    unsigned int RollOffPeriod;     /**!< Roll-off period (in usec, see spec for values). */

    unsigned int NumSymbolsPerFrame;/**!< Symbols per frame (bandwidth dependent, see spec). */
    unsigned int TxPower;           /**!< Transmit power level (quarter dBmV units, refer to PHYv3.1). */
    unsigned char PreEqEnabled;     /**!< Indicates if pre-equalization is enabled. */

} DOCSIF31_CM_US_OFDMA_CHAN, *PDOCSIF31_CM_US_OFDMA_CHAN; 

/**
* @brief Represents status information for a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
* @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
*/ 
typedef struct _DOCSIF31_CMSTATUSOFDMA_US {
    unsigned int ChannelId;        /**!< Upstream channel ID within a CMTS MAC interface. */
    unsigned int T3Timeouts;       /**!< Count of T3 timeout occurrences. */
    unsigned int T4Timeouts;       /**!< Count of T4 timeout occurrences. */
    unsigned int RangingAborteds;  /**!< Count of aborted ranging attempts. */
    unsigned int T3Exceededs;      /**!< Count of excessive T3 timeouts. */
    unsigned char IsMuted;         /**!< Indicates if the upstream channel is muted. */ 
    unsigned int RangingStatus;    /**!< Ranging state: other(1), aborted(2), retriesExceeded(3), success(4), continue(5), timeoutT4(6) */ 

} DOCSIF31_CMSTATUSOFDMA_US, *PDOCSIF31_CMSTATUSOFDMA_US;

#define MAX_KICKSTART_ROWS 5   /**<! Maximum number of rows of kickstart*/

/**!< Represents a buffer of fixed length. */
typedef struct _fixed_length_buffer {
    USHORT length;        /**< Size of the buffer in bytes. (Maximum: 65535) */ 
    UINT8 *buffer;        /**< Pointer to the buffer's data. */

} fixed_length_buffer_t; 

/**!< Represents a single row in an SNMPv3 kickstart configuration. */
typedef struct _snmpv3_kickstart_row {
    fixed_length_buffer_t security_name;     /**< Holds the SNMPv3 security name. */
    fixed_length_buffer_t security_number;   /**< Holds the SNMPv3 security number. */

} snmp_kickstart_row_t; 

/**!< Represents an SNMPv3 kickstart configuration table. */
typedef struct _snmpv3_kickstart_table {
    UINT8 n_rows;                                                /**< Number of rows in the table. */ 
    snmp_kickstart_row_t *kickstart_values[MAX_KICKSTART_ROWS];  /**< Array of SNMPv3 kickstart row entries. */

} snmpv3_kickstart_table_t; 

/**!< Represents diplexer frequency settings for a cable modem. */
typedef struct _CM_DIPLEXER_SETTINGS {
    UINT usDiplexerSetting; /**< Upstream diplexer upper band edge (MHz). */
    UINT dsDiplexerSetting; /**< Downstream diplexer upper band edge (MHz). */ 

} CM_DIPLEXER_SETTINGS; 

/** @} */  //END OF GROUP CM_HAL_TYPES


/**********************************************************************************
 *
 *  CM Subsystem level function prototypes
 *
**********************************************************************************/

/* 
 * TODO: Enhance Error Reporting 
 * - Replace the generic `RETURN_ERR` with a more informative error code enumeration.
 * - Define specific error codes for common failure scenarios, such as:
 *      - Invalid input parameters (e.g., null pointers, out-of-range values)
 *      - Resource allocation failures (e.g., out-of-memory)
 *      - Communication issues with hardware or external systems
 *      - Timeouts or unexpected responses
 *      - Internal module errors 
 * - Document the new error codes thoroughly, including their meanings and potential causes. 
 */

/**
 * @addtogroup CM_HAL_APIS
 * @{
 */

/**!
 * @brief Initializes the Hardware Abstraction Layer (HAL) and its dependencies.
 *
 * @returns Status of the initialization.
 * @retval RETURN_OK on successful initialization.
 * @retval RETURN_ERR on initialization failure, such as failure to create threads or open files.
 */ 
INT cm_hal_InitDB(void);

/**!
 * @brief Initializes the downstream (DS) PHY layer and hardware access.
 *
 * This function prepares the following for downstream communication:
 * - Global PHY-level data structures
 * - Direct access to the DS hardware
 *
 * @returns Status of the initialization.
 * @retval RETURN_OK on success. 
 */ 
INT docsis_InitDS(void);

/**!
 * @brief Initializes the upstream (US) PHY layer and hardware access.
 *
 * Prepares the following for upstream communication:
 * - Global PHY-level data structures
 * - Direct access to the US hardware 
 *
 * @returns Status of the initialization.
 * @retval RETURN_OK on success.
 */ 
INT docsis_InitUS(void);

/**!
 * @brief Retrieves and formats the Cable Modem's DOCSIS status.
 *
 * This function populates the provided buffer with a string representing the current DOCSIS status.
 *
 * @param[out] cm_status Pointer to a character array (at least 40 bytes) to hold the status string.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., retrieval error, memory allocation issue).
 *
 * TODO: cm_status must be updated to an enum. 
 * 
 * **Possible cm_status values:**
 * - "Unsupported status"
 * - "OTHER"
 * - "NOT_READY"
 * - "NOT_SYNCHRONIZED"
 * - "PHY_SYNCHRONIZED"
 * - "US_PARAMETERS_ACQUIRED"
 * - "RANGING_COMPLETE"
 * - "DHCPV4_COMPLETE"
 * - "TOD_ESTABLISHED"
 * - "SECURITY_ESTABLISHED"
 * - "CONFIG_FILE_DOWNLOAD_COMPLETE"
 * - "REGISTRATION_COMPLETE"
 * - "OPERATIONAL"
 * - "ACCESS_DENIED"
 * - "EAE_IN_PROGRESS"
 * - "DHCPV4_IN_PROGRESS"
 * - "DHCPV6_IN_PROGRESS"
 * - "DHCPV6_COMPLETE"
 * - "REGISTRATION_IN_PROGRESS"
 * - "BPI_INIT"
 * - "FORWARDING_DISABLED"
 * - "DS_TOPOLOGY_RESOLUTION_IN_PROGRESS"
 * - "RANGING_IN_PROGRESS"
 * - "RF_MUTE_ALL"
 */ 
INT docsis_getCMStatus(CHAR *cm_status); 

/**!
 * @brief Retrieves information about a downstream (DS) channel.
 *
 * This function populates a provided `PCMMGMT_CM_DS_CHANNEL` structure with downstream channel details. 
 *
 * **Important:** The caller is responsible for freeing the dynamically allocated memory of the returned structure.
 *
 * @param[out] ppinfo Pointer to a `PCMMGMT_CM_DS_CHANNEL` structure to be populated.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR on failure (e.g., retrieval error, memory allocation issue). 
 */
INT docsis_GetDSChannel(PCMMGMT_CM_DS_CHANNEL *ppinfo);

/**
* @brief Retrieve status of the upstream (US) channel information.
*
* @param[in]  i     - Index of the upstream channel. Valid range is from 0 to n, where n is an unsigned short value.
* @param[out] pinfo - Info of upstream channel to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs during the retrieval of upstream status or memory allocation fails.
*
*/
INT docsis_GetUsStatus(USHORT i, PCMMGMT_CM_US_CHANNEL pinfo);

/**!
 * @brief Retrieves information about an upstream (US) channel.
 *
 * This function populates a provided `PCMMGMT_CM_US_CHANNEL` structure with upstream channel details. 
 *
 * **Important:** The caller is responsible for freeing the dynamically allocated memory of the returned structure.
 *
 * @param[out] ppinfo - Pointer to a `PCMMGMT_CM_US_CHANNEL` structure to be populated.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., retrieval error, memory allocation issue).
 */
INT docsis_GetUSChannel(PCMMGMT_CM_US_CHANNEL *ppinfo);

/**!
 * @brief Retrieves the current DOCSIS registration status.
 *
 * This function populates a provided `PCMMGMT_CM_DOCSIS_INFO` structure with DOCSIS registration details. 
 *
 * **Important:** The caller must provide a pre-allocated `PCMMGMT_CM_DOCSIS_INFO` structure. The function does *not* manage memory allocation for this structure.
 *
 * @param[out] pinfo - Pointer to a `PCMMGMT_CM_DOCSIS_INFO` structure to be populated.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., retrieval error, invalid input).
 */
INT docsis_GetDOCSISInfo(PCMMGMT_CM_DOCSIS_INFO pinfo);

/**!
 * @brief Retrieves the number of active upstream channels in the current registration. 
 *
 * This function populates the provided variable with the count of active upstream channels. 
 *
 * @param[out] cnt - Pointer to an unsigned long variable to store the active channel count.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., retrieval error, NULL 'cnt' pointer).
 */
INT docsis_GetNumOfActiveTxChannels(ULONG *cnt); 

/**!
 * @brief Retrieves the number of active downstream channels in the current registration. 
 *
 * This function populates the provided variable with the count of active downstream channels. 
 *
 * @param[out] cnt - Pointer to an unsigned long variable to store the active channel count.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., retrieval error, NULL 'cnt' pointer).
 */
INT docsis_GetNumOfActiveRxChannels(ULONG *cnt); 

/**!
 * @brief Scans active downstream channels and reports packet errors.
 *
 * This function populates a provided `PCMMGMT_CM_ERROR_CODEWORDS` structure with error details.  
 *
 * **Important:** The caller must provide a pre-allocated `PCMMGMT_CM_ERROR_CODEWORDS` structure. The function does *not* manage memory allocation for this structure.
 *
 * @param[out] ppinfo - Pointer to a `PCMMGMT_CM_ERROR_CODEWORDS` structure to be populated with error information.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., scanning error, NULL 'ppinfo' pointer).
 */
INT docsis_GetErrorCodewords(PCMMGMT_CM_ERROR_CODEWORDS *ppinfo); 

/**
* @brief Retrieve the current IP Provisioning Mode Override status.
* @param[out] pValue Pointer to character array holding the current IP Provisioning Mode retrieved.
*                    \n Expected Values are "ipv4Only" , "ipv6Only" , "APM" , "DualStack" , "honorMdd" , "not defined".
*                    \n It is expected to return APM (2) and DualStack (3), but only ipv4Only(0) , ipv6Only (1) and hornorMdd (4).
*                    \n The maximum size allocated should be atleast 64 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, such as an invalid parameter or failure to retrieve the IP Provisioning Mode Override status.
*
*/
INT docsis_GetMddIpModeOverride(CHAR *pValue);

/**
* @brief Set the current IP Provisioning Mode Override status.
* @param[in] pValue Value that the IP Provisioning Mode is to be set to.
*                   \n Expected Values are ipv4Only (0), ipv6Only (1), APM (2), DualStack (3), honorMdd (4), ""
*                   \n It is possible to return APM (2) and DualStack (3), but only ipv4Only(0) , ipv6Only (1) and hornorMdd (4) can be set.
*                   \n The maximum size allocated should be atleast 64 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, such as an invalid parameter or failure to set the IP Provisioning Mode Override status.
*
*/
INT docsis_SetMddIpModeOverride(CHAR *pValue);

/**
* @brief Retrieve the Channel ID of the Upstream channel within its MAC (Media Access Control) domain.
*
* This function retrieves the Channel ID of the Upstream channel within its MAC domain, which refers to the network segment controlled by a single MAC address. The MAC domain encompasses the network devices, such as modems and routers, that share the same MAC address and communicate using the same protocols.
*
* @return UINT8 - Channel ID. It is a value between 0 and 255.
*
*/
UINT8 docsis_GetUSChannelId(void);

/**
* @brief Set the Channel ID of the Upstream channel within its MAC (Media Access Control) domain.
*
* This function sets the Channel ID of the Upstream channel within its MAC domain, which refers to the network segment controlled by a single MAC address. The MAC domain encompasses the network devices, such as modems and routers, that share the same MAC address and communicate using the same protocols.
*
* @param[in] index It is integer value which provides index to set the Upstream Channel ID to.
*
*/
void docsis_SetUSChannelId(INT index);

/**
* @brief Retrieve the current primary downstream (DS) channel frequency from the LKF (Low-Level Kernel Filtering) table.
*
* @return ULONG - channel frequency in Hertz.
*
*/
ULONG docsis_GetDownFreq(void);

/**
* @brief Set the current primary downstream (DS) channel frequency in the LKF (Low-Level Kernel Filtering) table.
* @param[in] value  It is an unsigned long value which provides primary channel frequency value that is to be set.
*
*/
void docsis_SetStartFreq(ULONG value);

/**
* @brief Retrieve the DOCSIS event log entries and display it.
* @param[out] *entryArray entries to be returned.
*
* @param[in] len Length of log entries.
*
* @return INT number of log entries retrieved.
*
*/
INT docsis_GetDocsisEventLogItems(CMMGMT_CM_EventLogEntry_t *entryArray, INT len);

/**
* @brief Clear the DOCSIS event log.
* This function must not suspend and must not invoke any blocking system calls. It should probably just send a message to a driver event handler task.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error is encountered during the operation, such as failure to set the event log clear entry.
*
*/
INT docsis_ClearDocsisEventLog(void);

/**
* @brief Retrieve all the relevant DHCP info for this CM.
* The caller is responsible for allocating memory for the pInfo structure before calling this function.
* The memory allocated for pInfo should be freed by the caller when it is no longer needed.
*
* @param[out] pInfo All DHCP info for CM, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if there are errors during the retrieval process, such as null pointer exceptions, failure in data acquisition from DHCP server, or internal processing errors.
*
*/
INT cm_hal_GetDHCPInfo(PCMMGMT_CM_DHCP_INFO pInfo);

/**
* @brief Retrieve all the relevant IPv6 DHCP info for this CM.
* The caller is responsible for allocating memory for the pInfo structure before calling this function.
* The memory allocated for pInfo should be freed by the caller when it is no longer needed.
*
* @param[out] pInfo All IPv6 DHCP info for CM, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if there are errors during the retrieval process, such as null pointer exceptions, failure in data acquisition from DHCP server, or internal processing errors.
*
*/
INT cm_hal_GetIPv6DHCPInfo(PCMMGMT_CM_IPV6DHCP_INFO pInfo);

/**
* @brief Retrieve list of CPEs connected to the CM.
* The caller is responsible for allocating memory for both the ppCPEList and LanMode parameters before calling this function.
* The memory allocated for the ppCPEList structure and LanMode string should be freed by the caller when they are no longer needed.
*
* @param[out] ppCPEList List of all CPE, to be returned.
*
* @param[out] InstanceNum Pointer to a variable that will hold the number of instances returned in the CPE list.
*                         The possibe range of acceptable values is 0 to (2^32)-1.
* @param[in]  LanMode     Input of "router" or "bridge" mode of the modem.
*                         \n The maximum size allocated should be atleast 100 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, including invalid input parameters, memory allocation failure, and failure in retrieving CPE results.
*
*/
INT cm_hal_GetCPEList(PCMMGMT_DML_CPE_LIST * ppCPEList, ULONG* InstanceNum, CHAR* LanMode);

/**
* @brief Retrieve the market region of this modem.
*
*This function retrieves the market region of the modem, indicating whether it belongs to the "US" (United States) or "EURO" (Europe) market.
*
* @param[out] market Pointer to the character array where the name of the market region will be stored.
*                    \n The maximum size allocated should be atleast 100 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, such as null pointers, insufficient buffer size, or failures in data retrieval, locking mechanisms, or during the synchronization process.
*
*/
INT cm_hal_GetMarket(CHAR* market);

/* HTTP Download HAL API Prototype */

/**
* @brief Set the configuration for HTTP downloads.
*
* This function sets the HTTP download configuration by specifying the HTTP download URL and filename to be stored in the HTTP download configuration file.
*
* @param[in] pHttpUrl HTTP download URL to be stored in the configuration file. 
*                     Example: "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[in] pfilename HTTP download filename to be stored in the configuration file. 
*                      Example: "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT"
*
* @return The status of the operation:
*         - RETURN_OK if the operation is successful.
*         - RETURN_ERR if any downloading is in process or the URL string is invalid.
*
* TODO: As pHttpUrl and pfilename are inputs, change it to 'const char'
*/

INT cm_hal_Set_HTTP_Download_Url (char* pHttpUrl, char* pfilename);

/**
* @brief Get Http Download Url.
* The memory for the buffers pHttpUrl and pFilename is expected to be pre-allocated by the caller.
* If the provided buffer size is smaller than required, the function may overwrite adjacent memory, leading to undefined behavior.
*
* @param[out] pHttpUrl  HTTP download URL fetched from HTTP download config file.
*                       \n The maximum size allocated should be atleast 200 bytes.
*                       \n Example: "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[out] pfilename HTTP download filename fetched from HTTP download config file.
*                       \n The maximum size allocated should be atleast 200 bytes.
*                       \n Example: "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT"
*
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if http url string is empty.
*
*
*/
INT cm_hal_Get_HTTP_Download_Url (char *pHttpUrl, char* pfilename);

/**
* @brief Set the HTTP Download Interface.
* @param[in] interface Interface numerical value to be saved to the config file.
*                      \n Possible values are interface=0 for wan0, interface=1 for erouter0.
*
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if invalid interface is passed.
*/
INT cm_hal_Set_HTTP_Download_Interface(unsigned int interface);

/**
* @brief Get the HTTP Download Interface
* @param[out] pinterface Interface numerical value to be fetched from the config file.
*                        \n Values: interface=0 for wan0, interface=1 for erouter0.
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, including invalid parameter passed and memory allocation failures.
*
*/
INT cm_hal_Get_HTTP_Download_Interface(unsigned int* pinterface);

/**
* @brief Start Http Download.
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if a download operation is already in progress.
*
*/
INT cm_hal_HTTP_Download ();

/**
* @brief Get the HTTP Download Status.
* @return the status of the HTTP Download.
* @retval 0 -   Download is not started.
* @retval 0-100 - Values of percent of download.
* @retval 200 - Download is completed and waiting for reboot.
* @retval 400 - Invalided Http server Url.
* @retval 401 - Cannot connect to Http server.
* @retval 402 - File is not found on Http server.
* @retval 403 - HW_Type_DL_Protection Failure.
* @retval 404 - HW Mask DL Protection Failure.
* @retval 405 - DL Rev Protection Failure.
* @retval 406 - DL Header Protection Failure.
* @retval 407 - DL CVC Failure.
* @retval 500 - General Download Failure.
*
*/
INT cm_hal_Get_HTTP_Download_Status();

/**
 * @brief Retrieves the reboot readiness status.
 *
 * This function retrieves the reboot readiness status and stores it in the provided integer pointer.
 * 
 * @param[out] pValue Pointer that holds the reboot readiness status.
 *                    1 for Ready, 2 for Not Ready
 *
 * @return The status of the operation.
 * @retval RETURN_OK if successful.
 * @retval RETURN_ERR if an error is detected during the operation, such as failure in retrieving operational status, EMTA (Embedded Multimedia Terminal Adapter) line status, or accessing required resources.
 */
INT cm_hal_Reboot_Ready(ULONG *pValue);

/**
* @brief Initiates a reboot operation after performing necessary checks and updates.
*
* This function creates a reboot file, retrieves information about the last reboot counter,
* updates the counter if necessary, and triggers a system reboot.
*
* @return the status of the reboot operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if the function fails to create the reboot file or encounters an error during the reboot process.
*/
INT cm_hal_HTTP_Download_Reboot_Now();

/**
* @brief Firmware update and factory reset the device.
* This function returns Success if reset happens successfully, else Error if there is any issue in initiating reset.
*
* @param[in] pUrl       Url for cm_hal_Set_HTTP_Download_Url. NULL for snmp.
*                         \n Example: "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[in] pImagename Imagename for cm_hal_Set_HTTP_Download_Url. NULL for snmp.
*                         \n Example: CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT
*
* @return the status of the Firmware update and factory reset operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any reboot is in process.
*
*/
INT cm_hal_FWupdateAndFactoryReset(char* pUrl, char* pImagename);

/**
* @brief Reinitializes the Cable Modem (CM) by reinitializing the Media Access Control (MAC) layer, preserving the existing downstream (DS) and upstream (US) channels.
*
* This function triggers a reinitialization of the MAC layer of the CM, ensuring that the current DS and US channels are retained.
*
* @return The status of the operation.
* @retval RETURN_OK if the MAC reinitialization is successful.
* @retval RETURN_ERR if any error is detected during the reinitialization process, such as a failure to lock or unlock the CM.
*
*/
INT cm_hal_ReinitMac();

/**
* @brief Retrieve the provisioned wan0 IP type.
* @param[out] pValue Integer pointer containing the ip type currently provisioned on wan0.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, such as a null pointer provided for pValue or a failure in retrieving the IP type from the system.
*
*/
INT docsis_GetProvIpType(CHAR *pValue);

/**
* @brief Retrieves the location of the CM certificate file.
*
* This function retrieves the file path where the CM certificate is stored in the file system.
*
* @param[out] pCert Pointer to a character array where the certificate file location will be stored.
*                   \n Example value: "/nvram/cmcert.bin"
*
* @return The status of the operation.
* @retval RETURN_OK if the certificate location is successfully retrieved and stored.
* @retval RETURN_ERR if any error is detected during the retrieval or storage process, such as a null pointer for the certificate path, failure to retrieve the certificate, or failure to write the certificate to the file.
*
*/
INT docsis_GetCert(CHAR* pCert);

/**
* @brief Retrieves the status of the CM certificate.
*
* This function retrieves the status of the CM certificate, indicating whether it is enabled or disabled.
*
* @param[out] pVal Pointer to a value containing the certificate status, to be returned.
*                  \n Values: 0 (disabled) or 1 (enabled).
*
* @return The status of the operation.
* @retval RETURN_OK if the certificate status is successfully retrieved.
* @retval RETURN_ERR if an error occurs, such as a null pointer provided for pVal or a failure in accessing the system configuration to retrieve the certificate status.
*
*/
INT docsis_GetCertStatus(ULONG *pVal);

/**
* @brief Retrieve the count of cable modem reset
* @param[out] resetcnt Pointer to the count of cable modem resets, to be returned.
*                      \n Possible value: Any non-negative integer representing the count of cable modem resets.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR  if errors occur, such as null pointers or data access failures.
*
*/
INT cm_hal_Get_CableModemResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of local reset events for the cable modem.
* @param[out] resetcnt Pointer to the count of local cable modem reset events.
*                      \n Possible value: Any non-negative integer representing the count of local cable modem resets.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR  if errors occur, such as null pointers or data access failures.
*
*/

INT cm_hal_Get_LocalResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of DOCSIS reset events for the cable modem.
* @param[out] resetcnt Pointer to the count of DOCSIS reset events.
*                      \n Possible value: Any non-negative integer representing the count of DOCSIS resets.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR  if errors occur, such as null pointers or data access failures.
*
*/

INT cm_hal_Get_DocsisResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of eRouter reset events.
* @param[out] resetcnt Pointer to the count of erouter resets.
*                      \n Possible value: Any non-negative integer representing the count of erouter resets.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR  if errors occur, such as null pointers or data access failures.
*
*/

INT cm_hal_Get_ErouterResetCount(ULONG *resetcnt);

/**
* @brief Function to control the flashing of an HTTP LED.
* @param[in] LedFlash Boolean value indicating whether to enable (1) or disable (0) LED Flash.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
*
*/

INT cm_hal_HTTP_LED_Flash( BOOLEAN LedFlash );

//>> Docsis3.1, please refer to the specification at the top of this file
/**
* @brief Get the Downstream OFDM (DSOF) channel table.
*
* This function must allocate the array of DOCSIF31_CM_US_OFDMA_CHAN internally, and it will return ppInfo, which will be de-allocated by the caller.
*
* @param[out] ppinfo Pointer to get the return array.
* @param[out] output_NumberOfEntries Array size needs to be returned with output_NumberOfEntries.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, including null pointer inputs, channel retrieval failures, memory allocation issues, or data processing errors within the function.
*
*/
INT docsis_GetDsOfdmChanTable(PDOCSIF31_CM_DS_OFDM_CHAN *ppinfo, int *output_NumberOfEntries);

/**
* @brief Retrieve the Upstream OFDMA channel table (docsIf31CmUsOfdmaChanTables).
* This function retrieves information about the Upstream OFDMA (Orthogonal Frequency Division Multiple Access) channels from the cable communication system. 
* This function must allocate the array of DOCSIF31_CM_US_OFDMA_CHAN internally, and it will return ppInfo, which will be de-allocated by the caller
*
* @param[out] ppinfo Pointer to receive the array containing Upstream OFDMA channel information.
*
* @param[out] output_NumberOfEntries Pointer to an integer where the size of the returned array will be stored.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, including null pointer inputs, channel retrieval failures, memory allocation issues, or data processing errors within the function.
*
*/
INT docsis_GetUsOfdmaChanTable(PDOCSIF31_CM_US_OFDMA_CHAN *ppinfo, int *output_NumberOfEntries);

/**
* @brief Retrieve the Upstream OFDMA channel status table (docsIf31CmStatusOfdmaUsTable)
* This function must allocate the array of DOCSIF31_CMSTATUSOFDMA_US internally, and it will return ppInfo, which will be de-allocated by the caller
*
* @param[out] ppinfo variable is a pointer to get the return array.
* @param[out] output_NumberOfEntries variable is a integer pointer.
*
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, including invalid parameters and memory allocation issues.
*
*/
INT docsis_GetStatusOfdmaUsTable(PDOCSIF31_CMSTATUSOFDMA_US *ppinfo, int *output_NumberOfEntries);
//<< Docsis3.1, please refer to the specification at the top of this file

/*
 * TODO: All functions in this interface will be upgraded to return enums where enums are implied, and INT will not be used in the future
 */

/**
* @brief Get the Low Latency DOCSIS (LLD) enable status.
*
* @return The status of the LLD status.
* @retval ENABLE if LLD is enabled in bootfile.
* @retval DISABLE if LLD is disabled/entry doesn't exists in bootfile.
* @retval RETURN_ERR if unable to retrieve the setting or if the function is called on unsupported firmware versions.
*
*/

INT docsis_LLDgetEnableStatus();

/**
* @brief Initialize SNMPv3 security parameters on the Cable Modem (CM).
* @param[in] pKickstart_Table a pointer to the SNMPv3 kickstart table.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected during initialization, such as invalid input parameters or failure to set SNMPv3 security parameters.
*
*/
INT cm_hal_snmpv3_kickstart_initialize(snmpv3_kickstart_table_t *pKickstart_Table);
/** @} */  //END OF GROUP CM_HAL_APIS

/**
* @brief Check if DOCSIS energy is detected to determine WAN mode.
* @param[out] pEnergyDetected Pointer to a boolean variable:
*                             - Set to 0 if no DOCSIS energy is detected, implying no DOCSIS connection.
*                             - Set to 1 if DOCSIS energy is detected, indicating a DOCSIS connection.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, such as a null pointer for pEnergyDetected or if the function is called on unsupported firmware versions.
*
*/

INT docsis_IsEnergyDetected( BOOLEAN *pEnergyDetected );


/**
* @brief Set the value of ReinitMacThreshold.
*
* This function sets the ReinitMacThreshold value to the specified unsigned long value. 
* The ReinitMacThreshold value determines the threshold at which the MAC (Media Access Control) layer of the cable modem should be reinitialized.
*
* @param[in] value The ReinitMacThreshold value to be set.
*
* @return The status of the operation:
*         - RETURN_OK if the operation is successful.
*         - RETURN_ERR if an error occurs, such as issues with setting the value in the system, validation failures, or configuration errors.
*/

INT cm_hal_set_ReinitMacThreshold(ULONG value);

/**
* @brief Retrieve the ReinitMacThreshold value.
*
* This function retrieves the current value of the ReinitMacThreshold parameter, which determines the threshold for reinitializing the MAC (Media Access Control) layer in the cable modem.
*
* @param[out] pValue Pointer to store the ReinitMacThreshold value.
*                    \n It should be an unsigned long pointer.
*
* @return The status of the operation:
*         - RETURN_OK if the operation is successful.
*         - RETURN_ERR if an error occurs, such as a null pointer provided for pValue, or if there is an issue accessing or reading the value from the modem's configuration.
*/
INT cm_hal_get_ReinitMacThreshold(ULONG *pValue);

/**
* @brief Retrieve the current Diplexer settings.
*
* This function retrieves the current Diplexer settings, which refer to the configuration of the Diplexer used in the cable modem. 
* A Diplexer is a passive device used in telecommunications and cable TV networks to separate or combine signals on different frequencies. In the context of cable modems, Diplexer settings may include parameters related to signal filtering, frequency band selection, or signal routing.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected, such as invalid parameters or failure to retrieve Diplexer settings.
*
*/
INT cm_hal_get_DiplexerSettings(CM_DIPLEXER_SETTINGS *pValue);

/**
* @brief Receive Current Diplexer Settings via this callback.
* @param[out] stCMDiplexerValue value to be received.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs, such as failure to register the callback.
*
*/
typedef INT ( * cm_hal_DiplexerVariationCallback)(CM_DIPLEXER_SETTINGS stCMDiplexerValue);

/**
* @brief To register callback for receiving dynamic diplexer settings
*
* This function registers a callback function to receive dynamic diplexer settings updates.
* The callback function will be triggered whenever there is a change in the diplexer settings, such as a change in frequency band selection, signal filtering, or signal routing.
* This callback is registered during initialization and it cannot be removed.
*
* @param[in] callback_proc is from cm_hal_DiplexerVariationCallback function.
*                stCMDiplexerValue variable is from the structure CM_DIPLEXER_SETTINGS.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if not supported or implemented (e.g., stub, unsupported feature, misconfiguration).
* 
*/
INT cm_hal_Register_DiplexerVariationCallback(cm_hal_DiplexerVariationCallback callback_proc);

#ifdef __cplusplus
}
#endif

#endif
