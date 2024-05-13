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

/**!
 * @brief Retrieves the current IP Provisioning Mode Override status.
 *
 * This function populates the provided buffer with a string representing the current mode.
 *
 * @param[out] pValue - Pointer to a character array (at least 64 bytes) to hold the status string.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., invalid parameter, retrieval error).
 *
 * **Possible Values:**
 * - "ipv4Only"
 * - "ipv6Only"
 * - "honorMdd"
 * 
 * **Note:** While "APM" and "DualStack" might be technically supported, the expected behavior is to only return "ipv4Only", "ipv6Only", and "honorMdd".
 */
INT docsis_GetMddIpModeOverride(CHAR *pValue); 

/**!
 * @brief Set the IP Provisioning Mode Override status.
 *
 * This function updates the status using the provided value.
 *
 * @param[in] pValue - Desired status string. Valid values for setting: "ipv4Only", "ipv6Only", "honorMdd".  An empty string ("") clears the override.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., invalid parameter, setting error).
 *
 * **Note:** While "APM" and "DualStack" might be returned by the getter function, they cannot be directly set using this function.
 */
INT docsis_SetMddIpModeOverride(CHAR *pValue); 

/**!
 * @brief Retrieves the Upstream channel ID within its MAC (Media Access Control) domain.
 *
 * This function returns the ID of the upstream channel associated with the local network segment (MAC domain). 
 * 
 * @returns Channel ID (value between 0 and 255).
 */
UINT8 docsis_GetUSChannelId(void); 

/**!
 * @brief Sets the Upstream channel ID within its MAC (Media Access Control) domain.
 *
 * This function updates the ID of the upstream channel associated with the local network segment (MAC domain). The MAC domain includes network devices sharing the same MAC address and communication protocols.
 *
 * @param[in] index - The new channel ID value.
 */
void docsis_SetUSChannelId(INT index); 

/**!
 * @brief Retrieves the current primary downstream channel frequency.
 *
 * This function returns the frequency of the main downstream channel as found in the Low-Level Kernel Filtering (LKF) table.
 *
 * @returns Channel frequency in Hertz (Hz).
 */
ULONG docsis_GetDownFreq(void); 

/**!

 * @brief Set the primary downstream channel frequency in the LKF table.
 *
 * Modifies the Low-Level Kernel Filtering (LKF) table to use the specified frequency for the primary downstream channel.
 *
 * @param[in] value - The desired channel frequency in Hertz (Hz).
 */
void docsis_SetStartFreq(ULONG value); 

/**!
 * @brief Retrieves DOCSIS event log entries.
 *
 * Populates the provided array with up to 'len' DOCSIS event log entries.
 *
 * @param[out] entryArray - Pointer to an array where retrieved log entries will be stored.
 * @param[in]  len        - Maximum number of entries to retrieve.
 *
 * @return Number of log entries successfully retrieved and placed into 'entryArray'. 
 */
INT docsis_GetDocsisEventLogItems(CMMGMT_CM_EventLogEntry_t *entryArray, INT len);

/**!
 * @brief Clears the DOCSIS event log.
 *
 * This function clears the log asynchronously, likely by sending a message to a driver event handler. 
 *
 * **Important:** This function must not block or use blocking system calls.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., an error setting the log clear entry).
 */
INT docsis_ClearDocsisEventLog(void);

/**!
 * @brief Retrieves the DHCP information for the Cable Modem (CM).
 *
 * Populates the provided `PCMMGMT_CM_DHCP_INFO` structure with the CM's DHCP details.
 *
 * **Important:** The caller is responsible for allocating and freeing the memory for the `pInfo` structure.
 *
 * @param[out] pInfo - Pointer to a pre-allocated `PCMMGMT_CM_DHCP_INFO` structure to be populated.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointer, data acquisition failure, internal error).
 */
INT cm_hal_GetDHCPInfo(PCMMGMT_CM_DHCP_INFO pInfo);

/**!
 * @brief Retrieves IPv6 DHCP information for the Cable Modem (CM).
 *
 * This function populates a caller-provided `CMMGMT_CM_IPV6DHCP_INFO` structure with IPv6 DHCP details obtained from the CM.
 *
 * **Important:** The caller is responsible for allocating and freeing the memory for the `pInfo` structure.
 *
 * @param[out] pInfo - Pointer to a pre-allocated `CMMGMT_CM_IPV6DHCP_INFO` structure to be filled with the IPv6 DHCP information.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointer, retrieval error, invalid data from DHCP server).
 */
INT cm_hal_GetIPv6DHCPInfo(PCMMGMT_CM_IPV6DHCP_INFO pInfo);

/**!
 * @brief Retrieves a list of CPEs (Customer Premises Equipment) connected to the Cable Modem (CM).
 *
 * Populates a caller-provided `PCMMGMT_DML_CPE_LIST` structure with CPE details and updates the `InstanceNum` with the count.
 *
 * **Important:** The caller must:
 *   - Allocate memory for the `ppCPEList` structure and the `LanMode` string.
 *   - Free the allocated memory for both parameters afterward. 
 *
 * @param[out] ppCPEList - Pointer to a pre-allocated `PCMMGMT_DML_CPE_LIST` structure to be populated.
 * @param[out] InstanceNum - Pointer to a variable that will receive the number of CPEs found.
 * @param[in]  LanMode - Specifies the modem's mode: "router" or "bridge". (Max length: 100 bytes)
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., invalid parameters, memory allocation issues, or retrieval errors). 
 */
INT cm_hal_GetCPEList(PCMMGMT_DML_CPE_LIST *ppCPEList, ULONG *InstanceNum, CHAR *LanMode);

/**!
 * @brief Retrieves the modem's market region (e.g., "US" for United States, "EURO" for Europe).
 *
 * Populates the provided buffer with the market region identifier.
 *
 * @param[out] market - Pointer to a character array (at least 100 bytes) to store the market identifier.
 *
 * @returns Status of the operation.
 * @retval RETURN_OK on success. 
 * @retval RETURN_ERR on failure (e.g., invalid 'market' pointer, insufficient buffer size, or data retrieval issues).
 */
INT cm_hal_GetMarket(CHAR *market);

/* HTTP Download HAL API Prototype */

/**!
 * @brief Configures an HTTP download.
 *
 * Prepares the configuration file for an HTTP download by specifying the download URL and the desired filename for the retrieved data.
 *
 * @param[in] pHttpUrl - The download URL (e.g., "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings").
 * @param[in] pfilename - The desired filename for storing the downloaded data (e.g., "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT").
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if a download is already in progress or the provided URL is invalid.
 *
 * **TODO:** Change `pHttpUrl` and `pfilename` to `const char*` as they are input parameters and should not be modified.
 */
INT cm_hal_Set_HTTP_Download_Url(const char *pHttpUrl, const char *pfilename); 

/**!
 * @brief Retrieves the configured HTTP download URL and filename.
 *
 * Populates the provided buffers with the URL and filename stored in the HTTP download configuration file.
 *
 * **Important:** The caller must pre-allocate buffers of at least 200 bytes for both `pHttpUrl` and `pfilename`. Insufficient buffer sizes can lead to memory corruption. 
 *
 * @param[out] pHttpUrl - Pointer to a buffer (at least 200 bytes) to store the download URL.
 * @param[out] pfilename - Pointer to a buffer (at least 200 bytes) to store the download filename.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if the configured URL is empty or an error occurs.
 */
INT cm_hal_Get_HTTP_Download_Url(char *pHttpUrl, char *pfilename);

/**!
 * @brief Configures the HTTP download interface.
 *
 * Specifies the network interface to be used for HTTP downloads.
 *
 * @param[in] interface - Network interface identifier:
 *               - 0 for wan0
 *               - 1 for erouter0
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if an invalid interface value is provided.
 */
INT cm_hal_Set_HTTP_Download_Interface(unsigned int interface); 

/**!
 * @brief Retrieves the configured HTTP download interface.
 *
 * Populates the provided variable with the network interface identifier.
 *
 * @param[out] pinterface - Pointer to an unsigned int variable where the interface identifier will be stored:
 *              - 0 for wan0
 *              - 1 for erouter0
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR on failure (e.g., invalid parameter, memory allocation issues).
 */
INT cm_hal_Get_HTTP_Download_Interface(unsigned int *pinterface); 

/**!
 * @brief Initiates an HTTP download.
 *
 * Starts the download process using the previously configured settings.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if a download is already in progress or an error occurs. 
 */ 
INT cm_hal_HTTP_Download();

/**!
 * @brief Retrieves the current HTTP download status.
 *
 * @returns An integer representing the download status:
 * * 0: Download not started.
 * * 1-99: Download progress percentage.
 * * 100: Download complete, pending reboot.
 * * 400-407: Specific HTTP error codes (see descriptions below).
 * * 500: General download failure.
 *
 * **Error Codes:**
 * * 400: Invalid HTTP server URL.
 * * 401: Cannot connect to the HTTP server.
 * * 402: File not found on the HTTP server.
 * * 403-407: Various download protection failures (HW_Type, HW Mask, DL Rev, DL Header, DL CVC).
 */
INT cm_hal_Get_HTTP_Download_Status(); 

/**!
 * @brief Checks if the system is ready for a reboot.
 *
 * Populates the provided variable with the reboot readiness status.
 *
 * @param[out] pValue - Pointer to an unsigned long variable where the status will be stored:
 *              - 1: System is ready for reboot.
 *              - 2: System is not ready for reboot.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if an error occurs (e.g., during status retrieval or resource access).
 */ 
INT cm_hal_Reboot_Ready(ULONG *pValue);

/**!
 * @brief Initiates a system reboot, performing pre-reboot checks and updates.
 *
 * This function:
 *   1. Creates a reboot file.
 *   2. Manages the reboot counter (retrieving and updating as needed).
 *   3. Triggers the system reboot.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if the reboot file creation or the reboot process itself fails. 
 */ 
INT cm_hal_HTTP_Download_Reboot_Now();

/**!
 * @brief Initiates a firmware update and factory reset.
 *
 * This function updates the device's firmware (optionally from a specified URL) and then performs a factory reset.
 *
 * @param[in] pUrl - URL for the firmware image (e.g., "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings").
 * @param[in] pImagename - Firmware image filename (e.g., "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT").
 * 
 * @returns Status of the operation:
 * @retval RETURN_OK on success.
 * @retval RETURN_ERR if a reboot is already in progress or other errors occur. 
 */
INT cm_hal_FWupdateAndFactoryReset(char *pUrl, char *pImagename);

/**!
 * @brief Resets the Cable Modem's (CM) MAC layer while preserving channels.
 * 
 * This function reinitializes the Media Access Control (MAC) layer of the CM. Existing downstream (DS) and upstream (US) channels are maintained during this process.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., locking/unlocking CM issues).
 */
INT cm_hal_ReinitMac(); 

/**!
 * @brief Retrieves the provisioned IP type for the wan0 interface.
 *
 * Populates the provided variable with the current IP type.
 *
 * @param[out] pValue - Pointer to a character variable where the IP type will be stored. Possible values include:
 *                 - "DHCP" (or its numeric equivalent)
 *                 - "STATIC" (or its numeric equivalent) 
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - if an error occurs (e.g., null pointer, retrieval failure).
 */
INT docsis_GetProvIpType(CHAR *pValue); 

/**!
 * @brief Retrieves the filepath of the Cable Modem (CM) certificate.
 *
 * Populates the provided buffer with the path where the CM certificate is stored.
 *
 * @param[out] pCert - Pointer to a character array where the filepath will be stored (e.g., "/nvram/cmcert.bin").
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, retrieval errors, or file access issues).
 */
INT docsis_GetCert(CHAR *pCert); 

/**!
 * @brief Retrieves the Cable Modem (CM) certificate status.
 *
 * Populates the provided variable with the certificate's enabled/disabled state.
 *
 * @param[out] pVal - Pointer to an unsigned long variable where the status will be stored:
 *              - 0: Certificate disabled.
 *              - 1: Certificate enabled.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, inability to access configuration).
 */
INT docsis_GetCertStatus(ULONG *pVal); 

/**!
 * @brief Retrieves the number of Cable Modem (CM) resets.
 *
 * Populates the provided variable with the count of CM resets.
 *
 * @param[out] resetcnt - Pointer to an unsigned long variable where the reset count will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, inability to access reset data).
 */
INT cm_hal_Get_CableModemResetCount(ULONG *resetcnt); 

/**!
 * @brief Retrieves the number of local Cable Modem (CM) resets.
 *
 * Populates the provided variable with the count of CM resets initiated locally (e.g., by user action or software command).
 *
 * @param[out] resetcnt - Pointer to an unsigned long variable where the reset count will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, inability to access reset data).
 */
INT cm_hal_Get_LocalResetCount(ULONG *resetcnt); 

/**!
 * @brief Retrieves the number of DOCSIS-related Cable Modem (CM) resets.
 *
 * Populates the provided variable with the count of CM resets triggered by DOCSIS events or operations.
 *
 * @param[out] resetcnt - Pointer to an unsigned long variable where the reset count will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, inability to access reset data).
 */
INT cm_hal_Get_DocsisResetCount(ULONG *resetcnt); 

/**!
 * @brief Retrieves the number of DOCSIS-related Cable Modem (CM) resets.
 *
 * Populates the provided variable with the count of CM resets triggered by DOCSIS events or operations.
 *
 * @param[out] resetcnt - Pointer to an unsigned long variable where the reset count will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - on success.
 * @retval RETURN_ERR - on failure (e.g., null pointer, inability to access reset data).
 */
INT cm_hal_Get_DocsisResetCount(ULONG *resetcnt); 

/**!
 * @brief Controls the flashing of the HTTP LED.
 *
 * Enables or disables the flashing of the HTTP LED.
 *
 * @param[in] LedFlash - Boolean value:
 *                 - true (1):  Enable LED flashing.
 *                 - false (0): Disable LED flashing.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success. 
 */
INT cm_hal_HTTP_LED_Flash(BOOLEAN LedFlash);

/**!
 * @brief Retrieves the Downstream OFDM (DSOFDM) channel table.
 *
 * Populates the provided pointer with a dynamically allocated array of `DOCSIF31_CM_DS_OFDM_CHAN` structures. Also updates the `output_NumberOfEntries` with the array size.
 * @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
 *
 * **Important:** The caller is responsible for deallocating the memory for `ppinfo`.
 *
 * @param[out] ppinfo - Pointer to a `PDOCSIF31_CM_DS_OFDM_CHAN` pointer. Will be populated with the allocated array.  
 * @param[out] output_NumberOfEntries - Pointer to an integer where the number of channels in the table will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointers, allocation issues, retrieval errors).
 */
INT docsis_GetDsOfdmChanTable(PDOCSIF31_CM_DS_OFDM_CHAN *ppinfo, int *output_NumberOfEntries);

/**!
 * @brief Retrieves the Upstream OFDMA (USOFDMA) channel table.
 *
 * Populates the provided pointer with a dynamically allocated array of `DOCSIF31_CM_US_OFDMA_CHAN` structures. Also updates the `output_NumberOfEntries` with the array size.
 * @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
 *
 * **Important:**  The caller is responsible for deallocating the memory for `ppinfo`.
 *
 * @param[out] ppinfo - Pointer to a `PDOCSIF31_CM_US_OFDMA_CHAN` pointer. Will be populated with the allocated array.  
 * @param[out] output_NumberOfEntries - Pointer to an integer where the number of channels in the table will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointers, allocation issues, retrieval errors).
 */
INT docsis_GetUsOfdmaChanTable(PDOCSIF31_CM_US_OFDMA_CHAN *ppinfo, int *output_NumberOfEntries);

/**!
 * @brief Retrieves the Upstream OFDMA (USOFDMA) channel status table.
 *
 * Populates the provided pointer with a dynamically allocated array of `DOCSIF31_CMSTATUSOFDMA_US` structures and updates `output_NumberOfEntries` with the array size.
 * @note for detailed information on Docsis3.1, please refer to the specification at the top of this file
 *
 * **Important:** The caller is responsible for deallocating the memory for `ppinfo`.
 *
 * @param[out] ppinfo - Pointer to a `PDOCSIF31_CMSTATUSOFDMA_US` pointer. Will be populated with the allocated array.  
 * @param[out] output_NumberOfEntries - Pointer to an integer where the number of channels in the status table will be stored. 
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., invalid parameters, allocation issues, or retrieval errors).
 */
INT docsis_GetStatusOfdmaUsTable(PDOCSIF31_CMSTATUSOFDMA_US *ppinfo, int *output_NumberOfEntries);

/*
 * TODO: All functions in this interface will be upgraded to return enums where enums are implied, and INT will not be used in the future
 */

/**!
 * @brief Retrieves the Low Latency DOCSIS (LLD) enablement status.
 *
 * @returns Status of LLD configuration:
 * @retval ENABLE - LLD is enabled in the bootfile.
 * @retval DISABLE - LLD is disabled or the entry is missing in the bootfile.
 * @retval RETURN_ERR -  On error (e.g., retrieval issues, unsupported firmware).
 *
 * **TODO:** In future updates, this function will return a well-defined enum (`LLD_STATUS` or similar) instead of integer values. 
 */
INT docsis_LLDgetEnableStatus(); 

/**!
 * @brief Initializes SNMPv3 security parameters for the Cable Modem (CM).
 *
 * Uses the provided SNMPv3 kickstart table to configure the CM's SNMPv3 settings.
 *
 * @param[in] pKickstart_Table - Pointer to an `snmpv3_kickstart_table_t` structure containing the SNMPv3 configuration.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., invalid parameters, SNMPv3 setup errors).
*/
INT cm_hal_snmpv3_kickstart_initialize(snmpv3_kickstart_table_t *pKickstart_Table);

/** @} */  //END OF GROUP CM_HAL_APIS

/**!
 * @brief Detects DOCSIS energy to determine WAN connection status.
 *
 * Populates the provided boolean variable to indicate the presence or absence of DOCSIS energy.
 *
 * @param[out] pEnergyDetected - Pointer to a boolean variable:
 *               - Set to false (0) if no DOCSIS energy is detected (no connection).
 *               - Set to true (1) if DOCSIS energy is detected (connection established).
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointer, unsupported firmware).
 */
INT docsis_IsEnergyDetected(BOOLEAN *pEnergyDetected); 

/**!
 * @brief Sets the threshold for MAC layer reinitialization.
 *
 * Updates the MAC reinitialization threshold to the provided value. When this threshold is reached, the Cable Modem's MAC layer will be automatically reinitialized.
 *
 * @param[in] value - The new MAC layer reinitialization threshold.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., setting errors, validation issues, configuration errors).
 */
INT cm_hal_set_ReinitMacThreshold(ULONG value);

/**!
 * @brief Retrieves the MAC layer reinitialization threshold.
 *
 * Populates the provided variable with the current threshold used to trigger an automatic reinitialization of the Cable Modem's MAC layer.
 *
 * @param[out] pValue - Pointer to an unsigned long variable where the threshold value will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., null pointer, issues retrieving the value).
 */
INT cm_hal_get_ReinitMacThreshold(ULONG *pValue);

/**!
 * @brief Retrieves the current Diplexer configuration.
 *
 * Populates the provided structure with the Diplexer's settings, which control how it filters and routes signals based on frequency.
 *
 * **Diplexer Background:** A Diplexer is a passive device that separates or combines signals of different frequencies, often used in cable modems to manage signal traffic. 
 *
 * @param[out] pValue - Pointer to a `CM_DIPLEXER_SETTINGS` structure where the retrieved settings will be stored.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On success.
 * @retval RETURN_ERR - On failure (e.g., invalid parameters, retrieval errors). 
 */
INT cm_hal_get_DiplexerSettings(CM_DIPLEXER_SETTINGS *pValue);

/**!
 * @brief Callback function for receiving current Diplexer settings.
 * 
 * Invoked when the CM Diplexer settings change.
 *
 * @param[in] stCMDiplexerValue - The updated Diplexer settings.
 *
 * @returns Status of the callback operation:
 * @retval RETURN_OK - On successful processing of the Diplexer settings.
 * @retval RETURN_ERR - On error (e.g., failure to handle the settings change).
 */
typedef INT (*cm_hal_DiplexerVariationCallback)(CM_DIPLEXER_SETTINGS stCMDiplexerValue);

/* 
 * TODO: Extend the return codes by listing out the possible reasons of failure, to improve the interface in the future.  
 */ 

/**!
 * @brief Registers a callback for dynamic Diplexer setting updates.
 *
 * This function registers a callback to be triggered when the Diplexer settings change. The callback receives updated frequency band selection, signal filtering, or routing parameters. 
 *
 * **Important:** The registered callback cannot be removed and should be provided during initialization.
 *
 * @param[in] callback_proc - Pointer to the `cm_hal_DiplexerVariationCallback` function to be registered. It will be invoked with a `CM_DIPLEXER_SETTINGS` structure containing the updated settings.
 *
 * @returns Status of the operation:
 * @retval RETURN_OK - On successful callback registration.
 * @retval RETURN_ERR - If not supported/implemented, or in case of errors (e.g., stub function, misconfiguration).
 */
INT cm_hal_Register_DiplexerVariationCallback(cm_hal_DiplexerVariationCallback callback_proc);

#ifdef __cplusplus
}
#endif

#endif
