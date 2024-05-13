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
 * @brief Represents the information about a DOCSIS 3.1 OFDM downstream channel in a cable modem.
 *
 * This structure holds information about parameters in associattion with the DOCSIS 3.1. OFDM downstream channel.
 */

//>> Docsis3.1, please refer to the specification at the top of this file
typedef struct _DOCSIF31_CM_DS_OFDM_CHAN {
    unsigned int ChannelId;                     /**< The identification number of the downstream channel within a particular MAC interface of the Cable Modem Termination System (CMTS). */
    unsigned int ChanIndicator;                 /**< This attribute is used to identify the OFDM downstream channel as primary, backup primary or non-primary. A value of'primary(2)' indicates that OFDM channel is assigned to be the CM's primary downstream channel.  A value of 'backupPrimary(3)' indicates that the OFDM channel is assigned to be the CM's backup primary downstream channel.  A value of 'nonPrimary(4)'indicates the OFDM channel is not assigned to be CM's primary or backup primary downstream channel*/
    unsigned int SubcarrierZeroFreq;            /**< The center frequency of subcarrier 0 of the OFDM transmission within a downstream channel of the Cable Modem Termination System (CMTS).*/
    unsigned int FirstActiveSubcarrierNum;      /**< The number of the first non-excluded subcarrier. The valid range is 148 to 7895 */
    unsigned int LastActiveSubcarrierNum;       /**< The number of the last non-excluded subcarrier. The valid range is 148 to 7895 */
    unsigned int NumActiveSubcarriers;          /**< The number of active data subcarriers within the OFDM downstream channel (i.e. this exclude subcarriers for continuous pilots and the PLC). For 4K FFT mode, the maximum number of subcarriers including continuous pilots and the PLC cannot exceed 3800, and for 8K FFT mode, the maximum number of active subcarriers including continuous pilots and the PLC cannot be greater than 7600. */
                                                /**< There are a minimum of 56 continuous pilots in a 192MHz channel that has no exclusions, and the size of the PLC is 8 subcarriers for 4K FFT mode and 16 subcarriers for 8K FFT mode. Therefore the maximum value of NumActiveSubcarriers is 3736 (or 3800 - 56 - 8) for 4K FFT mode and 7528 (or 7600 - 56 - 16) for 8K FFT mode. */
    unsigned int SubcarrierSpacing;             /**< The subcarrier spacing associated with a particular FFT mode configured on the OFDM downstream channel. If it is 4K mode, then the subcarrier spacing is 50kHz. If it is 8K mode, then the subcarrier spacing is 25kHz (in kHz) */
    unsigned int CyclicPrefix;                  /**< Cyclic prefix enables the receiver to overcome the effects of inter-symbol-interference and intercarrier-interference caused  by micro-reflections in the channel. There are five possible alues for the length of the CP and the choice depends on the delay spread of the channel - a longer delay spread requires a longer cyclic prefix. The cyclic prefix (in usec) are converted into samples using the sample rate of 204.8 Msamples/s and is an integer multiple of: 1/64 * 20 us. */
    unsigned int RollOffPeriod;                 /**< Roll off period maximizes channel capacity by sharpening the edges of the spectrum of the OFDM signal. For windowing purposes another segment at the start of the IDFT output is appended to the end of the IDFT output - the roll-off postfix (RP). There are five possible values for the (RP), and the choice depends on the bandwidth of the channel and the number of exclusion bands within the channel. A larger RP provides sharper edges in the spectrum of the OFDM signal; however,  there is a time vs. frequency trade-off. Larger RP values reduce the efficiency of transmission in the time domain, but because the spectral edges are sharper, more useful subcarriers appear in the frequency domain. There is an optimum value for the RP that maximizes capacity for a given bandwidth and/or exclusion band scenario. */
    unsigned int PlcFreq;                       /**< This is the PHY Link Channel (PLC) frequency. It is the center frequency of the lowest frequency subcarrier of the PLC. The aim of the PLC is for the CMTS to convey to the CM the physical properties of the OFDM channel */
    unsigned int NumPilots;                     /**< The number of continuous pilots configured for the OFDM downstream channel as received in the OCD message. */
    unsigned int TimeInterleaverDepth;          /**< The time interleaving used for this downstream channel as received in the OCD message. */
    char averageSNR[OFDM_PARAM_STR_MAX_LEN];    /**< Average Signal-to-Noise Ratio (SNR) of the downstream channel */
    char PowerLevel[OFDM_PARAM_STR_MAX_LEN];    /**< The power level of this downstream channel. Power level is expressed as in tenths of a dBmV */
    unsigned long long PlcTotalCodewords;       /**< The total number of PLC codewords received by the CM. */
    unsigned long long PlcUnreliableCodewords;  /**< The total number of PLC codewords which failed post-decoding LDPC syndrome check. */
    unsigned long long NcpTotalFields;          /**< The total number of NCP fields received by the CM. */
    unsigned long long NcpFieldCrcFailures;     /**< The total number of NCP fields received by the CM which failed the CRC check. */

} DOCSIF31_CM_DS_OFDM_CHAN, *PDOCSIF31_CM_DS_OFDM_CHAN;


/**
 * @brief Represents information about a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
 *
 * This structure about various parameters of DOCSIS 3.1 OFDMA upstream channel
 */


typedef struct _DOCSIF31_CM_US_OFDMA_CHAN {
    unsigned int ChannelId;                     /**< The identification number of the OFDMA upstream channel within a particular MAC interface of the Cable Modem Termination System (CMTS).*/
    unsigned int ConfigChangeCt;                /**< Count that keeps track of how many times the configuration of the Upstream Channel Descriptor (UCD) MAC Management Message has been changed for a specific OFDMA channel. */
    unsigned int SubcarrierZeroFreq;            /**< Lower edge frequency of the OFDMA upstream channel in Hertz (Hz). */
    unsigned int FirstActiveSubcarrierNum;      /**< Index or number of the first active subcarrier in the OFDMA upstream channel. The valid range is 74 to 3947. */
    unsigned int LastActiveSubcarrierNum;       /**< Index or number of the last active subcarrier in the OFDMA upstream channel. The valid range is 74 to 3947. */
    unsigned int NumActiveSubcarriers;          /**< The number of active subcarriers within the OFDMA upstream channel. The valid range is 1 to 3800. */
    unsigned int SubcarrierSpacing;             /**< The subcarrier spacing associated with a particular FFT mode configured on the OFDMA upstream channel. If it is 2K mode, then the subcarrier spacing is 50kHz. If it is 4K mode, then the subcarrier spacing is 25kHz. */
    unsigned int CyclicPrefix;                  /**< Cyclic prefix is added in order to enable the receiver to overcome the effects of inter-symbol interference (ISI) and inter-carrier interference caused by microreflections in the channel. The cyclic prefix (in usec) is converted into samples using the sample rate of 102.4 Msamples/s. There are eleven values for the length of the CP and the choice depends on the delay spread of the channel; a longer delay spread requires a longer cyclic prefix. */
    unsigned int RollOffPeriod;                 /**< Duration of the windowing applied to maximize the channel capacity by sharpening the edges of the spectrum of the OFDMA signal. There are typically eight possible values of roll-off prefix, each corresponding to a specific roll-off period. The roll-off period may be provided in microseconds and also in the number of samples using a sample rate of 102.4 Msamples/s. */
    unsigned int NumSymbolsPerFrame;            /**< The number of symbol periods per frame. For channel bandwidth greater than 72MHz, the maximum number of symbol periods per frame is 18 for 2K mode and 9 for 4K mode. For channel bandwidth less than 72 MHz but greater than 48MHz, the maximum number of symbols per frame is 24 for 2K mode and 12 for 4K mode. For channel bandwidth less than 48MHz, the maximum number of symbol periods is 36 for 2K mode and 18 for 4K mode. The minimum number of symbol periods per frame is 6 for both the FFT modes and is independent of the channel bandwidth. */
    unsigned int TxPower;                       /**< The operational transmit power for the associated OFDMA upstream channel.The CM reports its Target Power, P1.6r_n as described in [PHYv3.1]. Valid values for this object are 68 to (213 + (4*(Pmax - 65 dBmV))), since 68 quarter dBmV represents the lowest Tx power value 17 dBmV and 213 represents the nearest quarter dBmV to the highest Tx power value 53.2 dBmV. */
    unsigned char PreEqEnabled;                 /**< Whether pre-equalization is enabled on the associated OFDMA upstream channel. */
} DOCSIF31_CM_US_OFDMA_CHAN, *PDOCSIF31_CM_US_OFDMA_CHAN;


/**
 * @brief Represents information about a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
 *
 *
 * This structure holds information about various parameters of DOCSIS 3.1 OFDMA upstream channel.
 */

typedef struct _DOCSIF31_CMSTATUSOFDMA_US {
    // The full definitions for the fields below can be referenced within DOCS-IF31-MIB.
    unsigned int ChannelId;                     /**< The identification number of the OFDMA upstream channel within a particular MAC interface of the Cable Modem Termination System (CMTS).*/
    unsigned int T3Timeouts;                    /**< Number of T3 counter timeouts. */
    unsigned int T4Timeouts;                    /**< Number of T4 counter timeouts.*/
    unsigned int RangingAborteds;               /**< Number of times ranging process has been aborted.*/
    unsigned int T3Exceededs;                   /**< Number of excessive T3 timeouts.*/
    unsigned char IsMuted;                      /**< Indicates if upstream channel is muted.*/
    unsigned int RangingStatus;                 /**< Ranging State of CM: other(1),aborted(2),retriesExceeded(3),success(4),continue(5),timeoutT4(6)*/
} DOCSIF31_CMSTATUSOFDMA_US, *PDOCSIF31_CMSTATUSOFDMA_US;
//<< Docsis3.1, please refer to the specification at the top of this file

#define MAX_KICKSTART_ROWS 5   /**< Maximum number of rows of kickstart*/


/**
 * @brief Represents the fixed-length buffer.
 *
 * This structure holds information about the fixed-length buffer with a specified length and a pointer to the buffer data .
 */

typedef struct _fixed_length_buffer {
    USHORT length;                               /**< Length of the buffer. Maximum value is (2^16)-1. */
    UINT8 *buffer;                               /**< Pointer to the buffer. */
} fixed_length_buffer_t;

/**
 * @brief Represents a row in the SNMPv3 kickstart.
 *
 * This structure holds information about the fixed length buffer for security name and security number .
 */

typedef struct _snmpv3_kickstart_row {
    fixed_length_buffer_t security_name;          /**< Structure to describe the buffer for the security name */
    fixed_length_buffer_t security_number;        /**< Structure to describe the buffer for the security number*/
} snmp_kickstart_row_t;


/**
 * @brief Represents a SNMPv3 kickstart table.
 *
 * This structure holds information about the SNMPv3 kickstart table including the number of rows and an array of SNMPv3 kickstart rows.
 */

typedef struct _snmpv3_kickstart_table {
    UINT8 n_rows;                                                /**< Count of snmp kickstart rows. */
    snmp_kickstart_row_t *kickstart_values[MAX_KICKSTART_ROWS];  /**< Pointer to an array of smp kickstart rows. */
} snmpv3_kickstart_table_t;

/**
 * @brief Diplexer settings for cable modem.
 *
 * This structure holds information about the diplexer settings for both upstream and downstream channels including the upper edge frequency in megahertz (MHz).
 */

typedef  struct
_CM_DIPLEXER_SETTINGS
{
    UINT    usDiplexerSetting; /**< Upstream upper band edge of diplexer in MHz*/
    UINT    dsDiplexerSetting; /**< Downstream upper band edge of diplexer in MHz*/
}
CM_DIPLEXER_SETTINGS;

/** @} */  //END OF GROUP CM_HAL_TYPES


/**********************************************************************************
 *
 *  CM Subsystem level function prototypes
 *
**********************************************************************************/

/*
 * TODO: Extend the return codes by listing out the possible reasons of failure, to improve the interface in the future. This was reported during the review for header file migration to opensource github.
 */

/**
 * @addtogroup CM_HAL_APIS
 * @{
 */


/**
* @brief Initialize the Hal and associated requirements.
*
* @return The status of the operation.
* @retval RETURN_OK if initialization is successful.
* @retval RETURN_ERR if any error is encountered during initialization, such as failure to create threads or open files.
*
*/
INT cm_hal_InitDB(void);

/**
* @brief Initiates global Physical (PHY) level information and databases, and establishes direct access to the Downstream (DS) hardware (HW).
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
*
*/
INT docsis_InitDS(void);

/**
* @brief Initiates global Physical (PHY) level information and databases, and establishes direct access to the Upstream (US) hardware (HW).
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
*
*/
INT docsis_InitUS(void);

/**
* @brief Retrieve, format, and output the Cable Modem DOCSIS status.
*
* This function retrieves, formats, and outputs the Cable Modem DOCSIS status.
* The status is stored in the character array pointed to by cm_status.
*
* Expected status values are:
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
*
* @param[out] cm_status Pointer to a character array that will hold the Cable Modem DOCSIS status string to be returned.
*                       \n The maximum size allocated should be atleast 40 bytes.
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error if an error occurs during the retrieval of CM status or memory allocation fails.
*
* TODO: cm_status must be updated to an enum
*
*/
INT docsis_getCMStatus(CHAR *cm_status);

/**
* @brief Retrieve relevant downstream (DS) channel information.
*
* This function retrieves relevant downstream channel information and allocates memory for the PCMMGMT_CM_DS_CHANNEL structure.
* The memory allocated for the PCMMGMT_CM_DS_CHANNEL structure is owned by the function and should be freed by the caller when no longer needed.
*
* @param[out] ppinfo Pointer to PCMMGMT_CM_DS_CHANNEL structure that will hold all the info of DS channel to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs during the retrieval of downstream channel information or memory allocation fails.
*
*/
INT docsis_GetDSChannel(PCMMGMT_CM_DS_CHANNEL * ppinfo);

/**
* @brief Retrieve status of the upstream (US) channel information.
*
* @param[in]  i     Index of the upstream channel. Valid range is from 0 to n, where n is an unsigned short value.
* @param[out] pinfo Info of upstream channel to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs during the retrieval of upstream status or memory allocation fails.
*
*/
INT docsis_GetUsStatus(USHORT i, PCMMGMT_CM_US_CHANNEL pinfo);

/**
* @brief Retrieve relevant upstream (US) channel information.
*
* This function retrieves relevant upstream channel information and allocates memory for the PCMMGMT_CM_US_CHANNEL structure.
* The memory allocated for the PCMMGMT_CM_US_CHANNEL structure is owned by the function and should be freed by the caller when no longer needed.
*
* @param[out] ppinfo Pointer to a PCMMGMT_CM_US_CHANNEL structure that will hold all the info of the specific Upstream channel, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs during the retrieval of upstream channel information or memory allocation fails.
*
*/
INT docsis_GetUSChannel(PCMMGMT_CM_US_CHANNEL * ppinfo);

/**
* @brief Retrieve current DOCSIS registration status and report it.
* The memory for the PCMMGMT_CM_DOCSIS_INFO structure is allocated by the caller of this function. The function populates the structure with the DOCSIS registration information, but it does not allocate or free memory for the structure.
* 
* @param[out] pinfo DOCSIS Registration info, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if an error occurs during the retrieval of DOCSIS information or if the input parameter is invalid.
*
*/
INT docsis_GetDOCSISInfo(PCMMGMT_CM_DOCSIS_INFO pinfo);

/**
* @brief Retrieve number of Upstream channels actively in use in current registration.
* @param[out] cnt Pointer to an unsigned long variable that will store the number of active Upstream channels, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error occurs during the retrieval of the number of active upstream channels or if the input parameter `cnt` is invalid.
*
*/
INT docsis_GetNumOfActiveTxChannels(ULONG * cnt);

/**
* @brief Retrieve number of Downstream channels actively in use in current registration.
* @param[out] cnt Pointer to an unsigned long variable that will store the number of active Downstream channels, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error occurs during the retrieval of the number of active downstream channels or if the input parameter `cnt` is invalid.
*
*/
INT docsis_GetNumOfActiveRxChannels(ULONG * cnt);

/**
* @brief Scan all active downstream (DS) channels and report errors in received packets.
*
* This function scans all active downstream channels and reports errors in received packets. 
* Error information is stored in a PCMMGMT_CM_ERROR_CODEWORDS structure, the memory for which is allocated and released by the caller of this function.
*
* @param[out] ppinfo Pointer to a pointer to the PCMMGMT_CM_ERROR_CODEWORDS structure where the error information will be stored. 
* 
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR occurs during the scanning of downstream channels or if the input parameter `ppinfo` is invalid.
*
*/
INT docsis_GetErrorCodewords(PCMMGMT_CM_ERROR_CODEWORDS * ppinfo);

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
