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

/


#ifndef __CM_HAL_H__
#define __CM_HAL_H__

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

#ifndef RETURN_OK
#define RETURN_OK   0
#endif

#ifndef RETURN_ERR
#define RETURN_ERR   -1
#endif

#ifndef IPV4_ADDRESS_SIZE
#define  IPV4_ADDRESS_SIZE                          4
#endif

#ifndef ANSC_IPV4_ADDRESS
/* 
 * TODO:
 * While we're trying really hard to smooth the procedure of switch-over from IPv4 to IPv4, there
 * are many places where using the IP address as an integer for comparision and calculation is much
 * easier than array-based operation.
 */
#define  ANSC_IPV4_ADDRESS                                                                  \
         union                                                                              \
         {                                                                                  \
            unsigned char           Dot[IPV4_ADDRESS_SIZE];         /**< @brief  An unsigned character array of size 4. Possible value is {192, 168, 0, 100}*/                        \
            uint32_t                Value;                          /**< @brief  A 32 bit unsigned integer value.*/                        \
         }
#endif

/**
* @defgroup CM_HAL CM HAL
*
* @brief Cable Modem HAL component provides interface that cable modem software developers can use to interface to RDK-B.
*
* @defgroup CM_HAL_TYPES  CM HAL Data Types
* @ingroup  CM_HAL
*
* @defgroup CM_HAL_APIS   CM HAL  APIs
* @ingroup  CM_HAL
*
**/


/**
 * @addtogroup CM_HAL_TYPES
 * @{
 */

/**********************************************************************
                STRUCTURE DEFINITIONS
**********************************************************************/

/**
 * @brief Represents the information about a downstream channel of a cable modem.
 *
 * Holds information about the downstream channel like channel ID, frequency, power level, SNR level,modulation, octets, correcteds and lock status.
 */

typedef  struct
_CMMGMT_CM_DS_CHANNEL {
    ULONG                           ChannelID;      /**< @brief It is an unsigned long value that represents the Channel ID.
                                                           The maximum value is (2^32)-1. 
                                                            Possible value is 11. */
    CHAR                            Frequency[64];  /**< @brief  It is a character array that represents the DS channel Frequency.
                                                                  Possible value is "6449". */
    CHAR                            PowerLevel[64]; /**< @brief  It is a character array that represents the DS channel Power Level.
                                                                 Possible value is "75.1 dBmV"  */
    CHAR                            SNRLevel[64];   /**< @brief  It is a character array that represents the DS channel SNR Level.
                                                                 Possible value is "50 dB".*/
    CHAR                            Modulation[64]; /**< @brief  It is a character array that represents the Modulation of the DS channel.
                                                                Possible Values is "QAM", "OFDM", "OFDMA", "UNKNOWN".*/
    ULONG                           Octets;         /**< @brief  It is an unsigned long value that represents the Octets.
                                                                 The maximum value is (2^32)-1.
                                                                  Possible Values is 123.*/
    ULONG                           Correcteds;     /**< @brief  It is an unsigned long value that represents the Correcteds.
                                                                The maximum value is (2^32)-1.
                                                                 It is a vendor specific value. Possible value is 100. */
    ULONG                           Uncorrectables; /**< @brief  It is an unsigned long value that represents the Uncorrectables.
                                                                 The maximum value is (2^32)-1.
                                                                 It is a vendor specific value. Possible value is 12.*/
    CHAR                            LockStatus[64]; /**< @brief  It is a character array that represents the DS Lock Status.
                                                                 Possible value is "Locked", "NotLocked".*/
}
CMMGMT_CM_DS_CHANNEL, *PCMMGMT_CM_DS_CHANNEL;

/**
 * @brief Represents the information about a upstream channel of a cable modem.
 *
 * Holds information about the upstream channel like channel ID, frequency, power level, ,channel type, symbol rate, modulation and lock status.
 */

typedef  struct
_CMMGMT_CM_US_CHANNEL {
    ULONG                           ChannelID;      /**< @brief It is an unsigned long value that represents the Channel ID of the US channel.
                                                                The maximum value is (2^32)-1. Possible value is 12. */
    CHAR                            Frequency[64];  /**< @brief  It is a character array that represents the Frequency of the US channel.
                                                                 Possible value is "12750".*/
    CHAR                            PowerLevel[64]; /**< @brief   It is a character array that represents the PowerLevel of the US channel.
                                                                  Possible value is "60".*/
    CHAR                            ChannelType[64];/**< @brief   It is a character array that represents the ChannelType of the US channel.
                                                                   Possible Values: "UNKNOWN","TDMA","ATDMA","SCDMA","TDMA_AND_ATDMA".*/
    CHAR                            SymbolRate[64]; /**< @brief  It is a character array that represents the SymbolRate of the US channel.
                                                                 Possible value is "115200". */
    CHAR                            Modulation[64]; /**< @brief  It is a character array that represents the Modulation of the US channel.
                                                                 Possible value is "QAM", "OFDM", "OFDMA", "UNKNOWN".*/

    CHAR                            LockStatus[64]; /**< @brief  It is a character array that represents the LockStatus.
                                                                 Possible value is: "Locked", "NotLocked". */

}
CMMGMT_CM_US_CHANNEL, *PCMMGMT_CM_US_CHANNEL;

/**
 * @brief Represents the information about DOCSIS of a cable modem.
 *
 * Holds information about various DOCSIS related information version downstream and upstream scannimg and ranging statuses, TFTP starus, DHCP attempts, cnfiguration file name,TFTP attempts, Time of Day status,BPI state, network access, upgrade server IP, maximum CPE allowed, service flow parameters,data rates for downstream and upstream and core version.
 */

typedef  struct
_CMMGMT_CM_DOCSIS_INFO
{
    CHAR                            DOCSISVersion[64];               /**< @brief It is a character array that represents the DOCSIS Version.
                                                                                 It is a vendor specific value. 
                                                                                 Possible Values are "other","1.0","1.1","2.0","3.0","3.1" */
    CHAR                            DOCSISDownstreamScanning[64];     /**< @brief It is a character array that represents the DOCSIS Downstream Scanning Status.
                                                                                   It is a vendor specific value. 
                                                                                   Possible Values are "NotStarted", "InProgress", "Complete".  */
    CHAR                            DOCSISDownstreamRanging[64];      /**< @brief  It is a character array that represents the DOCSIS Downstream Ranging Status.
                                                                                   It is a vendor specific value. 
                                                                                   Possible Values are "NotStarted", "InProgress", "Complete".*/
    CHAR                            DOCSISUpstreamScanning[64];       /**< @brief  It is a character array that represents the DOCSIS Upstream Scanning Status.
                                                                                   It is a vendor specific value. 
                                                                                   Possible Values are "NotStarted", "InProgress", "Complete".*/
    CHAR                            DOCSISUpstreamRanging[64];        /**< @brief  It is a character array that represents the DOCSIS Upstream Ranging Status.
                                                                                   It is a vendor specific value.  
                                                                                   Possible Values are "NotStarted", "InProgress", "Complete".*/
    CHAR                            DOCSISTftpStatus[64];             /**< @brief  It is a character array that represents the DOCSIS Tftp Status.
                                                                                   It is a vendor specific value. 
                                                                                   Possible Values are "NotStarted","In Progress" ,"Download Complete" .*/
    CHAR                            DOCSISDataRegComplete[64];        /**< @brief  It is a character array that represents the DOCSIS Data Reg Complete Status.
                                                                                   It is a vendor specific value. 
                                                                                   Possible Values are "In Progress" ,"Registration Complete" .*/
    ULONG                           DOCSISDHCPAttempts;               /**< @brief  It is an unsigned long value that represents the DOCSIS DHCP Attempts.
                                                                                   The maximum value is (2^32)-1. 
                                                                                   Possible Value is 3.*/
    CHAR                            DOCSISConfigFileName[64];         /**< @brief  It is a character array that represents the DOCSIS Config File Name.
                                                                                   Possible Value is "goldenjim.cm".*/
    ULONG                           DOCSISTftpAttempts;               /**< @brief  It is an unsigned long value that represents the DOCSIS Tftp Attempts.
                                                                                   The maximum value is (2^32)-1.*/
    CHAR                            ToDStatus[64];                    /**< @brief  It is a character array that represents the ToD Status.
                                                                                   Possible Values are "Complete", "NotStarted".*/
    BOOLEAN                         BPIState;                         /**< @brief  It is an boolean value that represents the BPIState. */
    BOOLEAN                         NetworkAccess;                    /**< @brief  It is an boolean value that represents the Network Access. */   
    ANSC_IPV4_ADDRESS               UpgradeServerIP;                  /**< @brief  It a ANSC_IPV4_ADDRESS union type value that represents the Upgrade Server IP.*/
    ULONG                           MaxCpeAllowed;                    /**< @brief  It is an unsigned long value that represents the Max Cpe Allowed.
                                                                                   The maximum value is (2^32)-1. */
    CHAR                            UpstreamServiceFlowParams[64];    /**< @brief  It is a character array that holds the Upstream Service Flow Params.
                                                                                   Possible value is "Dummy"*/
    CHAR                            DownstreamServiceFlowParams[64];  /**< @brief  It is a character array that represents the Downstream Service Flow Params.
                                                                                   Possible value is "Dummy"*/
    CHAR                            DOCSISDownstreamDataRate[64];     /**< @brief  It is a character array that represents the DOCSIS Downstream Data Rate.
                                                                                   Possible value is "20000".*/
    CHAR                            DOCSISUpstreamDataRate[64];       /**< @brief  It is a character array that represents the DOCSIS Upstream Data Rate.
                                                                                   Possible value is "10000".*/
    CHAR                            CoreVersion[64];                  /**< @brief  It is a character array that represents the Core Version.
                                                                                   Possible value is "1.0".*/
}
CMMGMT_CM_DOCSIS_INFO, *PCMMGMT_CM_DOCSIS_INFO;

/**
 * @brief Represents the information of errorcode words of a cable modem.
 *
 * Holds information about the error codewords including the number of unerrored, correctable and uncorrectable codewords.
 */

typedef  struct
_CMMGMT_CM_ERROR_CODEWORDS {
    ULONG                           UnerroredCodewords;       /**< @brief It is an unsigned long value that holds the Unerrored Codewords. 
                                                                          It is a vendor specific value. */
    ULONG                           CorrectableCodewords;     /**< @brief It is an unsigned long value that holds the Correctable Codewords.   
			                                                              It is a vendor specific value.*/
    ULONG                           UncorrectableCodewords;   /**< @brief  It is an unsigned long value that holds the Uncorrectable Codewords. 
			                                                               It is a vendor specific value.*/
}
CMMGMT_CM_ERROR_CODEWORDS, *PCMMGMT_CM_ERROR_CODEWORDS;

/*
typedef enum
{
    PRI_EMERGENCY = 1,
    PRI_ALERT,
    PRI_CRITICAL,
    PRI_ERROR,
    PRI_WARNING,
    PRI_NOTICE,
    PRI_INFORMATION,
    PRI_DEBUG,

    PRI_LAST = 0xffffffff

}CMMGMT_CM_EventMgrPriorit_e;
*/

#define EVM_MAX_EVENT_TEXT      255      /**< Maximum length of event text */

/**
 * @brief Represents the information of entry in the cable modem's event log.
 *
 * Holds information about an event log entry, including the event index, first and last time the event occured, event counts, event level, event ID and the text associated with the event.
 */

typedef struct
{
    UINT                docsDevEvIndex;                   /**< @brief It is an unsigned integer value that represents the snmp docsDevEvIndex.
                                                                      The maximum value is (2^16)-1. 
                                                                      Possible value is 1. */
    struct timeval      docsDevEvFirstTime;               /**< @brief  It is a struct timeval type structure that holds the local date and time when this event was generated.*/
    struct timeval      docsDevEvLastTime;                /**< @brief  It is a struct timeval type structure that holds the local date and time when this event was generated.*/
    UINT                docsDevEvCounts;                  /**< @brief  It is an unsigned integer value that represents the docsDevEvCounts.
                                                                       The maximum value is (2^16)-1.
                                                                        Possible value is 1.*/
    UINT                docsDevEvLevel;                   /**< @brief  It is an unsigned integer value that represents the DOCSIS priority level associated with the event. Possible value is 1.*/
    UINT                docsDevEvId;                      /**< @brief  The maximum value is (2^16)-1. It is an unsigned integer value that represents the numeric identifier of the event. 
                                                                       The maximum value is (2^16)-1. 
                                                                        Possible value is 1.*/
    CHAR                docsDevEvText[EVM_MAX_EVENT_TEXT]; /**< @brief  It is a character array that represents the the numeric identifier of the event.
                                                                        It is a vendor specific value.*/

}CMMGMT_CM_EventLogEntry_t;
/**
 * @brief Represents the configuration settings of CM logging.
 *
 * Holds information of the configuration settings of CM logging related to CM logging and if the Docsis log should be cleared.
 */

typedef  struct
_CMMGMT_DML_CM_LOG {
    BOOLEAN                         EnableLog;             /**< @brief  Represents whether the CM logging is enabled*/
    BOOLEAN                         ClearDocsisLog;        /**< @brief  Represents whether to clear the  Docsis Log*/
}
CMMGMT_DML_CM_LOG,  *PCMMGMT_DML_CM_LOG;

/**
 * @brief Represents the information for a Docsis log entry.
 *
 * Holds information related to the Docsis log entry like the index, event ID, event level, timestamp and description.
 */
 
typedef  struct
_CMMGMT_DML_DOCSISLOG_FULL {
    ULONG                           Index;         /**< @brief  Index of Docsis log entry*/
    ULONG                           EventID;       /**< @brief  Event ID associated with the log entry*/
    ULONG                           EventLevel;    /**< @brief  Event level of the log entry*/
    CHAR                            Time[64];      /**< @brief  Timestamp of the log entry*/
    CHAR                            Description[256]; /**< @brief  Description of log entry*/
}
CMMGMT_DML_DOCSISLOG_FULL,  *PCMMGMT_DML_DOCSISLOG_FULL;

/**
 * @brief Represents the information of DHCP configuration of a cable modem.
 *
 * Holds information about the DHCP configuration like the IP Address, boot file name, subnet mask, gateway, TFTP server, time server, time offset, remaining lease time, remaining rebind time, remaining renew time, MAC address and DOCSIS DHCP status.
 */

typedef  struct
_CMMGMT_CM_DHCP_INFO
{
    ANSC_IPV4_ADDRESS               IPAddress;              /**< @brief  It a ANSC_IPV4_ADDRESS union type value that represents the IP Address.
                                                                         Possible values is "IPAddress.Dot = {192, 168, 0, 100}".*/
    CHAR                            BootFileName[64];       /**< @brief  It is a character array that represents the Boot File Name. Possible values is "ccsp.boot".*/
    ANSC_IPV4_ADDRESS               SubnetMask;             /**< @brief  It a ANSC_IPV4_ADDRESS union type value that represents the Subnet Mask.
                                                                         Possible values is "SubnetMask.Dot = {255, 255, 255, 0}".*/
    ANSC_IPV4_ADDRESS               Gateway;                /**< @brief  It a ANSC_IPV4_ADDRESS union type value that represents the Gateway.
                                                                         Possible values is "Gateway.Dot={192, 168, 0, 1}".*/
    ANSC_IPV4_ADDRESS               TFTPServer;             /**< @brief  It a ANSC_IPV4_ADDRESS union type value that represents the TFTP Server.
                                                                         Possible values is "TFTPServer.Dot = {192, 168, 0, 10}".*/
    CHAR                            TimeServer[64];         /**< @brief  It is a character array that represents the Time Server. Possible values is "ntp.cisco.com"*/
    INT                             TimeOffset;             /**< @brief  It is an integer value. The maximum value is (2^31)-1 that represents the Time Offset. Possible values is 8.*/
    ULONG                           LeaseTimeRemaining;     /**< @brief  It is an unsigned long value that represents the Lease Time Remaining. The maximum value iss 0 to (2^32)-1. Possible values is 3600.*/
    CHAR                            RebindTimeRemaining[64]; /**< @brief It is a character array that represents the Rebind Time Remaining. Possible values is 3700.*/
    CHAR                            RenewTimeRemaining[64];  /**< @brief It is a character array that represents the Renew Time Remaining. Possible values is 1200. */
    CHAR                            MACAddress[64];          /**< @brief  It is a character array that represents the MAC Address. Possible values is "00:1A:2B:11:22:33".*/
    CHAR                            DOCSISDHCPStatus[64];     /**< @brief  It is a character array that represents the DOCSIS DHCP Status. Possible values is "Complete".*/
}
CMMGMT_CM_DHCP_INFO, *PCMMGMT_CM_DHCP_INFO;

/**
 * @brief Represents the information of IPv6 DHCP configuration of a cable modem.
 *
 * Holds information about the IPv6 DHCP configuration like the IPv6 address, IPv6 boot file name, IPv6 prefix, IPv6 router, IPv6 TFTP server, IPv6 time server, remaining IPv6 lease time, remaining IPv6 rebind time and remaining IPv6 renew time.
 */

typedef  struct
_CMMGMT_CM_IPV6DHCP_INFO
{
    CHAR                            IPv6Address[40];             /**< @brief  It is a character array that represents the IPv6 Address.
                                                                              Possible value is "2012:cafe:100::1".*/
    CHAR                            IPv6BootFileName[64];        /**< @brief  It is a character array that represents the IPv6 Boot File Name. 
                                                                              Possible value is "ccsp.v6.boot".*/
    CHAR                            IPv6Prefix[40];               /**< @brief  It is a character array that represents the IPv6 Prefix. 
                                                                               Possible value is 2012:cafe::/32.*/
    CHAR                            IPv6Router[40];               /**< @brief  It is a character array that represents the IPv6 Router.
                                                                               Possible value is 2012:cafe::1.*/
    CHAR                            IPv6TFTPServer[40];           /**< @brief  It is a character array that represents the IPv6 TFTP Server.
                                                                               Possible value is "2012:cafe::2".*/
    CHAR                            IPv6TimeServer[40];            /**< @brief  It is a character array that represents the IPv6 Time Server. 
                                                                                Possible value is "ntp.cisco.com"*/
    ULONG                           IPv6LeaseTimeRemaining;         /**< @brief It is an unsigned long value that represents the IPv6 Lease Time Remaining. 
                                                                                The maximum value is(2^32)-1. 
                                                                                Possible value is 3600.*/
    ULONG                           IPv6RebindTimeRemaining;        /**< @brief  It is an unsigned long value that represents the IPv6 Rebind Time Remaining. 
                                                                                 The maximum value is (2^32)-1. 
                                                                                 Possible value is 3700.*/
    ULONG                           IPv6RenewTimeRemaining;         /**< @brief  It is an unsigned long value that represents the IPv6 Renew Time Remaining. 
                                                                                 The maximum value is (2^32)-1. 
                                                                                 Possible value is 1200.*/
}
CMMGMT_CM_IPV6DHCP_INFO, *PCMMGMT_CM_IPV6DHCP_INFO;

/**
 * @brief Represents the list of customer premises equipment.
 *
 * Holds information about the customer premises equipment including the IP address and MAC address.
 */

typedef  struct
_CMMGMT_DML_CPE_LIST
{
    CHAR                            IPAddress[32];      /**< @brief  It is a character array that contains the IP Address of the CPE. 
                                                                     Possible value is 192.168.0.1.*/
    CHAR                            MACAddress[32];     /**< @brief  It is a character array that contains the MAC Address of the CPE. 
                                                                     The MAC Address should be in the format AA:BB:CC:DD:EE:FF (colon-separated).*/
}
CMMGMT_DML_CPE_LIST,  *PCMMGMT_DML_CPE_LIST;


/**
 * @brief Represents the information about a DOCSIS 3.1 OFDM downstream channel in a cable modem.
 *
 * Holds information about the parameters associated with a DOCSIS 3.1 OFDM downstream channel including channel ID, subcarrier spacing, subcarrier frequencies, active subcarriers, subcarrier spacing, cyclic prefix, roll-off period, PLC frequency, number of pilots, time interleaver depth, average SNR, power level, PLC codewords, unreliable PLC codewords,NCP fields and NCP field CRC failures.
 */

//>> Docsis3.1
typedef struct _DOCSIF31_CM_DS_OFDM_CHAN {
    unsigned int ChannelId;                     /**< @brief The Cable Modem Termination System identification of the OFDM downstream channel within this particular MAC interface. if the interface is down, the object returns the most current value.  If the downstream channel ID is unknown, this object returns a value of 0. */
    unsigned int ChanIndicator;                 /**< @brief This data type defines the subcarrier spacing for the FFT mode in use. For downstream OFDM channels, if the FFT mode is 4K mode, then spacing is 50 kHz; if it is 8K mode, then the spacing is 25 kHz. For upstream OFDMA channels, if the FFT mode is 2K mode, then the spacing is 50kHz; if the mode is 4K mode, then the spacing is 25kHz. In units of kHz. other(1), primary(2), backupPrimary(3), nonPrimary(4) */
    unsigned int SubcarrierZeroFreq;            /**< @brief The center frequency of the subcarrier 0 of the OFDM transmission. Note that since ubcarrier 0 is always excluded, it will actually be below the allowed downstream spectrum band. This is the frequency of subcarrier X(0) in the definition of the DFT. */
    unsigned int FirstActiveSubcarrierNum;      /**< @brief The number of the first non-excluded subcarrier. The valid range is 148 to 7895 */
    unsigned int LastActiveSubcarrierNum;       /**< @brief The number of the last non-excluded subcarrier. The valid range is 148 to 7895 */
    unsigned int NumActiveSubcarriers;          /**< @brief The number of active data subcarriers within the OFDM downstream channel (i.e. this exclude subcarriers for continuous pilots and the PLC). For 4K FFT mode, the maximum number of subcarriers including continuous pilots and the PLC cannot exceed 3800, and for 8K FFT mode, the maximum number of active subcarriers including continuous pilots and the PLC cannot be greater than 7600. */
                                                /**< @brief There are a minimum of 56 continuous pilots in a 192MHz channel that has no exclusions, and the size of the PLC is 8 subcarriers for 4K FFT mode and 16 subcarriers for 8K FFT mode. Therefore the maximum value of NumActiveSubcarriers is 3736 (or 3800 - 56 - 8) for 4K FFT mode and 7528 (or 7600 - 56 - 16) for 8K FFT mode. */
    unsigned int SubcarrierSpacing;             /**< @brief The subcarrier spacing associated with a particular FFT mode configured on the OFDM downstream channel. If it is 4K mode, then the subcarrier spacing is 50kHz. If it is 8K mode, then the subcarrier spacing is 25kHz (in kHz) */
    unsigned int CyclicPrefix;                  /**< @brief Cyclic prefix enables the receiver to overcome the effects of inter-symbol-interference and intercarrier-interference caused  by micro-reflections in the channel. There are five possible alues for the length of the CP and the choice depends on the delay spread of the channel - a longer delay spread requires a longer cyclic prefix. The cyclic prefix (in usec) are converted into samples using the sample rate of 204.8 Msamples/s and is an integer multiple of: 1/64 * 20 us. */
    unsigned int RollOffPeriod;                 /**< @brief Roll off period maximizes channel capacity by sharpening the edges of the spectrum of the OFDM signal. For windowing purposes another segment at the start of the IDFT output is appended to the end of the IDFT output - the roll-off postfix (RP). There are five possible values for the (RP), and the choice depends on the bandwidth of the channel and the number of exclusion bands within the channel. A larger RP provides sharper edges in the spectrum of the OFDM signal; however,  there is a time vs. frequency trade-off. Larger RP values reduce the efficiency of transmission in the time domain, but because the spectral edges are sharper, more useful subcarriers appear in the frequency domain. There is an optimum value for the RP that maximizes capacity for a given bandwidth and/or exclusion band scenario. */
    unsigned int PlcFreq;                       /**< @brief This is the PHY Link Channel (PLC) frequency. It is the center frequency of the lowest frequency subcarrier of the PLC. The aim of the PLC is for the CMTS to convey to the CM the physical properties of the OFDM channel */
    unsigned int NumPilots;                     /**< @brief The number of continuous pilots configured for the OFDM downstream channel as received in the OCD message. */
    unsigned int TimeInterleaverDepth;          /**< @brief The time interleaving used for this downstream channel as received in the OCD message. */
    char averageSNR[OFDM_PARAM_STR_MAX_LEN];    /**< @brief The averageSNR value of this downstream channel */
    char PowerLevel[OFDM_PARAM_STR_MAX_LEN];    /**< @brief The power level of this downstream channel */
    unsigned long long PlcTotalCodewords;       /**< @brief The total number of PLC codewords received by the CM. */
    unsigned long long PlcUnreliableCodewords;  /**< @brief The total number of PLC codewords which failed post-decoding LDPC syndrome check. */
    unsigned long long NcpTotalFields;          /**< @brief The total number of NCP fields received by the CM. */
    unsigned long long NcpFieldCrcFailures;     /**< @brief The total number of NCP fields received by the CM which failed the CRC check. */

} DOCSIF31_CM_DS_OFDM_CHAN, *PDOCSIF31_CM_DS_OFDM_CHAN;


/**
 * @brief Represents information about a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
 *
 * Holds information about various parameters of DOCSIS 3.1 OFDMA upstream channel like Channel ID,Configuration change count, subcarrier frequencies, active subcarriers, subcarrier spacing., cycling prefix, roll-off period, number of symbols per frame, transmit power and pre-equalization status.
 */


typedef struct _DOCSIF31_CM_US_OFDMA_CHAN {
    unsigned int ChannelId;                     /**< @brief The Cable Modem identification of the OFDMA upstream channel within this particular MAC interface. If the interface is down, the object returns the most current value.  If the upstream channel ID is unknown, this object returns a value of 0. */
    unsigned int ConfigChangeCt;                /**< @brief The value of the Configuration Change Count field in the Upstream Channel Descriptor (UCD) MAC Management Message corresponding to this OFDMA channel. */
    unsigned int SubcarrierZeroFreq;            /**< @brief The lower edge frequency of the OFDMA upstream channel in Hz */
    unsigned int FirstActiveSubcarrierNum;      /**< @brief The upper edge of the OFDMA upstream channel. The minimum channel width for an OFDMA upstream channel is 6.4 MHz in 4K mode and 10MHz in 2K mode. The valid range is 74 to 3947. */
    unsigned int LastActiveSubcarrierNum;       /**< @brief The last active subcarrier number. The valid range is 74 to 3947. */
    unsigned int NumActiveSubcarriers;          /**< @brief The number of active subcarriers within the OFDMA upstream channel. The valid range is 1 to 3800. */
    unsigned int SubcarrierSpacing;             /**< @brief The subcarrier spacing associated with a particular FFT mode configured on the OFDMA upstream channel. If it is 2K mode, then the subcarrier spacing is 50kHz. If it is 4K mode, then the subcarrier spacing is 25kHz. */
    unsigned int CyclicPrefix;                  /**< @brief Cyclic prefix is added in order to enable the receiver to overcome the effects of inter-symbol interference (ISI) and inter-carrier interference caused by microreflections in the channel. The cyclic prefix (in usec) is converted into samples using the sample rate of 102.4 Msamples/s. There are eleven values for the length of the CP and the choice depends on the delay spread of the channel; a longer delay spread requires a longer cyclic prefix. */
    unsigned int RollOffPeriod;                 /**< @brief Windowing is applied in order to maximize channel capacity by sharpening the edges of the spectrum of the OFDMA signal. Windowing is applied in the time domain by tapering (or rolling off) the edges using a raised cosine function. There are eight possible values of roll-off prefix. The Roll-Off Period is given in us and in number of samples using the sample rate of 102.4 Msamples/s. The configuration where Roll-off prefix value is greater than or equal to cyclic prefix value is considered invalid. */
    unsigned int NumSymbolsPerFrame;            /**< @brief The number of symbol periods per frame. For channel bandwidth greater than 72MHz, the maximum number of symbol periods per frame is 18 for 2K mode and 9 for 4K mode. For channel bandwidth less than 72 MHz but greater than 48MHz, the maximum number of symbols per frame is 24 for 2K mode and 12 for 4K mode. For channel bandwidth less than 48MHz, the maximum number of symbol periods is 36 for 2K mode and 18 for 4K mode. The minimum number of symbol periods per frame is 6 for both the FFT modes and is independent of the channel bandwidth. */
    unsigned int TxPower;                       /**< @brief The operational transmit power for the associated OFDMA upstream channel.The CM reports its Target Power, P1.6r_n as described in [PHYv3.1]. Valid values for this object are 68 to (213 + (4*(Pmax - 65 dBmV))), since 68 quarter dBmV represents the lowest Tx power value 17 dBmV and 213 represents the nearest quarter dBmV to the highest Tx power value 53.2 dBmV. */
    unsigned char PreEqEnabled;                          /**< @brief Whether pre-equalization is enabled on the associated OFDMA upstream channel. */
} DOCSIF31_CM_US_OFDMA_CHAN, *PDOCSIF31_CM_US_OFDMA_CHAN;


/**
 * @brief Represents information about a DOCSIS 3.1 OFDMA upstream channel in a cable modem.
 *
 *
 * Holds information about various parameters of DOCSIS 3.1 OFDMA upstream channel like Channel ID, T3 timeouts, T4 timeouts, ranging aborts, excessive T3 timeouts, muting status and ranging status.
 */

typedef struct _DOCSIF31_CMSTATUSOFDMA_US {
    // The full definitions for the fields below can be referenced within DOCS-IF31-MIB.
    unsigned int ChannelId;                     /**< @brief The Cable Modem identification of the OFDMA upstream channel within this particular MAC interface. If the interface is down, the object returns the most current value.If the upstream channel ID is unknown,this object returns a value of 0.*/
    unsigned int T3Timeouts;                    /**< @brief Number of T3 counter timeouts. */
    unsigned int T4Timeouts;                    /**< @brief Number of T4 counter timeouts.*/
    unsigned int RangingAborteds;               /**< @brief Number of times ranging process has been aborted.*/
    unsigned int T3Exceededs;                   /**< @brief Number of excessive T3 timeouts.*/
    unsigned char IsMuted;                      /**< @brief Indicates if upstream channel is muted.*/
    unsigned int RangingStatus;                 /**< @brief Ranging State of CM: other(1),aborted(2),retriesExceeded(3),success(4),continue(5),timeoutT4(6)*/
} DOCSIF31_CMSTATUSOFDMA_US, *PDOCSIF31_CMSTATUSOFDMA_US;
//<< Docsis3.1

#define MAX_KICKSTART_ROWS 5   /**< Maximum number of rows of kickstart*/


/**
 * @brief Represents the fixed-length buffer.
 *
 * Holds information about the fixed-length buffer with a specified length and a pointer to the buffer data .
 */

typedef struct _fixed_length_buffer {
    USHORT length;                               /**< @brief length variable is unsigned short. 
                                                             The maximum value is (2^16)-1.*/
    UINT8 *buffer;                               /**< @brief buffer variable is unsigned charcter pointer. 
                                                             It is a variable that can store an integer value.
                                                             The maximum value is (2^8)-1. */
} fixed_length_buffer_t;

/**
 * @brief Represents a row in the SNMPv3 kickstart.
 *
 * Holds information about the fixed length buffer for security name and security number .
 */

typedef struct _snmpv3_kickstart_row {
    fixed_length_buffer_t security_name;          /**< @brief  Fixed length buffer for the security name */
    fixed_length_buffer_t security_number;        /**< @brief  Fixed length buffer for the security number*/
} snmp_kickstart_row_t;


/**
 * @brief Represents a SNMPv3 kickstart table.
 *
 * Holds information about the SNMPv3 kickstart table including the number of rows and an array of SNMPv3 kickstart rows.
 */

typedef struct _snmpv3_kickstart_table {
    UINT8 n_rows;                                                /**< @brief It is an unsigned character contains the count of snmp kickstart rows. */
    snmp_kickstart_row_t *kickstart_values[MAX_KICKSTART_ROWS];  /**< @brief It is a pointer array of size 5 contains list of snmp kickstart rows, with security_name and security_number. */
} snmpv3_kickstart_table_t;

/**
 * @brief Represents the diplexer settings for cable modem.
 *
 * Holds information about the diplexer settings for both upstream and downstream channels including the upper edge frequency in megahertz (MHz).
 */

typedef  struct
_CM_DIPLEXER_SETTINGS
{
    UINT    usDiplexerSetting; /**< @brief Unsigned integer representing the Upper Edge in MHz. It is a Vendor specific value.*/
    UINT    dsDiplexerSetting; /**< @brief Unsigned integer representing the Upper Edge in MHz. It is a Vendor specific value.*/
}
CM_DIPLEXER_SETTINGS;

/** @} */  //END OF GROUP CM_HAL_TYPES


/**********************************************************************************
 *
 *  CM Subsystem level function prototypes
 *
**********************************************************************************/

/*
 * TODO:
 *
 * 1. Extend the return codes by listing out the possible reasons of failure, to improve the interface in the future.
 *    This was reported during the review for header file migration to opensource github.
 *
 */

/**
 * @addtogroup CM_HAL_APIS
 * @{
 */


/**
* @brief Retrieves the global information for all shared DBs and makes them accessible locally.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
INT cm_hal_InitDB(void);

/**
* @brief Init global PHY level info and DBs and get direct access to DS HW.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
INT docsis_InitDS(void);

/**
* @brief Init global PHY level info and DBs and get direct access to US HW.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
INT docsis_InitUS(void);

/**
* @brief Retrieve, format and output the Cable Modem DOCSIS status.
* @param[out] cm_status Pointer to a character array that will hold the Cable Modem DOCSIS status string to be returned.
*                       \n The maximum size allocated should be atleast 700 bytes.
*                       \n  Possible Status values are "Unsupported status","OTHER","NOT_READY","NOT_SYNCHRONIZED","PHY_SYNCHRONIZED","US_PARAMETERS_ACQUIRED","RANGING_COMPLETE","DHCPV4_COMPLETE","TOD_ESTABLISHED","SECURITY_ESTABLISHED","CONFIG_FILE_DOWNLOAD_COMPLETE","REGISTRATION_COMPLETE","OPERATIONAL","ACCESS_DENIED","EAE_IN_PROGRESS","DHCPV4_IN_PROGRESS","DHCPV6_IN_PROGRESS","DHCPV6_COMPLETE","REGISTRATION_IN_PROGRESS","BPI_INIT","FORWARDING_DISABLED","DS_TOPOLOGY_RESOLUTION_IN_PROGRESS","RANGING_IN_PROGRESS",
*                           "RF_MUTE_ALL"
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*/
INT docsis_getCMStatus(CHAR *cm_status);

/**
* @brief Retrieve all the relevant DS channel info from global DBs.
* @param[out] ppinfo Pointer to PCMMGMT_CM_DS_CHANNEL structure that will hold all the info of DS channel to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*
*
*/
INT docsis_GetDSChannel(PCMMGMT_CM_DS_CHANNEL * ppinfo);

/**
* @brief Retrieve all the relevant US channel info from global DBs.
* @param[in]  i     Index to the US channel. It ranges from 0 to n where n is an unsigned short value.
* @param[out] pinfo Info of one US channel, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT docsis_GetUsStatus(USHORT i, PCMMGMT_CM_US_CHANNEL pinfo);

/**
* @brief Retrieve particular US channel information from global DBs.
* @param[out] ppinfo Pointer to a PCMMGMT_CM_US_CHANNEL structure that will hold all the info of the specific US channel, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT docsis_GetUSChannel(PCMMGMT_CM_US_CHANNEL * ppinfo);

/**
* @brief Retrieve current DOCSIS registration status and report it.
* @param[out] pinfo DOCSIS Registration info, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
INT docsis_GetDOCSISInfo(PCMMGMT_CM_DOCSIS_INFO pinfo);

/**
* @brief Retrieve number of US channels actively in use in current registration.
* @param[out] cnt Pointer to an unsigned long variable that will store the number of active US channels, to be returned.
*                 \n The maximum size allocated should be atleast 100 bytes.
*                 \n It represents a vendor-specific value.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT docsis_GetNumOfActiveTxChannels(ULONG * cnt);

/**
* @brief Retrieve number of DS channels actively in use in current registration.
* @param[out] cnt Pointer to an unsigned long variable that will store the number of active DS channels, to be returned.
*                 \n The maximum size allocated should be atleast 100 bytes.
*                 \n It represents a vendor-specific value.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT docsis_GetNumOfActiveRxChannels(ULONG * cnt);

/**
* @brief Scan all active DS channels and report errors in packets received.
* @param[out] ppinfo Pointer to a PCMMGMT_CM_ERROR_CODEWORDS structure holding the error info retrieved.
*                    \n The maximum size allocated should be atleast 24 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*
*/
INT docsis_GetErrorCodewords(PCMMGMT_CM_ERROR_CODEWORDS * ppinfo);

/**
* @brief Retrieve the current MIMO status.
* @param[out] pValue Pointer to character array holding the current IP Provisioning Mode retrieved.
*                    \n Possible Values are "ipv4Only" , "ipv6Only" , "APM" , "DualStack" , "honorMdd" , "not defined".
*                    \n It is possible to return APM (2) and DualStack (3), but only ipv4Only(0) , ipv6Only (1) and hornorMdd (4) can be set.
*                    \n The maximum size allocated should be atleast 64 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*
*
*/
INT docsis_GetMddIpModeOverride(CHAR *pValue);

/**
* @brief Set the current global MIMO status.
* @param[in] pValue Value that the IP Provisioning Mode is to be set to.
*                   \n Possible Values are ipv4Only (0), ipv6Only (1), APM (2), DualStack (3), honorMdd (4), ""
*                   \n It is possible to return APM (2) and DualStack (3), but only ipv4Only(0) , ipv6Only (1) and hornorMdd (4) can be set. Refer docsIf3CmMdCfgIpProvMode.
*                   \n The maximum size allocated should be atleast 64 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT docsis_SetMddIpModeOverride(CHAR *pValue);

/**
* @brief Retrieve the US channel ID in its MAC domain.
*
* @return UINT8 - Channel ID.
*
*
*
*/
UINT8 docsis_GetUSChannelId(void);

/**
* @brief Set the US channel ID in its MAC domain.
* @param[in] index It is integer value which provides index to set the Upstream Channel ID to.
*                  \n The maximum value is (2^31)-1.
*                  \n Possible Example: 12.
*
*
*/
void docsis_SetUSChannelId(INT index);

/**
* @brief Retrieve the current primary channel DS channel frequency from the LKF table.
*
* @return ULONG - channel frequency.
*
* 
*
*
*/
ULONG docsis_GetDownFreq(void);

/**
* @brief Change the DS primary channel frequency in the LKF table.
* @param[in] value  It is an unsigned long value which provides primary channel frequency value that is to be set.
*                  \n The maximum value is (2^32)-1. Example: 12750.
*
*
*/
void docsis_SetStartFreq(ULONG value);

/**
* @brief Retrieve the DOCSIS event log entries and display it.
* @param[out] *entryArray entries to be returned.
*
* @param[in] len Length of log entries.
*                \n It is integer datatype. The maximum value is (2^32)-1.
*
* @return INT - number of log entries retrieved.
*
*
* 
*
*
*/
INT docsis_GetDocsisEventLogItems(CMMGMT_CM_EventLogEntry_t *entryArray, INT len);

/**
* @brief Clear the DOCSIS event log.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
* 
*
*
*/
INT docsis_ClearDocsisEventLog(void);

/**
* @brief Retrieve all the relevant DHCP info for this CM.
* @param[out] pInfo All DHCP info for CM, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT cm_hal_GetDHCPInfo(PCMMGMT_CM_DHCP_INFO pInfo);

/**
* @brief Retrieve all the relevant IPv6 DHCP info for this CM.
* @param[out] pInfo All IPv6 DHCP info for CM, to be returned.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT cm_hal_GetIPv6DHCPInfo(PCMMGMT_CM_IPV6DHCP_INFO pInfo);

/**
* @brief Retrieve list of CPEs connected to the CM.
* @param[out] ppCPEList List of all CPE, to be returned.
*
* @param[out] InstanceNum Pointer to the number of instances, to be returned.
*                         The possibe range of acceptable values is 0 to (2^32)-1.
* @param[in]  LanMode     Input of "router" or "bridge" mode of the modem.
*                         \n The maximum size allocated should be atleast 100 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
* 
*
*
*
*/
INT cm_hal_GetCPEList(PCMMGMT_DML_CPE_LIST * ppCPEList, ULONG* InstanceNum, CHAR* LanMode);

/**
* @brief Retrieve the market of this modem.
* @param[out] market Pointer to the character array containing the name of the market for this modem, "US" or "EURO", to be returned
*                       \n The maximum size allocated should be atleast 100 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT cm_hal_GetMarket(CHAR* market);

/* HTTP Download HAL API Prototype */

/* cm_hal_Set_HTTP_DL_Url  - 1 */

/**
* @brief Set Http Download Settings.
* @param[in] pHttpUrl   HTTP download URL to be stored in HTTP download config file.
*                       \n The maximum size allocated should be atleast 60 bytes.
*                       \n Possible value is "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[in] pfilename  HTTP download filename to be stored in HTTP download config file.
*                       \n The maximum size allocated should be atleast 60 bytes.
*                       \n Possible value is "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT"
*
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any Downloading is in process or Url string is invalided.
*
*
*/
INT cm_hal_Set_HTTP_Download_Url (char* pHttpUrl, char* pfilename);

/**
* @brief Get Http Download Url.
* @param[out] pHttpUrl  HTTP download URL fetched from HTTP download config file.
*                       \n The maximum size allocated should be atleast 200 bytes.
*                       \n Possible value is "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[out] pfilename HTTP download filename fetched from HTTP download config file.
*                       \n The maximum size allocated should be atleast 200 bytes.
*                       \n Possible value is "CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT"
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
*                      \n The maximum size allocated should be atleast 100 bytes.
*
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*/
/* interface=0 for wan0, interface=1 for erouter0 */
INT cm_hal_Set_HTTP_Download_Interface(unsigned int interface);

/**
* @brief Get the HTTP Download Interface
* @param[out] pinterface Interface numerical value to be fetched from the config file.
*                        \n Values: interface=0 for wan0, interface=1 for erouter0.
*                        \n The buffer size should be atleast 100 bytes long.
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
/* interface=0 for wan0, interface=1 for erouter0 */
INT cm_hal_Get_HTTP_Download_Interface(unsigned int* pinterface);

/* cm_hal_HTTP_Download - 3 */
/**
* @brief Start Http Download.
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any Downloading is in process.
*
* 
*
*/
INT cm_hal_HTTP_Download ();

/* cm_hal_ Get_HTTP_Download _Status ? 4 */
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

/* cm_hal_Reboot_Ready - 5 */
/**
* @brief Get the Reboot Ready Status.
* @param[out] *pValue Pointer to the integer containing Reboot Ready Status.
*                     \n It is a unsigned long value.
*                     \n The maximum size allocated should be atleast 100 bytes.
*
* @return the status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
INT cm_hal_Reboot_Ready(ULONG *pValue);

/* cm_hal_HTTP_DL_Reboot_Now - 6*/
/**
* @brief Http Download Reboot Now.
* @return the status of the reboot operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any reboot is in process.
*/
INT cm_hal_HTTP_Download_Reboot_Now();

/**
* @brief Firmware update and factory reset the device.
* @param[in] pUrl       Url for cm_hal_Set_HTTP_Download_Url. NULL for snmp.
*                         \n It is variable of character pointer datatype.
*                         \n The maximum size allocated should be atleast 1024 bytes.
*                         \n Possible value is "https://ci.xconfds.coast.xcal.tv/featureControl/getSettings"
* @param[in] pImagename Imagename for cm_hal_Set_HTTP_Download_Url. NULL for snmp.
*                         \n It is variable of character pointer datatype.
*                         \n The maximum size allocated should be atleast 1024 bytes.
*                         \n Possible value is CGM4331COM_DEV_23Q3_sprint_20230817053130sdy_GRT
*
* @return the status of the Firmware update and factory reset operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any reboot is in process.
*
*
*/
INT cm_hal_FWupdateAndFactoryReset(char* pUrl, char* pImagename);

/**
* @brief Reinit CM.  Performs reinit MAC only to same DS/US.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
* 
*
*
*/
INT cm_hal_ReinitMac();

/**
* @brief Retrieve the provisioned wan0 IP type.
* @param[out] pValue Integer pointer containing the ip type currently provisioned on wan0.
*                    \n It is variable of character pointer datatype.
*                    \n The maximum size allocated should be atleast 100 bytes.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*/
INT docsis_GetProvIpType(CHAR *pValue);

/**
* @brief Retrieve the location of the certificate.
* @param[out] pCert Pointer to character array holding the certificate location, to be returned.
*                   \n It is variable of character pointer datatype.
*                   \n The maximum size allocated should be atleast 100 bytes.
*                   \n Possible Value is "/nvram/cmcert.bin".
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT docsis_GetCert(CHAR* pCert);

/**
* @brief Retrieve status of the certificate.
* @param[out] pVal Pointer to value containing the certificate status, to be returned.
*                  \n It is a unsigned long value.
*                  \n The maximum size allocated should be atleast 100 bytes.
*                  \n Possible Values is 0 or 1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*/
INT docsis_GetCertStatus(ULONG *pVal);

/**
* @brief Retrieve the count of cable modem reset
* @param[out] resetcnt Pointer to the count of cable modem resets, to be returned.
*                      \n It is a unsigned long value.
*                      \n The maximum size allocated should be atleast 100 bytes.
*                      \n Possible value is 1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/
INT cm_hal_Get_CableModemResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of local reset.
* @param[out] resetcnt Pointer to the count of local cable modem resets.
*                      \n It is a unsigned long value.
*                      \n The maximum size allocated should be atleast 100 bytes.
*                      \n Possible value is 2.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/

INT cm_hal_Get_LocalResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of docsis reset.
* @param[out] resetcnt Pointer to the count of docsis resets.
*                      \n It is a unsigned long value.
*                      \n The maximum size allocated should be atleast 100 bytes.
*                      \n Possible value is 3.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/

INT cm_hal_Get_DocsisResetCount(ULONG *resetcnt);

/**
* @brief Retrieve the count of erouter reset.
* @param[out] resetcnt Pointer to the count of erouter resets.
*                      \n It is a unsigned long value.
*                      \n The maximum size allocated should be atleast 100 bytes.
*                      \n Possible value is 4.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/

INT cm_hal_Get_ErouterResetCount(ULONG *resetcnt);

/**
* @brief Enable/Disable HTTP LED Flashing.
* @param[in] LedFlash Enable/Disable LED Flash. It is a Boolean value.
*                           \n Possible values is 1 to enable LEDFlash or 0 to disable.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/

INT cm_hal_HTTP_LED_Flash( BOOLEAN LedFlash );

//>> Docsis3.1
/**
* @brief Get the Downstream DSOF channel table (docsIf31CmDsOfdmChanTable).
* @param[out] ppinfo Pointer to get the return array.
*
* @param[out] output_NumberOfEntries Array size needs to be returned with output_NumberOfEntries. The maximum value is (2^31)-1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
* @note HAL function need to allocate the array of DOCSIF31_CM_DS_OFDM_CHAN and return with ppinfo.
*
*/
INT docsis_GetDsOfdmChanTable(PDOCSIF31_CM_DS_OFDM_CHAN *ppinfo, int *output_NumberOfEntries);

/**
* @brief Get the Upstream DSOFA channel table (docsIf31CmUsOfdmaChanTables).
* @param[out] ppinfo Pointer to get the return array.
*
* @param[out] output_NumberOfEntries variable is a integer pointer. The maximum value is (2^31)-1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
* @note HAL function need to allocate the array of DOCSIF31_CM_US_OFDMA_CHAN and return with ppinfo.
*
*/
INT docsis_GetUsOfdmaChanTable(PDOCSIF31_CM_US_OFDMA_CHAN *ppinfo, int *output_NumberOfEntries);

/**
* @brief Get the Upstream DSOFA channel status table (docsIf31CmStatusOfdmaUsTable)
* @param[out] ppinfo variable is a pointer to get the return array.
*
* @param[out] output_NumberOfEntries variable is a integer pointer. The maximum values is (2^31)-1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
* @note HAL function need to allocate the array of DOCSIF31_CMSTATUSOFDMA_US and return with ppinfo.
*
*/
INT docsis_GetStatusOfdmaUsTable(PDOCSIF31_CMSTATUSOFDMA_US *ppinfo, int *output_NumberOfEntries);
//<< Docsis3.1


/**
* @brief Get the LLD enable status.
*
* @return The status of the LLD status.
* @retval ENABLE if LLD is enabled in bootfile.
* @retval DISABLE if LLD is disabled/entry doesn't exists in bootfile.
* @retval RETURN_ERR if any other error detected.
*
* 
*/

INT docsis_LLDgetEnableStatus();

/**
* @brief Configure the SNMPv3 security parameters on the CM.
* @param[in] pKickstart_Table a pointer to the SNMPv3 kickstart table.
*
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
* 
*
*
*/
INT cm_hal_snmpv3_kickstart_initialize(snmpv3_kickstart_table_t *pKickstart_Table);
/** @} */  //END OF GROUP CM_HAL_APIS

/**
* @brief Get the docsis energy to detect WAN mode.
* @param[out] pEnergyDetected variable is a boolean pointer.
*             \n Possible values is 0 for No Docsis, 1 if DOCSIS is connected.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*
*/

INT docsis_IsEnergyDetected( BOOLEAN *pEnergyDetected );


/**
* @brief Set ReinitMacThreshold value.
* @param[in] value ReinitMacThreshold value to be set.
*             \n It is a unsigned long value. The maximum value is (2^32)-1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT cm_hal_set_ReinitMacThreshold(ULONG value);

/**
* @brief Get ReinitMacThreshold value.
* @param[out] pValue Pointer to ReinitMacThreshold value to be returned.
*              \n It is a unsigned long pointer. The maximum value is (2^32)-1.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
* 
*
*/
INT cm_hal_get_ReinitMacThreshold(ULONG *pValue);

/**
* @brief Get Current Diplexer Settings.
* @param[out] pValue Pointer to the current Diplexer Settings value to be returned.
*
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT cm_hal_get_DiplexerSettings(CM_DIPLEXER_SETTINGS *pValue);

/**
* @brief Receive Current Diplexer Settings via this callback.
* @param[out] stCMDiplexerValue value to be received.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*/
typedef INT ( * cm_hal_DiplexerVariationCallback)(CM_DIPLEXER_SETTINGS stCMDiplexerValue);

/**
* @brief To register callback for receiving dynamic diplexer settings
* @param[in] callback_proc is from cm_hal_DiplexerVariationCallback function.
*                stCMDiplexerValue variable is from the structure CM_DIPLEXER_SETTINGS.
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected.
*
*
*
*/
INT cm_hal_Register_DiplexerVariationCallback(cm_hal_DiplexerVariationCallback callback_proc);

#ifdef __cplusplus
}
#endif

#endif