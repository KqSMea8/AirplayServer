/*
 * Copyright (c) 2016-2017 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "Metrics.h"

#if (TARGET_OS_IOS)
#import <CoreUtils/SoftLinking.h>
#import <WirelessDiagnostics/AWDDNSDomainStats.h>
#import <WirelessDiagnostics/AWDMDNSResponderDNSMessageSizeStats.h>
#import <WirelessDiagnostics/AWDMDNSResponderDNSStatistics.h>
#import <WirelessDiagnostics/AWDMDNSResponderResolveStats.h>
#import <WirelessDiagnostics/AWDMDNSResponderResolveStatsDNSServer.h>
#import <WirelessDiagnostics/AWDMDNSResponderResolveStatsDomain.h>
#import <WirelessDiagnostics/AWDMDNSResponderResolveStatsHostname.h>
#import <WirelessDiagnostics/AWDMDNSResponderResolveStatsResult.h>
#import <WirelessDiagnostics/AWDMDNSResponderServicesStats.h>
#import <WirelessDiagnostics/AWDMetricIds_MDNSResponder.h>
#import <WirelessDiagnostics/WirelessDiagnostics.h>

#import "DNSCommon.h"
#import "mDNSMacOSX.h"
#import "DebugServices.h"

//===========================================================================================================================
//  External Frameworks
//===========================================================================================================================

SOFT_LINK_FRAMEWORK(PrivateFrameworks, WirelessDiagnostics)

// AWDServerConnection class

SOFT_LINK_CLASS(WirelessDiagnostics, AWDServerConnection)

#define AWDServerConnectionSoft     getAWDServerConnectionClass()

// Classes for query stats

SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderDNSStatistics)
SOFT_LINK_CLASS(WirelessDiagnostics, AWDDNSDomainStats)

#define AWDMDNSResponderDNSStatisticsSoft       getAWDMDNSResponderDNSStatisticsClass()
#define AWDDNSDomainStatsSoft                   getAWDDNSDomainStatsClass()

// Classes for resolve stats

SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderResolveStats)
SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderResolveStatsDNSServer)
SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderResolveStatsDomain)
SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderResolveStatsHostname)
SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderResolveStatsResult)

#define AWDMDNSResponderResolveStatsSoft                getAWDMDNSResponderResolveStatsClass()
#define AWDMDNSResponderResolveStatsDNSServerSoft       getAWDMDNSResponderResolveStatsDNSServerClass()
#define AWDMDNSResponderResolveStatsDomainSoft          getAWDMDNSResponderResolveStatsDomainClass()
#define AWDMDNSResponderResolveStatsHostnameSoft        getAWDMDNSResponderResolveStatsHostnameClass()
#define AWDMDNSResponderResolveStatsResultSoft          getAWDMDNSResponderResolveStatsResultClass()

// Classes for services stats

SOFT_LINK_CLASS(WirelessDiagnostics, AWDMetricManager)

#define AWDMetricManagerSoft        getAWDMetricManagerClass()

// Classes for DNS message size stats

SOFT_LINK_CLASS(WirelessDiagnostics, AWDMDNSResponderDNSMessageSizeStats)

#define AWDMDNSResponderDNSMessageSizeStatsSoft     getAWDMDNSResponderDNSMessageSizeStatsClass()

//===========================================================================================================================
//  Macros
//===========================================================================================================================

#define countof(X)                      (sizeof(X) / sizeof(X[0]))
#define countof_field(TYPE, FIELD)      countof(((TYPE *)0)->FIELD)
#define increment_saturate(VAR, MAX)    do {if ((VAR) < (MAX)) {++(VAR);}} while (0)
#define ForgetMem(X)                    do {if(*(X)) {free(*(X)); *(X) = NULL;}} while(0)

//===========================================================================================================================
//  Constants
//===========================================================================================================================

#define kQueryStatsMaxQuerySendCount        10
#define kQueryStatsSendCountBinCount        (kQueryStatsMaxQuerySendCount + 1)
#define kQueryStatsLatencyBinCount          55
#define kQueryStatsExpiredAnswerStateCount  (ExpiredAnswer_EnumCount)
#define kResolveStatsMaxObjCount            2000

//===========================================================================================================================
//  Data structures
//===========================================================================================================================

// Data structures for query stats.

typedef struct QueryStats       QueryStats;
typedef struct DNSHistSet       DNSHistSet;
typedef mDNSBool                (*QueryNameTest_f)(const QueryStats *inStats, const domainname *inQueryName);

struct QueryStats
{
    QueryStats *        next;           // Pointer to next domain stats in list.
    const char *        domainStr;      // Domain (see below) as a C string.
    uint8_t *           domain;         // Domain for which these stats are collected.
    const char *        altDomainStr;   // Alt domain string to use in the AWD version of the stats instead of domainStr.
    DNSHistSet *        nonCellular;    // Query stats for queries sent over non-cellular interfaces.
    DNSHistSet *        cellular;       // Query stats for queries sent over cellular interfaces.
    QueryNameTest_f     test;           // Function that tests whether a given query's stats belong based on the query name.
    int                 labelCount;     // Number of labels in domain name. Used for domain name comparisons.
    mDNSBool            terminal;       // If true and test passes, then no other QueryStats on the list should be visited.
};

check_compile_time(sizeof(QueryStats) <= 64);

// DNSHist contains the per domain per network type histogram data that goes in a DNSDomainStats protobuf message. See
// <rdar://problem/23980546> MDNSResponder.proto update.
//
// answeredQuerySendCountBins
//
// An array of 11 histogram bins. The value at index i, for 0 <= i <= 9, is the number of times that an answered DNS query
// was sent i times. The value at index 10 is the number of times that an answered query was sent 10+ times.
//
// unansweredQuerySendCountBins
//
// An array of 11 histogram bins. The value at index i, for 0 <= i <= 9, is the number of times that an unanswered DNS query
// was sent i times. The value at index 10 is the number of times that an unanswered query was sent 10+ times.
//
// responseLatencyBins
//
// An array of 55 histogram bins. Each array value is the number of DNS queries that were answered in a paricular time
// interval. The 55 consecutive non-overlapping time intervals have the following non-inclusive upper bounds (all values are
// in milliseconds): 1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190,
// 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000, 1500, 2000, 2500, 3000, 3500, 4000,
// 4500, 5000, 6000, 7000, 8000, 9000, 10000, ∞.

typedef struct
{
    uint16_t    unansweredQuerySendCountBins[kQueryStatsSendCountBinCount];
    uint16_t    unansweredQueryDurationBins[kQueryStatsLatencyBinCount];
    uint16_t    answeredQuerySendCountBins[kQueryStatsSendCountBinCount];
    uint16_t    responseLatencyBins[kQueryStatsLatencyBinCount];
    uint16_t    negAnsweredQuerySendCountBins[kQueryStatsSendCountBinCount];
    uint16_t    negResponseLatencyBins[kQueryStatsLatencyBinCount];
    uint16_t    expiredAnswerStateBins[kQueryStatsExpiredAnswerStateCount];

}   DNSHist;

check_compile_time(sizeof(DNSHist) <= 512);
check_compile_time(countof_field(DNSHist, unansweredQuerySendCountBins)  == (kQueryStatsMaxQuerySendCount + 1));
check_compile_time(countof_field(DNSHist, answeredQuerySendCountBins)    == (kQueryStatsMaxQuerySendCount + 1));
check_compile_time(countof_field(DNSHist, negAnsweredQuerySendCountBins) == (kQueryStatsMaxQuerySendCount + 1));
check_compile_time(countof_field(DNSHist, expiredAnswerStateBins)         == (kQueryStatsExpiredAnswerStateCount));

// Important: Do not modify kResponseLatencyMsLimits because the code used to generate AWD reports expects the response
// latency histogram bins to observe these time interval upper bounds.

static const mDNSu32        kResponseLatencyMsLimits[] =
{
        1,     2,     3,     4,     5,
       10,    20,    30,    40,    50,    60,    70,    80,    90,
      100,   110,   120,   130,   140,   150,   160,   170,   180,   190,
      200,   250,   300,   350,   400,   450,   500,   550,   600,   650,   700,   750,   800,   850,   900,   950,
     1000,  1500,  2000,  2500,  3000,  3500,  4000,  4500,
     5000,  6000,  7000,  8000,  9000,
    10000
};

check_compile_time(countof(kResponseLatencyMsLimits) == 54);
check_compile_time(countof_field(DNSHist, unansweredQueryDurationBins) == (countof(kResponseLatencyMsLimits) + 1));
check_compile_time(countof_field(DNSHist, responseLatencyBins)         == (countof(kResponseLatencyMsLimits) + 1));
check_compile_time(countof_field(DNSHist, negResponseLatencyBins)      == (countof(kResponseLatencyMsLimits) + 1));

struct DNSHistSet
{
    DNSHist *       histA;      // Histogram data for queries for A resource records.
    DNSHist *       histAAAA;   // Histogram data for queries for AAAA resource records.
};

typedef struct
{
    const char *        domainStr;
    const char *        altDomainStr;
    QueryNameTest_f     test;
    mDNSBool            terminal;

}   QueryStatsArgs;

// Data structures for resolve stats.

static const char * const       kResolveStatsDomains[] =
{
    "apple.com.",
    "icloud.com.",
    "mzstatic.com.",
    "me.com."
};

check_compile_time(countof(kResolveStatsDomains) == 4);

typedef struct ResolveStatsDomain           ResolveStatsDomain;
typedef struct ResolveStatsHostname         ResolveStatsHostname;
typedef struct ResolveStatsDNSServer        ResolveStatsDNSServer;
typedef struct ResolveStatsIPv4AddrSet      ResolveStatsIPv4AddrSet;
typedef struct ResolveStatsIPv6Addr         ResolveStatsIPv6Addr;
typedef struct ResolveStatsNegAAAASet       ResolveStatsNegAAAASet;

struct ResolveStatsDomain
{
    ResolveStatsDomain *        next;           // Next domain object in list.
    const char *                domainStr;
    uint8_t *                   domain;         // Domain for which these stats are collected.
    int                         labelCount;     // Number of labels in domain name. Used for domain name comparisons.
    ResolveStatsHostname *      hostnameList;   // List of hostname objects in this domain.
};

check_compile_time(sizeof(ResolveStatsDomain) <= 40);

struct ResolveStatsHostname
{
    ResolveStatsHostname *          next;       // Next hostname object in list.
    ResolveStatsIPv4AddrSet *       addrV4List; // List of IPv4 addresses to which this hostname resolved.
    ResolveStatsIPv6Addr *          addrV6List; // List of IPv6 addresses to which this hostname resolved.
    ResolveStatsNegAAAASet *        negV6List;  // List of negative AAAA response objects.
    uint8_t                         name[1];    // Variable length storage for hostname as length-prefixed labels.
};

check_compile_time(sizeof(ResolveStatsHostname) <= 64);

struct ResolveStatsDNSServer
{
    ResolveStatsDNSServer *     next;           // Next DNS server object in list.
    uint8_t                     id;             // 8-bit ID assigned to this DNS server used by IP address objects.
    mDNSBool                    isForCell;      // True if this DNS server belongs to a cellular interface.
    mDNSBool                    isAddrV6;       // True if this DNS server has an IPv6 address instead of IPv4.
    uint8_t                     addrBytes[1];   // Variable length storage for DNS server's IP address.
};

check_compile_time(sizeof(ResolveStatsDNSServer) <= 32);

typedef struct
{
    uint16_t        count;          // Number of times this IPv4 address was provided as a resolution result.
    uint8_t         serverID;       // 8-bit ID of the DNS server from which this IPv4 address came.
    uint8_t         isNegative;
    uint8_t         addrBytes[4];   // IPv4 address bytes.

}   IPv4AddrCounter;

check_compile_time(sizeof(IPv4AddrCounter) <= 8);

struct ResolveStatsIPv4AddrSet
{
    ResolveStatsIPv4AddrSet *       next;           // Next set of IPv4 address counters in list.
    IPv4AddrCounter                 counters[3];    // Array of IPv4 address counters.
};

check_compile_time(sizeof(ResolveStatsIPv4AddrSet) <= 32);

struct ResolveStatsIPv6Addr
{
    ResolveStatsIPv6Addr *      next;           // Next IPv6 address object in list.
    uint16_t                    count;          // Number of times this IPv6 address was provided as a resolution result.
    uint8_t                     serverID;       // 8-bit ID of the DNS server from which this IPv6 address came.
    uint8_t                     addrBytes[16];  // IPv6 address bytes.
};

check_compile_time(sizeof(ResolveStatsIPv6Addr) <= 32);

typedef struct
{
    uint16_t        count;      // Number of times that a negative response was returned by a DNS server.
    uint8_t         serverID;   // 8-bit ID of the DNS server that sent the negative responses.

}   NegAAAACounter;

check_compile_time(sizeof(NegAAAACounter) <= 4);

struct ResolveStatsNegAAAASet
{
    ResolveStatsNegAAAASet *        next;           // Next set of negative AAAA response counters in list.
    NegAAAACounter                  counters[6];    // Array of negative AAAA response counters.
};

check_compile_time(sizeof(ResolveStatsNegAAAASet) <= 32);

typedef enum
{
    kResponseType_IPv4Addr  = 1,
    kResponseType_IPv6Addr  = 2,
    kResponseType_NegA      = 3,
    kResponseType_NegAAAA   = 4

}   ResponseType;

typedef struct
{
    ResponseType        type;
    const uint8_t *     data;

}   Response;

// Data structures for DNS message size stats.

#define kQuerySizeBinWidth      16
#define kQuerySizeBinMax        512
#define kQuerySizeBinCount      ((kQuerySizeBinMax / kQuerySizeBinWidth) + 1)

check_compile_time(kQuerySizeBinWidth > 0);
check_compile_time(kQuerySizeBinCount > 0);
check_compile_time((kQuerySizeBinMax % kQuerySizeBinWidth) == 0);

#define kResponseSizeBinWidth       16
#define kResponseSizeBinMax         512
#define kResponseSizeBinCount       ((kResponseSizeBinMax / kResponseSizeBinWidth) + 1)

check_compile_time(kResponseSizeBinWidth > 0);
check_compile_time(kResponseSizeBinCount > 0);
check_compile_time((kResponseSizeBinMax % kResponseSizeBinWidth) == 0);

typedef struct
{
    uint16_t    querySizeBins[kQuerySizeBinCount];
    uint16_t    responseSizeBins[kResponseSizeBinCount];

}   DNSMessageSizeStats;

check_compile_time(sizeof(DNSMessageSizeStats) <= 132);

//===========================================================================================================================
//  Local Prototypes
//===========================================================================================================================

// Query stats

mDNSlocal mStatus       QueryStatsCreate(const char *inDomainStr, const char *inAltDomainStr, QueryNameTest_f inTest, mDNSBool inTerminal, QueryStats **outStats);
mDNSlocal void          QueryStatsFree(QueryStats *inStats);
mDNSlocal void          QueryStatsFreeList(QueryStats *inList);
mDNSlocal mStatus       QueryStatsUpdate(QueryStats *inStats, int inType, const ResourceRecord *inRR, mDNSu32 inQuerySendCount, ExpiredAnswerMetric inExpiredAnswerState, mDNSu32 inLatencyMs, mDNSBool inForCell);
mDNSlocal const char *  QueryStatsGetDomainString(const QueryStats *inStats);
mDNSlocal mDNSBool      QueryStatsDomainTest(const QueryStats *inStats, const domainname *inQueryName);
mDNSlocal mDNSBool      QueryStatsHostnameTest(const QueryStats *inStats, const domainname *inQueryName);
mDNSlocal mDNSBool      QueryStatsContentiCloudTest(const QueryStats *inStats, const domainname *inQueryName);
mDNSlocal mDNSBool      QueryStatsCourierPushTest(const QueryStats *inStats, const domainname *inQueryName);

// Resolve stats

mDNSlocal mStatus   ResolveStatsDomainCreate(const char *inDomainStr, ResolveStatsDomain **outDomain);
mDNSlocal void      ResolveStatsDomainFree(ResolveStatsDomain *inDomain);
mDNSlocal mStatus   ResolveStatsDomainUpdate(ResolveStatsDomain *inDomain, const domainname *inHostname, const Response *inResp, const mDNSAddr *inDNSAddr, mDNSBool inForCell);
mDNSlocal mStatus   ResolveStatsDomainCreateAWDVersion(const ResolveStatsDomain *inDomain, AWDMDNSResponderResolveStatsDomain **outDomain);

mDNSlocal mStatus   ResolveStatsHostnameCreate(const domainname *inName, ResolveStatsHostname **outHostname);
mDNSlocal void      ResolveStatsHostnameFree(ResolveStatsHostname *inHostname);
mDNSlocal mStatus   ResolveStatsHostnameUpdate(ResolveStatsHostname *inHostname, const Response *inResp, uint8_t inServerID);
mDNSlocal mStatus   ResolveStatsHostnameCreateAWDVersion(const ResolveStatsHostname *inHostname, AWDMDNSResponderResolveStatsHostname **outHostname);

mDNSlocal mStatus   ResolveStatsDNSServerCreate(const mDNSAddr *inAddr, mDNSBool inForCell, ResolveStatsDNSServer **outServer);
mDNSlocal void      ResolveStatsDNSServerFree(ResolveStatsDNSServer *inServer);
mDNSlocal mStatus   ResolveStatsDNSServerCreateAWDVersion(const ResolveStatsDNSServer *inServer, AWDMDNSResponderResolveStatsDNSServer **outServer);

mDNSlocal mStatus   ResolveStatsIPv4AddrSetCreate(ResolveStatsIPv4AddrSet **outSet);
mDNSlocal void      ResolveStatsIPv4AddrSetFree(ResolveStatsIPv4AddrSet *inSet);

mDNSlocal mStatus   ResolveStatsIPv6AddressCreate(uint8_t inServerID, const uint8_t inAddrBytes[16], ResolveStatsIPv6Addr **outAddr);
mDNSlocal void      ResolveStatsIPv6AddressFree(ResolveStatsIPv6Addr *inAddr);

mDNSlocal mStatus   ResolveStatsNegAAAASetCreate(ResolveStatsNegAAAASet **outSet);
mDNSlocal void      ResolveStatsNegAAAASetFree(ResolveStatsNegAAAASet *inSet);
mDNSlocal mStatus   ResolveStatsGetServerID(const mDNSAddr *inServerAddr, mDNSBool inForCell, uint8_t *outServerID);

// DNS message size stats

mDNSlocal mStatus   DNSMessageSizeStatsCreate(DNSMessageSizeStats **outStats);
mDNSlocal void      DNSMessageSizeStatsFree(DNSMessageSizeStats *inStats);

mDNSlocal mStatus   CreateQueryStatsList(QueryStats **outList);
mDNSlocal mStatus   CreateResolveStatsList(ResolveStatsDomain **outList);
mDNSlocal void      FreeResolveStatsList(ResolveStatsDomain *inList);
mDNSlocal void      FreeResolveStatsServerList(ResolveStatsDNSServer *inList);
mDNSlocal mStatus   SubmitAWDMetric(UInt32 inMetricID);
mDNSlocal mStatus   SubmitAWDMetricQueryStats(void);
mDNSlocal mStatus   SubmitAWDMetricResolveStats(void);
mDNSlocal mStatus   SubmitAWDMetricDNSMessageSizeStats(void);
mDNSlocal mStatus   CreateAWDDNSDomainStats(DNSHist *inHist, const char *inDomain, mDNSBool inForCell, AWDDNSDomainStats_RecordType inType, AWDDNSDomainStats **outStats);
mDNSlocal void      LogDNSHistSet(const DNSHistSet *inSet, const char *inDomain, mDNSBool inForCell);
mDNSlocal void      LogDNSHist(const DNSHist *inHist, const char *inDomain, mDNSBool inForCell, const char *inType);
mDNSlocal void      LogDNSHistSendCounts(const uint16_t inSendCountBins[kQueryStatsSendCountBinCount]);
mDNSlocal void      LogDNSHistLatencies(const uint16_t inLatencyBins[kQueryStatsLatencyBinCount]);
mDNSlocal void      LogDNSMessageSizeStats(const uint16_t *inBins, size_t inBinCount, unsigned int inBinWidth);

mDNSlocal size_t    CopyHistogramBins(uint32_t *inDstBins, uint16_t *inSrcBins, size_t inBinCount);

//===========================================================================================================================
//  Globals
//===========================================================================================================================

static AWDServerConnection *        gAWDServerConnection        = nil;
static QueryStats *                 gQueryStatsList             = NULL;
static ResolveStatsDomain *         gResolveStatsList           = NULL;
static ResolveStatsDNSServer *      gResolveStatsServerList     = NULL;
static unsigned int                 gResolveStatsNextServerID   = 0;
static int                          gResolveStatsObjCount       = 0;
static DNSMessageSizeStats *        gDNSMessageSizeStats        = NULL;

// Important: Do not add to this list without getting privacy approval. See <rdar://problem/24155761&26397203&34763471>.

static const QueryStatsArgs     kQueryStatsArgs[] =
{
    { ".",                      NULL,                               QueryStatsDomainTest,           mDNSfalse },
    { "",                       "alt:*-courier.push.apple.com.",    QueryStatsCourierPushTest,      mDNSfalse },
    { "apple.com.",             NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "gateway.icloud.com.",    "alt:gateway.icloud.com",           QueryStatsHostnameTest,         mDNSfalse },
    { "",                       "alt:*-content.icloud.com.",        QueryStatsContentiCloudTest,    mDNSfalse },
    { "icloud.com.",            NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "mzstatic.com.",          NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "google.com.",            NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "baidu.com.",             NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "yahoo.com.",             NULL,                               QueryStatsDomainTest,           mDNStrue  },
    { "qq.com.",                NULL,                               QueryStatsDomainTest,           mDNStrue  }
};

check_compile_time(countof(kQueryStatsArgs) == 11);

//===========================================================================================================================
//  MetricsInit
//===========================================================================================================================

mStatus MetricsInit(void)
{
    @autoreleasepool
    {
        gAWDServerConnection = [[AWDServerConnectionSoft alloc]
            initWithComponentId:     AWDComponentId_MDNSResponder
            andBlockOnConfiguration: NO];

        if (gAWDServerConnection)
        {
            [gAWDServerConnection
                registerQueriableMetricCallback: ^(UInt32 inMetricID)
                {
                    SubmitAWDMetric(inMetricID);
                }
                forIdentifier: (UInt32)AWDMetricId_MDNSResponder_DNSStatistics];

            [gAWDServerConnection
                registerQueriableMetricCallback: ^(UInt32 inMetricID)
                {
                    SubmitAWDMetric(inMetricID);
                }
                forIdentifier: (UInt32)AWDMetricId_MDNSResponder_ResolveStats];

            [gAWDServerConnection
                registerQueriableMetricCallback: ^(UInt32 inMetricID)
                {
                    SubmitAWDMetric(inMetricID);
                }
                forIdentifier: (UInt32)AWDMetricId_MDNSResponder_ServicesStats];

            [gAWDServerConnection
                registerQueriableMetricCallback: ^(UInt32 inMetricID)
                {
                    SubmitAWDMetric(inMetricID);
                }
                forIdentifier: (UInt32)AWDMetricId_MDNSResponder_DNSMessageSizeStats];
        }
        else
        {
            LogMsg("MetricsInit: failed to create AWD server connection.");
        }
    }

    if( gAWDServerConnection )
    {
        CreateQueryStatsList(&gQueryStatsList);
        CreateResolveStatsList(&gResolveStatsList);
        DNSMessageSizeStatsCreate(&gDNSMessageSizeStats);
    }

    return (mStatus_NoError);
}

//===========================================================================================================================
//  MetricsUpdateDNSQueryStats
//===========================================================================================================================

mDNSexport void MetricsUpdateDNSQueryStats(const domainname *inQueryName, mDNSu16 inType, const ResourceRecord *inRR, mDNSu32 inSendCount, ExpiredAnswerMetric inExpiredAnswerState, mDNSu32 inLatencyMs, mDNSBool inForCell)
{
    QueryStats *        stats;
    mDNSBool            match;

    require_quiet(gAWDServerConnection, exit);
    require_quiet((inType == kDNSType_A) || (inType == kDNSType_AAAA), exit);

    for (stats = gQueryStatsList; stats; stats = stats->next)
    {
        match = stats->test(stats, inQueryName);
        if (match)
        {
            QueryStatsUpdate(stats, inType, inRR, inSendCount, inExpiredAnswerState, inLatencyMs, inForCell);
            if (stats->terminal) break;
        }
    }

exit:
    return;
}

//===========================================================================================================================
//  MetricsUpdateDNSResolveStats
//===========================================================================================================================

mDNSexport void MetricsUpdateDNSResolveStats(const domainname *inQueryName, const ResourceRecord *inRR, mDNSBool inForCell)
{
    ResolveStatsDomain *        domainStats;
    domainname                  hostname;
    size_t                      hostnameLen;
    mDNSBool                    isQueryInDomain;
    int                         skipCount;
    int                         skipCountLast = -1;
    int                         queryLabelCount;
    const domainname *          queryParentDomain;
    Response                    response;

    require_quiet(gAWDServerConnection, exit);
    require_quiet((inRR->rrtype == kDNSType_A) || (inRR->rrtype == kDNSType_AAAA), exit);
    require_quiet(inRR->rDNSServer, exit);

    queryLabelCount = CountLabels(inQueryName);

    for (domainStats = gResolveStatsList; domainStats; domainStats = domainStats->next)
    {
        isQueryInDomain = mDNSfalse;
        skipCount = queryLabelCount - domainStats->labelCount;
        if (skipCount >= 0)
        {
            if (skipCount != skipCountLast)
            {
                queryParentDomain = SkipLeadingLabels(inQueryName, skipCount);
                skipCountLast = skipCount;
            }
            isQueryInDomain = SameDomainName(queryParentDomain, (const domainname *)domainStats->domain);
        }
        if (!isQueryInDomain) continue;

        hostnameLen = (size_t)(queryParentDomain->c - inQueryName->c);
        if (hostnameLen >= sizeof(hostname.c)) continue;

        memcpy(hostname.c, inQueryName->c, hostnameLen);
        hostname.c[hostnameLen] = 0;

        if (inRR->RecordType == kDNSRecordTypePacketNegative)
        {
            response.type = (inRR->rrtype == kDNSType_A) ? kResponseType_NegA : kResponseType_NegAAAA;
            response.data = NULL;
        }
        else
        {
            response.type = (inRR->rrtype == kDNSType_A) ? kResponseType_IPv4Addr : kResponseType_IPv6Addr;
            response.data = (inRR->rrtype == kDNSType_A) ? inRR->rdata->u.ipv4.b : inRR->rdata->u.ipv6.b;
        }
        ResolveStatsDomainUpdate(domainStats, &hostname, &response, &inRR->rDNSServer->addr, inForCell);
    }

exit:
    return;
}

//===========================================================================================================================
//  MetricsUpdateDNSQuerySize
//===========================================================================================================================

mDNSlocal void UpdateMessageSizeCounts(uint16_t *inBins, size_t inBinCount, unsigned int inBinWidth, uint32_t inSize);

mDNSexport void MetricsUpdateDNSQuerySize(mDNSu32 inSize)
{
    if (!gDNSMessageSizeStats) return;
    UpdateMessageSizeCounts(gDNSMessageSizeStats->querySizeBins, kQuerySizeBinCount, kQuerySizeBinWidth, inSize);
}

mDNSlocal void UpdateMessageSizeCounts(uint16_t *inBins, size_t inBinCount, unsigned int inBinWidth, uint32_t inSize)
{
    size_t      i;

    if (inSize == 0) return;
    i = (inSize - 1) / inBinWidth;
    if (i >= inBinCount) i = inBinCount - 1;
    increment_saturate(inBins[i], UINT16_MAX);
}

//===========================================================================================================================
//  MetricsUpdateDNSResponseSize
//===========================================================================================================================

mDNSexport void MetricsUpdateDNSResponseSize(mDNSu32 inSize)
{
    if (!gDNSMessageSizeStats) return;
    UpdateMessageSizeCounts(gDNSMessageSizeStats->responseSizeBins, kResponseSizeBinCount, kResponseSizeBinWidth, inSize);
}

//===========================================================================================================================
//  LogMetrics
//===========================================================================================================================

mDNSexport void LogMetrics(void)
{
    QueryStats *                        stats;
    const ResolveStatsDomain *          domain;
    const ResolveStatsHostname *        hostname;
    const ResolveStatsDNSServer *       server;
    const ResolveStatsIPv4AddrSet *     addrV4;
    const ResolveStatsIPv6Addr *        addrV6;
    const ResolveStatsNegAAAASet *      negV6;
    int                                 hostnameCount;
    int                                 i;
    unsigned int                        serverID;
    int                                 serverObjCount   = 0;
    int                                 hostnameObjCount = 0;
    int                                 addrObjCount     = 0;

    LogMsgNoIdent("gAWDServerConnection %p", gAWDServerConnection);
    LogMsgNoIdent("---- DNS query stats by domain -----");

    for (stats = gQueryStatsList; stats; stats = stats->next)
    {
        if (!stats->nonCellular && !stats->cellular)
        {
            LogMsgNoIdent("No data for %s", QueryStatsGetDomainString(stats));
            continue;
        }
        if (stats->nonCellular) LogDNSHistSet(stats->nonCellular, QueryStatsGetDomainString(stats), mDNSfalse);
        if (stats->cellular)    LogDNSHistSet(stats->cellular,    QueryStatsGetDomainString(stats), mDNStrue);
    }

    LogMsgNoIdent("---- DNS resolve stats by domain -----");

    LogMsgNoIdent("Servers:");
    for (server = gResolveStatsServerList; server; server = server->next)
    {
        serverObjCount++;
        LogMsgNoIdent(server->isAddrV6 ? "%2u: %s %.16a" : "%2u: %s %.4a",
            server->id, server->isForCell ? " C" : "NC", server->addrBytes);
    }

    for (domain = gResolveStatsList; domain; domain = domain->next)
    {
        hostnameCount = 0;
        for (hostname = domain->hostnameList; hostname; hostname = hostname->next) { hostnameCount++; }
        hostnameObjCount += hostnameCount;

        LogMsgNoIdent("%s (%d hostname%s)", domain->domainStr, hostnameCount, (hostnameCount == 1) ? "" : "s");

        for (hostname = domain->hostnameList; hostname; hostname = hostname->next)
        {
            LogMsgNoIdent("    %##s", hostname->name);
            for (serverID = 0; serverID < gResolveStatsNextServerID; ++serverID)
            {
                for (addrV4 = hostname->addrV4List; addrV4; addrV4 = addrV4->next)
                {
                    if (serverID == 0) addrObjCount++;
                    for (i = 0; i < (int)countof(addrV4->counters); ++i)
                    {
                        const IPv4AddrCounter *      counter;

                        counter = &addrV4->counters[i];
                        if (counter->count == 0) break;
                        if (counter->serverID == serverID)
                        {
                            if (counter->isNegative)
                            {
                                LogMsgNoIdent("%10u: %3u negative A", counter->serverID, counter->count);
                            }
                            else
                            {
                                LogMsgNoIdent("%10u: %3u %.4a", counter->serverID, counter->count, counter->addrBytes);
                            }
                        }
                    }
                }
                for (addrV6 = hostname->addrV6List; addrV6; addrV6 = addrV6->next)
                {
                    if (serverID == 0) addrObjCount++;
                    if (addrV6->serverID == serverID)
                    {
                        LogMsgNoIdent("%10u: %3u %.16a", addrV6->serverID, addrV6->count, addrV6->addrBytes);
                    }
                }
                for (negV6 = hostname->negV6List; negV6; negV6 = negV6->next)
                {
                    if (serverID == 0) addrObjCount++;
                    for (i = 0; i < (int)countof(negV6->counters); ++i)
                    {
                        const NegAAAACounter *      counter;

                        counter = &negV6->counters[i];
                        if (counter->count == 0) break;
                        if (counter->serverID == serverID)
                        {
                            LogMsgNoIdent("%10u: %3u negative AAAA", counter->serverID, counter->count);
                        }
                    }
                }
            }
        }
    }
    LogMsgNoIdent("Total object count: %3d (server %d hostname %d address %d)",
        serverObjCount + hostnameObjCount + addrObjCount, serverObjCount, hostnameObjCount, addrObjCount);

    LogMsgNoIdent("---- Num of Services Registered -----");
    LogMsgNoIdent("Current_number_of_services_registered :[%d], Max_number_of_services_registered :[%d]",
                  curr_num_regservices, max_num_regservices);

    if (gDNSMessageSizeStats)
    {
        LogMsgNoIdent("---- DNS query size stats ---");
        LogDNSMessageSizeStats(gDNSMessageSizeStats->querySizeBins, kQuerySizeBinCount, kQuerySizeBinWidth);

        LogMsgNoIdent("-- DNS response size stats --");
        LogDNSMessageSizeStats(gDNSMessageSizeStats->responseSizeBins, kResponseSizeBinCount, kResponseSizeBinWidth);
    }
    else
    {
        LogMsgNoIdent("No DNS message size stats.");
    }
}

//===========================================================================================================================
//  QueryStatsCreate
//===========================================================================================================================

mDNSlocal mStatus StringToDomainName(const char *inString, uint8_t **outDomainName);

mDNSlocal mStatus QueryStatsCreate(const char *inDomainStr, const char *inAltDomainStr, QueryNameTest_f inTest, mDNSBool inTerminal, QueryStats **outStats)
{
    mStatus             err;
    QueryStats *        obj;

    obj = (QueryStats *)calloc(1, sizeof(*obj));
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    obj->domainStr = inDomainStr;
    err = StringToDomainName(obj->domainStr, &obj->domain);
    require_noerr_quiet(err, exit);

    obj->altDomainStr   = inAltDomainStr;
    obj->test           = inTest;
    obj->labelCount     = CountLabels((const domainname *)obj->domain);
    obj->terminal       = inTerminal;

    *outStats = obj;
    obj = NULL;
    err = mStatus_NoError;

exit:
    if (obj) QueryStatsFree(obj);
    return (err);
}

mDNSlocal mStatus StringToDomainName(const char *inString, uint8_t **outDomainName)
{
    mStatus             err;
    uint8_t *           domainPtr = NULL;
    size_t              domainLen;
    const mDNSu8 *      ptr;
    domainname          domain;

    if (strcmp(inString, ".") == 0)
    {
        domain.c[0] = 0;
    }
    else
    {
        ptr = MakeDomainNameFromDNSNameString(&domain, inString);
        require_action_quiet(ptr, exit, err = mStatus_BadParamErr);
    }
    domainLen = DomainNameLength(&domain);

    domainPtr = (uint8_t *)malloc(domainLen);
    require_action_quiet(domainPtr, exit, err = mStatus_NoMemoryErr);

    memcpy(domainPtr, domain.c, domainLen);

    *outDomainName = domainPtr;
    domainPtr = NULL;
    err = mStatus_NoError;

exit:
    return(err);
}

//===========================================================================================================================
//  QueryStatsFree
//===========================================================================================================================

mDNSlocal void QueryStatsFree(QueryStats *inStats)
{
    ForgetMem(&inStats->domain);
    if (inStats->nonCellular)
    {
        ForgetMem(&inStats->nonCellular->histA);
        ForgetMem(&inStats->nonCellular->histAAAA);
        free(inStats->nonCellular);
        inStats->nonCellular = NULL;
    }
    if (inStats->cellular)
    {
        ForgetMem(&inStats->cellular->histA);
        ForgetMem(&inStats->cellular->histAAAA);
        free(inStats->cellular);
        inStats->cellular = NULL;
    }
    free(inStats);
}

//===========================================================================================================================
//  QueryStatsFreeList
//===========================================================================================================================

mDNSlocal void QueryStatsFreeList(QueryStats *inList)
{
    QueryStats *        stats;

    while ((stats = inList) != NULL)
    {
        inList = stats->next;
        QueryStatsFree(stats);
    }
}

//===========================================================================================================================
//  QueryStatsUpdate
//===========================================================================================================================

mDNSlocal mStatus QueryStatsUpdate(QueryStats *inStats, int inType, const ResourceRecord *inRR, mDNSu32 inQuerySendCount, ExpiredAnswerMetric inExpiredAnswerState, mDNSu32 inLatencyMs, mDNSBool inForCell)
{
    mStatus             err;
    DNSHistSet *        set;
    DNSHistSet **       pSet;
    DNSHist *           hist;
    DNSHist **          pHist;
    int                 i;

    require_action_quiet(inRR || (inQuerySendCount > 0), exit, err = mStatus_NoError);
    require_action_quiet((inType == kDNSType_A) || (inType == kDNSType_AAAA), exit, err = mStatus_NoError);

    pSet = inForCell ? &inStats->cellular : &inStats->nonCellular;
    if ((set = *pSet) == NULL)
    {
        set = (DNSHistSet *)calloc(1, sizeof(*set));
        require_action_quiet(set, exit, err = mStatus_NoMemoryErr);
        *pSet = set;
    }
    pHist = (inType == kDNSType_A) ? &set->histA : &set->histAAAA;
    if ((hist = *pHist) == NULL)
    {
        hist = (DNSHist *)calloc(1, sizeof(*hist));
        require_action_quiet(hist, exit, err = mStatus_NoMemoryErr);
        *pHist = hist;
    }

    if (inRR)
    {
        uint16_t *          sendCountBins;
        uint16_t *          latencyBins;
        const mDNSBool      isNegative = (inRR->RecordType == kDNSRecordTypePacketNegative);

        i = Min(inQuerySendCount, kQueryStatsMaxQuerySendCount);

        sendCountBins = isNegative ? hist->negAnsweredQuerySendCountBins : hist->answeredQuerySendCountBins;
        increment_saturate(sendCountBins[i], UINT16_MAX);

        if (inQuerySendCount > 0)
        {
            for (i = 0; (i < (int)countof(kResponseLatencyMsLimits)) && (inLatencyMs >= kResponseLatencyMsLimits[i]); ++i) {}
            latencyBins = isNegative ? hist->negResponseLatencyBins : hist->responseLatencyBins;
            increment_saturate(latencyBins[i], UINT16_MAX);
        }
    }
    else
    {
        i = Min(inQuerySendCount, kQueryStatsMaxQuerySendCount);
        increment_saturate(hist->unansweredQuerySendCountBins[i], UINT16_MAX);

        for (i = 0; (i < (int)countof(kResponseLatencyMsLimits)) && (inLatencyMs >= kResponseLatencyMsLimits[i]); ++i) {}
        increment_saturate(hist->unansweredQueryDurationBins[i], UINT16_MAX);
    }
    increment_saturate(hist->expiredAnswerStateBins[Min(inExpiredAnswerState, (kQueryStatsExpiredAnswerStateCount-1))], UINT16_MAX);
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  QueryStatsGetDomainString
//===========================================================================================================================

mDNSlocal const char * QueryStatsGetDomainString(const QueryStats *inStats)
{
    return (inStats->altDomainStr ? inStats->altDomainStr : inStats->domainStr);
}

//===========================================================================================================================
//  QueryStatsDomainTest
//===========================================================================================================================

mDNSlocal mDNSBool QueryStatsDomainTest(const QueryStats *inStats, const domainname *inQueryName)
{
    const domainname *      parentDomain;
    int                     labelCount;

    if (inStats->domain[0] == 0) return (mDNStrue);

    labelCount = CountLabels(inQueryName);
    if (labelCount < inStats->labelCount) return (mDNSfalse);

    parentDomain = SkipLeadingLabels(inQueryName, labelCount - inStats->labelCount);
    return (SameDomainName(parentDomain, (const domainname *)inStats->domain));
}

//===========================================================================================================================
//  QueryStatsHostnameTest
//===========================================================================================================================

mDNSlocal mDNSBool QueryStatsHostnameTest(const QueryStats *inStats, const domainname *inQueryName)
{
    return (SameDomainName(inQueryName, (const domainname *)inStats->domain));
}

//===========================================================================================================================
//  QueryStatsContentiCloudTest
//===========================================================================================================================

mDNSlocal const uint8_t *LocateLabelSuffix(const uint8_t *inLabel, const uint8_t *inSuffixPtr, size_t inSuffixLen);

#define kContentSuffixStr       "-content"

mDNSlocal mDNSBool QueryStatsContentiCloudTest(const QueryStats *inStats, const domainname *inQueryName)
{
    const mDNSu8 * const    firstLabel = inQueryName->c;
    const uint8_t *         suffix;
    const domainname *      parentDomain;
    int                     labelCount;

    (void) inStats; // Unused.

    labelCount = CountLabels(inQueryName);
    if (labelCount != 3) return (mDNSfalse);

    suffix = LocateLabelSuffix(firstLabel, (const uint8_t *)kContentSuffixStr, sizeof_string(kContentSuffixStr));
    if (suffix && (suffix > &firstLabel[1]))
    {
        parentDomain = SkipLeadingLabels(inQueryName, 1);
        if (SameDomainName(parentDomain, (const domainname *)"\x6" "icloud" "\x3" "com"))
        {
            return (mDNStrue);
        }
    }

    return (mDNSfalse);
}

mDNSlocal const uint8_t *LocateLabelSuffix(const uint8_t *inLabel, const uint8_t *inSuffixPtr, size_t inSuffixLen)
{
    const uint8_t *     ptr;
    const uint8_t *     lp;
    const uint8_t *     sp;
    size_t              len;
    const size_t        labelLen = inLabel[0];

    if (labelLen < inSuffixLen) return (NULL);

    ptr = &inLabel[1 + labelLen - inSuffixLen];
    lp  = ptr;
    sp  = inSuffixPtr;
    for (len = inSuffixLen; len > 0; --len)
    {
        if (tolower(*lp) != tolower(*sp)) return (NULL);
        ++lp;
        ++sp;
    }

    return (ptr);
}

//===========================================================================================================================
//  QueryStatsCourierPushTest
//===========================================================================================================================

#define kCourierSuffixStr       "-courier"

mDNSlocal mDNSBool QueryStatsCourierPushTest(const QueryStats *inStats, const domainname *inQueryName)
{
    const mDNSu8 * const    firstLabel = inQueryName->c;
    const uint8_t *         suffix;
    const uint8_t *         ptr;
    const domainname *      parentDomain;
    int                     labelCount;

    (void) inStats; // Unused.

    labelCount = CountLabels(inQueryName);
    if (labelCount != 4) return (mDNSfalse);

    suffix = LocateLabelSuffix(firstLabel, (const mDNSu8 *)kCourierSuffixStr, sizeof_string(kCourierSuffixStr));
    if (suffix && (suffix > &firstLabel[1]))
    {
        for (ptr = &firstLabel[1]; ptr < suffix; ++ptr)
        {
            if (!isdigit(*ptr)) break;
        }
        if (ptr == suffix)
        {
            parentDomain = SkipLeadingLabels(inQueryName, 1);
            if (SameDomainName(parentDomain, (const domainname *)"\x4" "push" "\x5" "apple" "\x3" "com"))
            {
                return (mDNStrue);
            }
        }
    }

    return (mDNSfalse);
}

//===========================================================================================================================
//  ResolveStatsDomainCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsDomainCreate(const char *inDomainStr, ResolveStatsDomain **outDomain)
{
    mStatus                     err;
    ResolveStatsDomain *        obj;

    obj = (ResolveStatsDomain *)calloc(1, sizeof(*obj));
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    obj->domainStr = inDomainStr;
    err = StringToDomainName(obj->domainStr, &obj->domain);
    require_noerr_quiet(err, exit);

    obj->labelCount = CountLabels((const domainname *)obj->domain);

    *outDomain = obj;
    obj = NULL;
    err = mStatus_NoError;

exit:
    if (obj) ResolveStatsDomainFree(obj);
    return (err);
}

//===========================================================================================================================
//  ResolveStatsDomainFree
//===========================================================================================================================

mDNSlocal void ResolveStatsDomainFree(ResolveStatsDomain *inDomain)
{
    ResolveStatsHostname *      hostname;

    ForgetMem(&inDomain->domain);
    while ((hostname = inDomain->hostnameList) != NULL)
    {
        inDomain->hostnameList = hostname->next;
        ResolveStatsHostnameFree(hostname);
    }
    free(inDomain);
}

//===========================================================================================================================
//  ResolveStatsDomainUpdate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsDomainUpdate(ResolveStatsDomain *inDomain, const domainname *inHostname, const Response *inResp, const mDNSAddr *inDNSAddr, mDNSBool inForCell)
{
    mStatus                     err;
    ResolveStatsHostname **     p;
    ResolveStatsHostname *      hostname;
    uint8_t                     serverID;

    for (p = &inDomain->hostnameList; (hostname = *p) != NULL; p = &hostname->next)
    {
        if (SameDomainName((domainname *)hostname->name, inHostname)) break;
    }

    if (!hostname)
    {
        require_action_quiet(gResolveStatsObjCount < kResolveStatsMaxObjCount, exit, err = mStatus_Refused);
        err = ResolveStatsHostnameCreate(inHostname, &hostname);
        require_noerr_quiet(err, exit);
        gResolveStatsObjCount++;
        *p = hostname;
    }

    err = ResolveStatsGetServerID(inDNSAddr, inForCell, &serverID);
    require_noerr_quiet(err, exit);

    err = ResolveStatsHostnameUpdate(hostname, inResp, serverID);
    require_noerr_quiet(err, exit);

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsHostnameCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsHostnameCreate(const domainname *inName, ResolveStatsHostname **outHostname)
{
    mStatus                     err;
    ResolveStatsHostname *      obj;
    size_t                      nameLen;

    nameLen = DomainNameLength(inName);
    require_action_quiet(nameLen > 0, exit, err = mStatus_Invalid);

    obj = (ResolveStatsHostname *)calloc(1, sizeof(*obj) - 1 + nameLen);
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    memcpy(obj->name, inName, nameLen);

    *outHostname = obj;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsDomainCreateAWDVersion
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsDomainCreateAWDVersion(const ResolveStatsDomain *inDomain, AWDMDNSResponderResolveStatsDomain **outDomain)
{
    mStatus                                     err;
    AWDMDNSResponderResolveStatsDomain *        domain;
    ResolveStatsHostname *                      hostname;
    AWDMDNSResponderResolveStatsHostname *      awdHostname;
    NSString *                                  name;

    domain = [[AWDMDNSResponderResolveStatsDomainSoft alloc] init];
    require_action_quiet(domain, exit, err = mStatus_UnknownErr);

    name = [[NSString alloc] initWithUTF8String:inDomain->domainStr];
    require_action_quiet(name, exit, err = mStatus_UnknownErr);

    domain.name = name;
    [name release];
    name = nil;

    for (hostname = inDomain->hostnameList; hostname; hostname = hostname->next)
    {
        err = ResolveStatsHostnameCreateAWDVersion(hostname, &awdHostname);
        require_noerr_quiet(err, exit);

        [domain addHostname:awdHostname];
        [awdHostname release];
        awdHostname = nil;
    }

    *outDomain = domain;
    domain = nil;
    err = mStatus_NoError;

exit:
    [domain release];
    return (err);
}

//===========================================================================================================================
//  ResolveStatsHostnameFree
//===========================================================================================================================

mDNSlocal void ResolveStatsHostnameFree(ResolveStatsHostname *inHostname)
{
    ResolveStatsIPv4AddrSet *       addrV4;
    ResolveStatsIPv6Addr *          addrV6;
    ResolveStatsNegAAAASet *        negV6;

    while ((addrV4 = inHostname->addrV4List) != NULL)
    {
        inHostname->addrV4List = addrV4->next;
        ResolveStatsIPv4AddrSetFree(addrV4);
    }
    while ((addrV6 = inHostname->addrV6List) != NULL)
    {
        inHostname->addrV6List = addrV6->next;
        ResolveStatsIPv6AddressFree(addrV6);
    }
    while ((negV6 = inHostname->negV6List) != NULL)
    {
        inHostname->negV6List = negV6->next;
        ResolveStatsNegAAAASetFree(negV6);
    }
    free(inHostname);
}

//===========================================================================================================================
//  ResolveStatsHostnameUpdate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsHostnameUpdate(ResolveStatsHostname *inHostname, const Response *inResp, uint8_t inServerID)
{
    mStatus     err;

    if ((inResp->type == kResponseType_IPv4Addr) || (inResp->type == kResponseType_NegA))
    {
        ResolveStatsIPv4AddrSet **      p;
        ResolveStatsIPv4AddrSet *       addrV4;
        int                             i;
        IPv4AddrCounter *               counter;

        for (p = &inHostname->addrV4List; (addrV4 = *p) != NULL; p = &addrV4->next)
        {
            for (i = 0; i < (int)countof(addrV4->counters); ++i)
            {
                counter = &addrV4->counters[i];
                if (counter->count == 0) break;
                if (counter->serverID != inServerID) continue;
                if (inResp->type == kResponseType_NegA)
                {
                    if (counter->isNegative) break;
                }
                else
                {
                    if (memcmp(counter->addrBytes, inResp->data, 4) == 0) break;
                }
            }
            if (i < (int)countof(addrV4->counters)) break;
        }
        if (!addrV4)
        {
            require_action_quiet(gResolveStatsObjCount < kResolveStatsMaxObjCount, exit, err = mStatus_Refused);
            err = ResolveStatsIPv4AddrSetCreate(&addrV4);
            require_noerr_quiet(err, exit);
            gResolveStatsObjCount++;

            *p = addrV4;
            counter = &addrV4->counters[0];
        }
        if (counter->count == 0)
        {
            counter->serverID = inServerID;
            if (inResp->type == kResponseType_NegA)
            {
                counter->isNegative = 1;
            }
            else
            {
                counter->isNegative = 0;
                memcpy(counter->addrBytes, inResp->data, 4);
            }
        }
        increment_saturate(counter->count, UINT16_MAX);
        err = mStatus_NoError;
    }
    else if (inResp->type == kResponseType_IPv6Addr)
    {
        ResolveStatsIPv6Addr **     p;
        ResolveStatsIPv6Addr *      addrV6;

        for (p = &inHostname->addrV6List; (addrV6 = *p) != NULL; p = &addrV6->next)
        {
            if ((addrV6->serverID == inServerID) && (memcmp(addrV6->addrBytes, inResp->data, 16) == 0)) break;
        }
        if (!addrV6)
        {
            require_action_quiet(gResolveStatsObjCount < kResolveStatsMaxObjCount, exit, err = mStatus_Refused);
            err = ResolveStatsIPv6AddressCreate(inServerID, inResp->data, &addrV6);
            require_noerr_quiet(err, exit);
            gResolveStatsObjCount++;

            *p = addrV6;
        }
        increment_saturate(addrV6->count, UINT16_MAX);
        err = mStatus_NoError;
    }
    else if (inResp->type == kResponseType_NegAAAA)
    {
        ResolveStatsNegAAAASet **       p;
        ResolveStatsNegAAAASet *        negV6;
        int                             i;
        NegAAAACounter *                counter;

        for (p = &inHostname->negV6List; (negV6 = *p) != NULL; p = &negV6->next)
        {
            for (i = 0; i < (int)countof(negV6->counters); ++i)
            {
                counter = &negV6->counters[i];
                if ((counter->count == 0) || (counter->serverID == inServerID)) break;
            }
            if (i < (int)countof(negV6->counters)) break;
        }
        if (!negV6)
        {
            require_action_quiet(gResolveStatsObjCount < kResolveStatsMaxObjCount, exit, err = mStatus_Refused);
            err = ResolveStatsNegAAAASetCreate(&negV6);
            require_noerr_quiet(err, exit);
            gResolveStatsObjCount++;

            *p = negV6;
            counter = &negV6->counters[0];
        }
        if (counter->count == 0) counter->serverID = inServerID;
        increment_saturate(counter->count, UINT16_MAX);
        err = mStatus_NoError;
    }
    else
    {
        err = mStatus_Invalid;
    }

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsHostnameCreateAWDVersion
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsHostnameCreateAWDVersion(const ResolveStatsHostname *inHostname, AWDMDNSResponderResolveStatsHostname **outHostname)
{
    mStatus                                     err;
    AWDMDNSResponderResolveStatsHostname *      hostname;
    NSString *                                  name;
    char                                        nameBuf[MAX_ESCAPED_DOMAIN_NAME];
    const char *                                ptr;
    ResolveStatsIPv4AddrSet *                   addrV4;
    ResolveStatsIPv6Addr *                      addrV6;
    ResolveStatsNegAAAASet *                    negV6;
    AWDMDNSResponderResolveStatsResult *        result = nil;
    int                                         i;

    hostname = [[AWDMDNSResponderResolveStatsHostnameSoft alloc] init];
    require_action_quiet(hostname, exit, err = mStatus_UnknownErr);

    ptr = ConvertDomainNameToCString((domainname *)inHostname->name, nameBuf);
    require_action_quiet(ptr, exit, err = mStatus_UnknownErr);

    name = [[NSString alloc] initWithUTF8String:nameBuf];
    require_action_quiet(name, exit, err = mStatus_UnknownErr);

    hostname.name = name;
    [name release];
    name = nil;

    for (addrV4 = inHostname->addrV4List; addrV4; addrV4 = addrV4->next)
    {
        for (i = 0; i < (int)countof(addrV4->counters); ++i)
        {
            const IPv4AddrCounter *     counter;
            NSData *                    addrBytes;

            counter = &addrV4->counters[i];
            if (counter->count == 0) break;

            result = [[AWDMDNSResponderResolveStatsResultSoft alloc] init];
            require_action_quiet(result, exit, err = mStatus_UnknownErr);

            if (counter->isNegative)
            {
                result.type = AWDMDNSResponderResolveStatsResult_ResultType_NegA;
            }
            else
            {
                addrBytes = [[NSData alloc] initWithBytes:counter->addrBytes length:4];
                require_action_quiet(addrBytes, exit, err = mStatus_UnknownErr);

                result.type = AWDMDNSResponderResolveStatsResult_ResultType_IPv4Addr;
                result.data = addrBytes;
                [addrBytes release];
            }
            result.count    = counter->count;
            result.serverID = counter->serverID;

            [hostname addResult:result];
            [result release];
            result = nil;
        }
    }

    for (addrV6 = inHostname->addrV6List; addrV6; addrV6 = addrV6->next)
    {
        NSData *        addrBytes;

        result = [[AWDMDNSResponderResolveStatsResultSoft alloc] init];
        require_action_quiet(result, exit, err = mStatus_UnknownErr);

        addrBytes = [[NSData alloc] initWithBytes:addrV6->addrBytes length:16];
        require_action_quiet(addrBytes, exit, err = mStatus_UnknownErr);

        result.type     = AWDMDNSResponderResolveStatsResult_ResultType_IPv6Addr;
        result.count    = addrV6->count;
        result.serverID = addrV6->serverID;
        result.data     = addrBytes;

        [addrBytes release];

        [hostname addResult:result];
        [result release];
        result = nil;
    }

    for (negV6 = inHostname->negV6List; negV6; negV6 = negV6->next)
    {
        for (i = 0; i < (int)countof(negV6->counters); ++i)
        {
            const NegAAAACounter *      counter;

            counter = &negV6->counters[i];
            if (counter->count == 0) break;

            result = [[AWDMDNSResponderResolveStatsResultSoft alloc] init];
            require_action_quiet(result, exit, err = mStatus_UnknownErr);

            result.type     = AWDMDNSResponderResolveStatsResult_ResultType_NegAAAA;
            result.count    = counter->count;
            result.serverID = counter->serverID;

            [hostname addResult:result];
            [result release];
            result = nil;
        }
    }

    *outHostname = hostname;
    hostname = nil;
    err = mStatus_NoError;

exit:
    [result release];
    [hostname release];
    return (err);
}

//===========================================================================================================================
//  ResolveStatsDNSServerCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsDNSServerCreate(const mDNSAddr *inAddr, mDNSBool inForCell, ResolveStatsDNSServer **outServer)
{
    mStatus                     err;
    ResolveStatsDNSServer *     obj;
    size_t                      addrLen;

    require_action_quiet((inAddr->type == mDNSAddrType_IPv4) || (inAddr->type == mDNSAddrType_IPv6), exit, err = mStatus_Invalid);

    addrLen = (inAddr->type == mDNSAddrType_IPv4) ? 4 : 16;
    obj = (ResolveStatsDNSServer *)calloc(1, sizeof(*obj) - 1 + addrLen);
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    obj->isForCell = inForCell;
    if (inAddr->type == mDNSAddrType_IPv4)
    {
        obj->isAddrV6 = mDNSfalse;
        memcpy(obj->addrBytes, inAddr->ip.v4.b, addrLen);
    }
    else
    {
        obj->isAddrV6 = mDNStrue;
        memcpy(obj->addrBytes, inAddr->ip.v6.b, addrLen);
    }

    *outServer = obj;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsDNSServerFree
//===========================================================================================================================

mDNSlocal void ResolveStatsDNSServerFree(ResolveStatsDNSServer *inServer)
{
    free(inServer);
}

//===========================================================================================================================
//  ResolveStatsDNSServerCreateAWDVersion
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsDNSServerCreateAWDVersion(const ResolveStatsDNSServer *inServer, AWDMDNSResponderResolveStatsDNSServer **outServer)
{
    mStatus                                     err;
    AWDMDNSResponderResolveStatsDNSServer *     server;
    NSData *                                    addrBytes = nil;

    server = [[AWDMDNSResponderResolveStatsDNSServerSoft alloc] init];
    require_action_quiet(server, exit, err = mStatus_UnknownErr);

    addrBytes = [[NSData alloc] initWithBytes:inServer->addrBytes length:(inServer->isAddrV6 ? 16 : 4)];
    require_action_quiet(addrBytes, exit, err = mStatus_UnknownErr);

    server.serverID = inServer->id;
    server.address  = addrBytes;
    if (inServer->isForCell)
    {
        server.networkType = AWDMDNSResponderResolveStatsDNSServer_NetworkType_Cellular;
    }
    else
    {
        server.networkType = AWDMDNSResponderResolveStatsDNSServer_NetworkType_NonCellular;
    }

    *outServer = server;
    server = nil;
    err = mStatus_NoError;

exit:
    [addrBytes release];
    [server release];
    return (err);
}

//===========================================================================================================================
//  ResolveStatsIPv4AddrSetCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsIPv4AddrSetCreate(ResolveStatsIPv4AddrSet **outSet)
{
    mStatus                         err;
    ResolveStatsIPv4AddrSet *       obj;

    obj = (ResolveStatsIPv4AddrSet *)calloc(1, sizeof(*obj));
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    *outSet = obj;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsIPv4AddrSetFree
//===========================================================================================================================

mDNSlocal void ResolveStatsIPv4AddrSetFree(ResolveStatsIPv4AddrSet *inSet)
{
    free(inSet);
}

//===========================================================================================================================
//  ResolveStatsIPv6AddressCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsIPv6AddressCreate(uint8_t inServerID, const uint8_t inAddrBytes[16], ResolveStatsIPv6Addr **outAddr)
{
    mStatus                     err;
    ResolveStatsIPv6Addr *      obj;

    obj = (ResolveStatsIPv6Addr *)calloc(1, sizeof(*obj));
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    obj->serverID = inServerID;
    memcpy(obj->addrBytes, inAddrBytes, 16);

    *outAddr = obj;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsIPv6AddressFree
//===========================================================================================================================

mDNSlocal void ResolveStatsIPv6AddressFree(ResolveStatsIPv6Addr *inAddr)
{
    free(inAddr);
}

//===========================================================================================================================
//  ResolveStatsNegAAAASetCreate
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsNegAAAASetCreate(ResolveStatsNegAAAASet **outSet)
{
    mStatus                         err;
    ResolveStatsNegAAAASet *        obj;

    obj = (ResolveStatsNegAAAASet *)calloc(1, sizeof(*obj));
    require_action_quiet(obj, exit, err = mStatus_NoMemoryErr);

    *outSet = obj;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  ResolveStatsNegAAAASetFree
//===========================================================================================================================

mDNSlocal void ResolveStatsNegAAAASetFree(ResolveStatsNegAAAASet *inSet)
{
    free(inSet);
}

//===========================================================================================================================
//  ResolveStatsGetServerID
//===========================================================================================================================

mDNSlocal mStatus ResolveStatsGetServerID(const mDNSAddr *inServerAddr, mDNSBool inForCell, uint8_t *outServerID)
{
    mStatus                         err;
    ResolveStatsDNSServer **        p;
    ResolveStatsDNSServer *         server;

    require_action_quiet((inServerAddr->type == mDNSAddrType_IPv4) || (inServerAddr->type == mDNSAddrType_IPv6), exit, err = mStatus_Invalid);

    for (p = &gResolveStatsServerList; (server = *p) != NULL; p = &server->next)
    {
        if ((inForCell && server->isForCell) || (!inForCell && !server->isForCell))
        {
            if (inServerAddr->type == mDNSAddrType_IPv4)
            {
                if (!server->isAddrV6 && (memcmp(server->addrBytes, inServerAddr->ip.v4.b, 4) == 0)) break;
            }
            else
            {
                if (server->isAddrV6 && (memcmp(server->addrBytes, inServerAddr->ip.v6.b, 16) == 0)) break;
            }
        }
    }

    if (!server)
    {
        require_action_quiet(gResolveStatsNextServerID <= UINT8_MAX, exit, err = mStatus_Refused);
        require_action_quiet(gResolveStatsObjCount < kResolveStatsMaxObjCount, exit, err = mStatus_Refused);
        err = ResolveStatsDNSServerCreate(inServerAddr, inForCell, &server);
        require_noerr_quiet(err, exit);
        gResolveStatsObjCount++;

        server->id   = (uint8_t)gResolveStatsNextServerID++;
        server->next = gResolveStatsServerList;
        gResolveStatsServerList = server;
    }
    else if (gResolveStatsServerList != server)
    {
        *p = server->next;
        server->next = gResolveStatsServerList;
        gResolveStatsServerList = server;
    }

    *outServerID = server->id;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  DNSMessageSizeStatsCreate
//===========================================================================================================================

mDNSlocal mStatus DNSMessageSizeStatsCreate(DNSMessageSizeStats **outStats)
{
    mStatus                     err;
    DNSMessageSizeStats *       stats;

    stats = (DNSMessageSizeStats *)calloc(1, sizeof(*stats));
    require_action_quiet(stats, exit, err = mStatus_NoMemoryErr);

    *outStats = stats;
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  DNSMessageSizeStatsFree
//===========================================================================================================================

mDNSlocal void DNSMessageSizeStatsFree(DNSMessageSizeStats *inStats)
{
    free(inStats);
}

//===========================================================================================================================
//  CreateQueryStatsList
//===========================================================================================================================

mDNSlocal mStatus CreateQueryStatsList(QueryStats **outList)
{
    mStatus                             err;
    QueryStats **                       p;
    QueryStats *                        stats;
    const QueryStatsArgs *              args;
    const QueryStatsArgs * const        end     = kQueryStatsArgs + countof(kQueryStatsArgs);
    QueryStats *                        list    = NULL;

    p = &list;
    for (args = kQueryStatsArgs; args < end; ++args)
    {
        err = QueryStatsCreate(args->domainStr, args->altDomainStr, args->test, args->terminal, &stats);
        require_noerr_quiet(err, exit);

        *p = stats;
        p = &stats->next;
    }

    *outList = list;
    list = NULL;
    err = mStatus_NoError;

exit:
    QueryStatsFreeList(list);
    return (err);
}

//===========================================================================================================================
//  CreateResolveStatsList
//===========================================================================================================================

mDNSlocal mStatus CreateResolveStatsList(ResolveStatsDomain **outList)
{
    mStatus                     err;
    unsigned int                i;
    ResolveStatsDomain *        domain;
    ResolveStatsDomain **       p;
    ResolveStatsDomain *        list = NULL;

    p = &list;
    for (i = 0; i < (unsigned int)countof(kResolveStatsDomains); ++i)
    {
        err = ResolveStatsDomainCreate(kResolveStatsDomains[i], &domain);
        require_noerr_quiet(err, exit);

        *p = domain;
        p = &domain->next;
    }

    *outList = list;
    list = NULL;
    err = mStatus_NoError;

exit:
    FreeResolveStatsList(list);
    return (err);
}

//===========================================================================================================================
//  FreeResolveStatsList
//===========================================================================================================================

mDNSlocal void FreeResolveStatsList(ResolveStatsDomain *inList)
{
    ResolveStatsDomain *        domain;

    while ((domain = inList) != NULL)
    {
        inList = domain->next;
        ResolveStatsDomainFree(domain);
    }
}

//===========================================================================================================================
//  FreeResolveStatsServerList
//===========================================================================================================================

mDNSlocal void FreeResolveStatsServerList(ResolveStatsDNSServer *inList)
{
    ResolveStatsDNSServer *     server;

    while ((server = inList) != NULL)
    {
        inList = server->next;
        ResolveStatsDNSServerFree(server);
    }
}

//===========================================================================================================================
//  SubmitAWDMetric
//===========================================================================================================================

mDNSlocal mStatus SubmitAWDMetric(UInt32 inMetricID)
{
    mStatus     err;

    switch (inMetricID)
    {
        case AWDMetricId_MDNSResponder_DNSStatistics:
            err = SubmitAWDMetricQueryStats();
            break;

        case AWDMetricId_MDNSResponder_ResolveStats:
            err = SubmitAWDMetricResolveStats();
            break;

        case AWDMetricId_MDNSResponder_ServicesStats:
            [AWDMetricManagerSoft postMetricWithId:AWDMetricId_MDNSResponder_ServicesStats unsignedIntegerValue:max_num_regservices];
            KQueueLock();
            // reset the no of max services since we want to collect the max no of services registered per AWD submission period
            max_num_regservices = curr_num_regservices;
            KQueueUnlock("SubmitAWDSimpleMetricServiceStats");
            err = mStatus_NoError;
            break;

        case AWDMetricId_MDNSResponder_DNSMessageSizeStats:
            err = SubmitAWDMetricDNSMessageSizeStats();
            break;

        default:
            err = mStatus_UnsupportedErr;
            break;
    }

    if (err) LogMsg("SubmitAWDMetric for metric ID 0x%08X failed with error %d", inMetricID, err);
    return (err);
}

//===========================================================================================================================
//  SubmitAWDMetricQueryStats
//===========================================================================================================================

mDNSlocal mStatus   AddQueryStats(AWDMDNSResponderDNSStatistics *inMetric, const QueryStats *inStats);
mDNSlocal mStatus   AddDNSHistSet(AWDMDNSResponderDNSStatistics *inMetric, DNSHistSet *inSet, const char *inDomain, mDNSBool inForCell);

mDNSlocal mStatus SubmitAWDMetricQueryStats(void)
{
    mStatus                             err;
    BOOL                                success;
    QueryStats *                        stats;
    QueryStats *                        statsList;
    QueryStats *                        newStatsList;
    AWDMetricContainer *                container   = nil;
    AWDMDNSResponderDNSStatistics *     metric      = nil;

    newStatsList = NULL;
    CreateQueryStatsList(&newStatsList);

    KQueueLock();
    statsList       = gQueryStatsList;
    gQueryStatsList = newStatsList;
    KQueueUnlock("SubmitAWDMetricQueryStats");

    container = [gAWDServerConnection newMetricContainerWithIdentifier:AWDMetricId_MDNSResponder_DNSStatistics];
    require_action_quiet(container, exit, err = mStatus_UnknownErr);

    metric = [[AWDMDNSResponderDNSStatisticsSoft alloc] init];
    require_action_quiet(metric, exit, err = mStatus_UnknownErr);

    while ((stats = statsList) != NULL)
    {
        err = AddQueryStats(metric, stats);
        require_noerr_quiet(err, exit);

        statsList = stats->next;
        QueryStatsFree(stats);
    }

    container.metric = metric;
    success = [gAWDServerConnection submitMetric:container];
    LogMsg("SubmitAWDMetricQueryStats: metric submission %s.", success ? "succeeded" : "failed");
    err = success ? mStatus_NoError : mStatus_UnknownErr;

exit:
    [metric release];
    [container release];
    QueryStatsFreeList(statsList);
    return (err);
}

mDNSlocal mStatus AddQueryStats(AWDMDNSResponderDNSStatistics *inMetric, const QueryStats *inStats)
{
    mStatus     err;

    if (inStats->nonCellular)
    {
        err = AddDNSHistSet(inMetric, inStats->nonCellular, QueryStatsGetDomainString(inStats), mDNSfalse);
        require_noerr_quiet(err, exit);
    }
    if (inStats->cellular)
    {
        err = AddDNSHistSet(inMetric, inStats->cellular, QueryStatsGetDomainString(inStats), mDNStrue);
        require_noerr_quiet(err, exit);
    }
    err = mStatus_NoError;

exit:
    return (err);
}

mDNSlocal mStatus AddDNSHistSet(AWDMDNSResponderDNSStatistics *inMetric, DNSHistSet *inSet, const char *inDomain, mDNSBool inForCell)
{
    mStatus                 err;
    AWDDNSDomainStats *     awdStats;

    if (inSet->histA)
    {
        err = CreateAWDDNSDomainStats(inSet->histA, inDomain, inForCell, AWDDNSDomainStats_RecordType_A, &awdStats);
        require_noerr_quiet(err, exit);

        [inMetric addStats:awdStats];
        [awdStats release];
    }
    if (inSet->histAAAA)
    {
        err = CreateAWDDNSDomainStats(inSet->histAAAA, inDomain, inForCell, AWDDNSDomainStats_RecordType_AAAA, &awdStats);
        require_noerr_quiet(err, exit);

        [inMetric addStats:awdStats];
        [awdStats release];
    }
    err = mStatus_NoError;

exit:
    return (err);
}

//===========================================================================================================================
//  SubmitAWDMetricResolveStats
//===========================================================================================================================

mDNSlocal mStatus SubmitAWDMetricResolveStats(void)
{
    mStatus                             err;
    ResolveStatsDomain *                newResolveStatsList;
    ResolveStatsDomain *                domainList  = NULL;
    ResolveStatsDNSServer *             serverList  = NULL;
    AWDMetricContainer *                container   = nil;
    AWDMDNSResponderResolveStats *      metric      = nil;
    ResolveStatsDNSServer *             server;
    ResolveStatsDomain *                domain;
    BOOL                                success;

    err = CreateResolveStatsList(&newResolveStatsList);
    require_noerr_quiet(err, exit);

    KQueueLock();
    domainList = gResolveStatsList;
    serverList = gResolveStatsServerList;
    gResolveStatsList           = newResolveStatsList;
    gResolveStatsServerList     = NULL;
    gResolveStatsNextServerID   = 0;
    gResolveStatsObjCount       = 0;
    KQueueUnlock("SubmitAWDMetricResolveStats");

    container = [gAWDServerConnection newMetricContainerWithIdentifier:AWDMetricId_MDNSResponder_ResolveStats];
    require_action_quiet(container, exit, err = mStatus_UnknownErr);

    metric = [[AWDMDNSResponderResolveStatsSoft alloc] init];
    require_action_quiet(metric, exit, err = mStatus_UnknownErr);

    while ((server = serverList) != NULL)
    {
        AWDMDNSResponderResolveStatsDNSServer *     awdServer;

        serverList = server->next;
        err = ResolveStatsDNSServerCreateAWDVersion(server, &awdServer);
        ResolveStatsDNSServerFree(server);
        require_noerr_quiet(err, exit);

        [metric addServer:awdServer];
        [awdServer release];
    }

    while ((domain = domainList) != NULL)
    {
        AWDMDNSResponderResolveStatsDomain *        awdDomain;

        domainList = domain->next;
        err = ResolveStatsDomainCreateAWDVersion(domain, &awdDomain);
        ResolveStatsDomainFree(domain);
        require_noerr_quiet(err, exit);

        [metric addDomain:awdDomain];
        [awdDomain release];
    }

    container.metric = metric;
    success = [gAWDServerConnection submitMetric:container];
    LogMsg("SubmitAWDMetricResolveStats: metric submission %s.", success ? "succeeded" : "failed");
    err = success ? mStatus_NoError : mStatus_UnknownErr;

exit:
    [metric release];
    [container release];
    FreeResolveStatsList(domainList);
    FreeResolveStatsServerList(serverList);
    return (err);
}

//===========================================================================================================================
//  SubmitAWDMetricDNSMessageSizeStats
//===========================================================================================================================

mDNSlocal mStatus SubmitAWDMetricDNSMessageSizeStats(void)
{
    mStatus                                     err;
    DNSMessageSizeStats *                       stats;
    DNSMessageSizeStats *                       newStats;
    AWDMetricContainer *                        container;
    AWDMDNSResponderDNSMessageSizeStats *       metric = nil;
    BOOL                                        success;

    newStats = NULL;
    DNSMessageSizeStatsCreate(&newStats);

    KQueueLock();
    stats                   = gDNSMessageSizeStats;
    gDNSMessageSizeStats    = newStats;
    KQueueUnlock("SubmitAWDMetricDNSMessageSizeStats");

    container = [gAWDServerConnection newMetricContainerWithIdentifier:AWDMetricId_MDNSResponder_DNSMessageSizeStats];
    require_action_quiet(container, exit, err = mStatus_UnknownErr);

    metric = [[AWDMDNSResponderDNSMessageSizeStatsSoft alloc] init];
    require_action_quiet(metric, exit, err = mStatus_UnknownErr);

    if (stats)
    {
        size_t          binCount;
        uint32_t        bins[Max(kQuerySizeBinCount, kResponseSizeBinCount)];

        // Set query size counts.

        binCount = CopyHistogramBins(bins, stats->querySizeBins, kQuerySizeBinCount);
        [metric setQuerySizeCounts:bins count:(NSUInteger)binCount];

        // Set response size counts.

        binCount = CopyHistogramBins(bins, stats->responseSizeBins, kResponseSizeBinCount);
        [metric setResponseSizeCounts:bins count:(NSUInteger)binCount];
    }

    container.metric = metric;
    success = [gAWDServerConnection submitMetric:container];
    LogMsg("SubmitAWDMetricDNSMessageSizeStats: metric submission %s.", success ? "succeeded" : "failed");
    err = success ? mStatus_NoError : mStatus_UnknownErr;

exit:
    [metric release];
    [container release];
    if (stats) DNSMessageSizeStatsFree(stats);
    return (err);
}

//===========================================================================================================================
//  CreateAWDDNSDomainStats
//===========================================================================================================================

mDNSlocal mStatus CreateAWDDNSDomainStats(DNSHist *inHist, const char *inDomain, mDNSBool inForCell, AWDDNSDomainStats_RecordType inType, AWDDNSDomainStats **outStats)
{
    mStatus                 err;
    AWDDNSDomainStats *     awdStats    = nil;
    NSString *              domain      = nil;
    size_t                  binCount;
    uint32_t                sendCountBins[kQueryStatsSendCountBinCount];
    uint32_t                latencyBins[kQueryStatsLatencyBinCount];
    uint32_t                expiredAnswerBins[kQueryStatsExpiredAnswerStateCount];

    awdStats = [[AWDDNSDomainStatsSoft alloc] init];
    require_action_quiet(awdStats, exit, err = mStatus_UnknownErr);

    domain = [[NSString alloc] initWithUTF8String:inDomain];
    require_action_quiet(domain, exit, err = mStatus_UnknownErr);

    awdStats.domain      = domain;
    awdStats.networkType = inForCell ? AWDDNSDomainStats_NetworkType_Cellular : AWDDNSDomainStats_NetworkType_NonCellular;
    awdStats.recordType  = inType;

    // Positively answered query send counts

    binCount = CopyHistogramBins(sendCountBins, inHist->answeredQuerySendCountBins, kQueryStatsSendCountBinCount);
    [awdStats setAnsweredQuerySendCounts:sendCountBins count:(NSUInteger)binCount];

    // binCount > 1 means that at least one of the non-zero send count bins had a non-zero count, i.e., at least one query
    // was sent out on the wire. In that case, include the associated latency bins as well.

    if (binCount > 1)
    {
        binCount = CopyHistogramBins(latencyBins, inHist->responseLatencyBins, kQueryStatsLatencyBinCount);
        [awdStats setResponseLatencyMs:latencyBins count:(NSUInteger)binCount];
    }

    // Negatively answered query send counts

    binCount = CopyHistogramBins(sendCountBins, inHist->negAnsweredQuerySendCountBins, kQueryStatsSendCountBinCount);
    [awdStats setNegAnsweredQuerySendCounts:sendCountBins count:(NSUInteger)binCount];

    if (binCount > 1)
    {
        binCount = CopyHistogramBins(latencyBins, inHist->negResponseLatencyBins, kQueryStatsLatencyBinCount);
        [awdStats setNegResponseLatencyMs:latencyBins count:(NSUInteger)binCount];
    }

    // Unanswered query send counts

    binCount = CopyHistogramBins(sendCountBins, inHist->unansweredQuerySendCountBins, kQueryStatsSendCountBinCount);
    [awdStats setUnansweredQuerySendCounts:sendCountBins count:(NSUInteger)binCount];

    if (binCount > 1)
    {
        binCount = CopyHistogramBins(latencyBins, inHist->unansweredQueryDurationBins, kQueryStatsLatencyBinCount);
        [awdStats setUnansweredQueryDurationMs:latencyBins count:(NSUInteger)binCount];
    }
    
    // Expired answers states
    
    binCount = CopyHistogramBins(expiredAnswerBins, inHist->expiredAnswerStateBins, kQueryStatsExpiredAnswerStateCount);
    [awdStats setExpiredAnswerStates:expiredAnswerBins count:(NSUInteger)binCount];

    *outStats = awdStats;
    awdStats = nil;
    err = mStatus_NoError;

exit:
    [domain release];
    [awdStats release];
    return (err);
}

//===========================================================================================================================
//  LogDNSHistSet
//===========================================================================================================================

mDNSlocal void LogDNSHistSet(const DNSHistSet *inSet, const char *inDomain, mDNSBool inForCell)
{
    if (inSet->histA)       LogDNSHist(inSet->histA,    inDomain, inForCell, "A");
    if (inSet->histAAAA)    LogDNSHist(inSet->histAAAA, inDomain, inForCell, "AAAA");
}

//===========================================================================================================================
//  LogDNSHist
//===========================================================================================================================

#define Percent(N, D)       (((N) * 100) / (D)), ((((N) * 10000) / (D)) % 100)
#define PercentFmt          "%3u.%02u"
#define LogStat(LABEL, COUNT, ACCUMULATOR, TOTAL) \
    LogMsgNoIdent("%s %5u " PercentFmt " " PercentFmt, (LABEL), (COUNT), Percent(COUNT, TOTAL), Percent(ACCUMULATOR, TOTAL))

mDNSlocal void LogDNSHist(const DNSHist *inHist, const char *inDomain, mDNSBool inForCell, const char *inType)
{
    unsigned int        totalAnswered;
    unsigned int        totalNegAnswered;
    unsigned int        totalUnanswered;
    int                 i;

    totalAnswered = 0;
    for (i = 0; i < kQueryStatsSendCountBinCount; ++i)
    {
        totalAnswered += inHist->answeredQuerySendCountBins[i];
    }

    totalNegAnswered = 0;
    for (i = 0; i < kQueryStatsSendCountBinCount; ++i)
    {
        totalNegAnswered += inHist->negAnsweredQuerySendCountBins[i];
    }

    totalUnanswered = 0;
    for (i = 0; i < kQueryStatsSendCountBinCount; ++i)
    {
        totalUnanswered += inHist->unansweredQuerySendCountBins[i];
    }

    LogMsgNoIdent("Domain: %s (%s, %s)", inDomain, inForCell ? "C" : "NC", inType);
    LogMsgNoIdent("Answered questions            %4u", totalAnswered);
    LogMsgNoIdent("Negatively answered questions %4u", totalNegAnswered);
    LogMsgNoIdent("Unanswered questions          %4u", totalUnanswered);
    LogMsgNoIdent("Expired - no cached answer    %4u", inHist->expiredAnswerStateBins[ExpiredAnswer_Allowed]);
    LogMsgNoIdent("Expired - answered from cache %4u", inHist->expiredAnswerStateBins[ExpiredAnswer_AnsweredWithExpired]);
    LogMsgNoIdent("Expired - cache changed       %4u", inHist->expiredAnswerStateBins[ExpiredAnswer_ExpiredAnswerChanged]);
    LogMsgNoIdent("-- Query send counts ---------");
    LogDNSHistSendCounts(inHist->answeredQuerySendCountBins);
    LogMsgNoIdent("-- Query send counts (NAQs) --");
    LogDNSHistSendCounts(inHist->negAnsweredQuerySendCountBins);

    if (totalAnswered > inHist->answeredQuerySendCountBins[0])
    {
        LogMsgNoIdent("--- Response times -----------");
        LogDNSHistLatencies(inHist->responseLatencyBins);
    }

    if (totalNegAnswered > inHist->negAnsweredQuerySendCountBins[0])
    {
        LogMsgNoIdent("--- Response times (NAQs) ----");
        LogDNSHistLatencies(inHist->negResponseLatencyBins);
    }

    if (totalUnanswered > 0)
    {
        LogMsgNoIdent("--- Unanswered query times ---");
        LogDNSHistLatencies(inHist->unansweredQueryDurationBins);
    }
}

//===========================================================================================================================
//  LogDNSHistSendCounts
//===========================================================================================================================

mDNSlocal void LogDNSHistSendCounts(const uint16_t inSendCountBins[kQueryStatsSendCountBinCount])
{
    uint32_t        total;
    char            label[16];
    int             i;

    total = 0;
    for (i = 0; i < kQueryStatsSendCountBinCount; ++i)
    {
        total += inSendCountBins[i];
    }

    if (total > 0)
    {
        uint32_t        accumulator = 0;

        for (i = 0; i < kQueryStatsSendCountBinCount; ++i)
        {
            accumulator += inSendCountBins[i];
            if (i < (kQueryStatsSendCountBinCount - 1))
            {
                snprintf(label, sizeof(label), "%2d ", i);
            }
            else
            {
                snprintf(label, sizeof(label), "%2d+", i);
            }
            LogStat(label, inSendCountBins[i], accumulator, total);
            if (accumulator == total) break;
        }
    }
    else
    {
        LogMsgNoIdent("No data.");
    }
}

//===========================================================================================================================
//  LogDNSHistLatencies
//===========================================================================================================================

mDNSlocal void LogDNSHistLatencies(const uint16_t inLatencyBins[kQueryStatsLatencyBinCount])
{
    uint32_t        total;
    int             i;
    char            label[16];

    total = 0;
    for (i = 0; i < kQueryStatsLatencyBinCount; ++i)
    {
        total += inLatencyBins[i];
    }

    if (total > 0)
    {
        uint32_t        accumulator = 0;

        for (i = 0; i < kQueryStatsLatencyBinCount; ++i)
        {
            accumulator += inLatencyBins[i];
            if (i < (int)countof(kResponseLatencyMsLimits))
            {
                snprintf(label, sizeof(label), "< %5u ms", kResponseLatencyMsLimits[i]);
            }
            else
            {
                snprintf(label, sizeof(label), "<     ∞ ms");
            }
            LogStat(label, inLatencyBins[i], accumulator, total);
            if (accumulator == total) break;
        }
    }
    else
    {
        LogMsgNoIdent("No data.");
    }
}

//===========================================================================================================================
//  LogDNSMessageSizeStats
//===========================================================================================================================

mDNSlocal void LogDNSMessageSizeStats(const uint16_t *inBins, size_t inBinCount, unsigned int inBinWidth)
{
    size_t          i;
    uint32_t        total;

    total = 0;
    for (i = 0; i < inBinCount; ++i)
    {
        total += inBins[i];
    }

    if (total > 0)
    {
        uint32_t            accumulator;
        unsigned int        lower, upper;
        char                label[16];

        accumulator = 0;
        upper       = 0;
        for (i = 0; i < inBinCount; ++i)
        {
            accumulator += inBins[i];
            lower = upper + 1;
            if (i < (inBinCount - 1))
            {
                upper += inBinWidth;
                snprintf(label, sizeof(label), "%3u - %-3u", lower, upper);
            }
            else
            {
                snprintf(label, sizeof(label), "%3u+     ", lower);
            }
            LogStat(label, inBins[i], accumulator, total);
            if (accumulator == total) break;
        }
    }
    else
    {
        LogMsgNoIdent("No data.");
    }
}

//===========================================================================================================================
//  CopyHistogramBins
//
//  Note: The return value is the size (in number of elements) of the smallest contiguous sub-array that contains the first
//  bin and all bins with non-zero values.
//===========================================================================================================================

mDNSlocal size_t CopyHistogramBins(uint32_t *inDstBins, uint16_t *inSrcBins, size_t inBinCount)
{
    size_t      i;
    size_t      minCount;

    if (inBinCount == 0) return (0);

    minCount = 1;
    for (i = 0; i < inBinCount; ++i)
    {
        inDstBins[i] = inSrcBins[i];
        if (inDstBins[i] > 0) minCount = i + 1;
    }

    return (minCount);
}
#endif // TARGET_OS_IOS
