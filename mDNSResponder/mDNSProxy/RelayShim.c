/* -*- Mode: C; tab-width: 4; c-file-style: "bsd"; c-basic-offset: 4; fill-column: 108 -*-
 *
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
 *
 */

//*************************************************************************************************************
// Headers

#include <sys/socket.h>      // For AF_INET, AF_INET6, etc.
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "mDNSPosix.h"
#include "DSO.h"
#include "RelayProtocol.h"
#include "RelayInterface.h"

//*************************************************************************************************************
// Globals

mDNS mDNSStorage;                       // mDNS core uses this to store its globals
mDNS_PlatformSupport PlatformStorage;    // Stores this platform's globals
struct timeval tv_start, tv_end, tv_interval;

// mDNSCore shim code
mDNSexport mStatus mDNS_Init(mDNS *const m, mDNS_PlatformSupport *const p,
                             CacheEntity *rrcachestorage, mDNSu32 rrcachesize,
                             mDNSBool AdvertiseLocalAddresses, mDNSCallback *Callback, void *Context)
{
    mDNSs32 timenow = mDNS_TimeNow_NoLock(m);
    mStatus result;

	(void)rrcachestorage;
	(void)rrcachesize;
	
	memset(m, 0, sizeof *m);
	m->p = p;
	m->AdvertiseLocalAddresses       = AdvertiseLocalAddresses;
    m->mDNSPlatformStatus            = mStatus_Waiting;
    m->MainCallback                  = Callback;
    m->MainContext                   = Context;

    result = mDNSPlatformTimeInit();
    if (result != mStatus_NoError) return(result);

    m->timenow_adjust = (mDNSs32)mDNSRandom(0xFFFFFFFF);
	
    if (result != mStatus_NoError)
        return(result);

    m->timenow_last            = timenow;
    m->NextScheduledEvent      = timenow;
    m->SuppressSending         = timenow;
    m->NextCacheCheck          = timenow + FutureTime;
    m->NextScheduledQuery      = timenow + FutureTime;
    m->NextScheduledProbe      = timenow + FutureTime;
    m->NextScheduledResponse   = timenow + FutureTime;
    m->NextScheduledNATOp      = timenow + FutureTime;
    m->NextScheduledSPS        = timenow + FutureTime;
    m->NextScheduledKA         = timenow + FutureTime;
    m->NextScheduledStopTime   = timenow + FutureTime;
    
    m->SleepState              = SleepState_Awake;
    m->rrcache_report          = 10;

    result = mDNSPlatformInit(m);

    return(result);
}

mDNSexport void mDNSCoreInitComplete(mDNS *const m, mStatus result)
{
	(void)result;
	(void)m;
}

// XXX called from the event loop, returns the next time we need an event.   Use for keepalive.
mDNSexport mDNSs32 mDNS_Execute(mDNS *const m)
{
    mDNS_Lock(m);   // Must grab lock before trying to read m->timenow
	// :]
    mDNS_Unlock(m);     // Calling mDNS_Unlock is what gives m->NextScheduledEvent its new value
    return(m->NextScheduledEvent);
}

mDNSexport DNSServer *mDNS_AddDNSServer(mDNS *const m, const domainname *d, const mDNSInterfaceID interface,
										const mDNSs32 serviceID, const mDNSAddr *addr, const mDNSIPPort port,
										mDNSu32 scoped, mDNSu32 timeout, mDNSBool cellIntf, mDNSBool isExpensive,
										mDNSu16 resGroupID, mDNSBool reqA, mDNSBool reqAAAA, mDNSBool reqDO)
{
	(void)m;
	(void)d;
	(void)interface;
	(void)serviceID;
	(void)addr;
	(void)port;
	(void)scoped;
	(void)timeout;
	(void)cellIntf;
	(void)isExpensive;
	(void)resGroupID;
	(void)reqA;
	(void)reqAAAA;
	(void)reqDO;
	
	return NULL;
}

mDNSexport mStatus mDNS_SetSecretForDomain(mDNS *m, DomainAuthInfo *info,
                                           const domainname *domain, const domainname *keyname, const char *b64keydata, const domainname *hostname, mDNSIPPort *port, mDNSBool autoTunnel)
{
	(void)m;
	(void)info;
	(void)domain;
	(void)keyname;
	(void)b64keydata;
	(void)hostname;
	(void)port;
	(void)autoTunnel;
	
	return mStatus_NoError;
}

mDNSexport void mDNS_SetFQDN(mDNS *const m)
{
	(void)m;
}

mDNSexport mDNSs32 mDNS_TimeNow(const mDNS *const m)
{
    mDNSs32 time;
    mDNSPlatformLock(m);
    if (m->mDNS_busy) {
        LogMsg("mDNS_TimeNow called while holding mDNS lock. This is incorrect. Code protected by lock should just use m->timenow.");
        if (!m->timenow) LogMsg("mDNS_TimeNow: m->mDNS_busy is %ld but m->timenow not set", m->mDNS_busy);
    }

    if (m->timenow) time = m->timenow;
    else time = mDNS_TimeNow_NoLock(m);
    mDNSPlatformUnlock(m);
    return(time);
}

mDNSexport void rciEnumerateInterfaces(mDNS *m, mDNSs32 utc,
									   int (*ifsetup)(mDNS *const m, mDNSAddr *addr, mDNSAddr *mask,
													  struct sockaddr *intfAddr, char *name,
													  int index, mDNSs32 utc, void *link))
{
	(void)m;
	(void)ifsetup;
	(void)utc;
}

mDNSexport mStatus rciSendMessage(const void *const msg, const mDNSu8 *const end, void *linkv)
{
	(void)msg;
	(void)end;
	(void)linkv;
	return mStatus_NoError;
}

mDNSexport void rciInit(mDNS *const m)
{
	(void)m;
}

mDNSexport mDNSs32 rciIdle(mDNS *const m, mDNSs32 nextTimerEvent)
{
	(void)m;
	return nextTimerEvent;
}

#ifdef RELAY_TEST_MAIN
//*************************************************************************************************************
// Globals

const char ProgramName[] = "relaytest";
DiscoveryRelayState *discoveryRelays;
DiscoveryRelayConnectState *connectState;
mDNSu16 configPort;

mDNSexport void mDNSCoreReceive(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end,
                                const mDNSAddr *srcaddr, mDNSIPPort srcport, const mDNSAddr *dstaddr,
								mDNSIPPort dstport, const mDNSInterfaceID InterfaceID)
{
	(void)m;
	(void)msg;
	(void)end;
	(void)srcaddr;
	(void)srcport;
	(void)dstaddr;
	(void)dstport;
	(void)InterfaceID;

	// The tester doesn't actually care about incoming mDNS packets.   Probably shouldn't listen for them.
}

mDNSlocal void drFinalize(DiscoveryRelayState *dr)
{
	DiscoveryRelayState **drp = &discoveryRelays;
	// Remove this relay from the list (which currently can only have one entry, but that could
	// usefully change.
	while (*drp) {
		if (*drp == dr) {
			*drp = dr->next;
		} else {
			drp = &((*drp)->next);
		}
	}
	LogMsg("Dropping connection to Discovery Proxy %s", &dr->dso->remoteName);
	free(dr);
}

// Set up the initial server state and run the event loop.
mDNSlocal mStatus mDNSRelayTest(const char *host, int port)
{
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct addrinfo *ai;
	int rc;
	sigset_t signals;
	mDNSBool gotSomething = mDNSfalse;

	// Set up mDNS listener/sender infrastructure
    mStatus status = mDNS_Init(&mDNSStorage, &PlatformStorage,
                               mDNS_Init_NoCache, mDNS_Init_ZeroCacheSize,
                               mDNS_Init_AdvertiseLocalAddresses,
                               mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
    if (status)
		return(status);

	memset(&sin, 0, sizeof sin);
	memset(&sin6, 0, sizeof sin6);
	
	// Validate the hostname or IP address
	rc = getaddrinfo(host, NULL, NULL, &ai);
	if (rc < 0) {
		LogMsg("TestRelay: resolution on %s failed: %s", host, strerror(errno));
		return mStatus_Invalid;
	}
	
    gettimeofday(&tv_start, NULL);
	
    mDNSPosixListenForSignalInEventLoop(SIGINT);
    mDNSPosixListenForSignalInEventLoop(SIGTERM);

	connectState = drConnectStateCreate(&mDNSStorage,
										host, port, 10, AbsoluteMaxDNSMessageData, 256, "mDNSRelayText", drFinalize);
	if (connectState == NULL) {
		LogMsg("TestRelay: unable to create a discovery proxy structure!");
		return mDNSfalse;
	}

	// Connect to the relay.
    do {
        struct timeval timeout;
		mDNSs32 ticks;

        // Only idle if we didn't find any data the last time around
        if (!gotSomething) {
			mDNSs32 now = mDNS_TimeNow(&mDNSStorage);
            ticks = DSOIdle(now + 1000 * mDNSPlatformOneSecond) - now;
            if (ticks < 1) ticks = 1;
        } else {    // otherwise call EventLoop again with 0 timemout
            ticks = 0;
		}

        timeout.tv_sec = ticks / mDNSPlatformOneSecond;
        timeout.tv_usec = (ticks % mDNSPlatformOneSecond) * 1000000 / mDNSPlatformOneSecond;

		// If we lose our connection to the proxy (or aren't yet connected), reconnect.
		if (discoveryRelays == NULL) {
			drConnected(connectState, NULL, mDNSfalse);
		}
        mDNSPosixRunEventLoopOnce(&mDNSStorage, &timeout, &signals, &gotSomething);
    }
    while ( !( sigismember( &signals, SIGINT) || sigismember( &signals, SIGTERM)));
	return mDNStrue;
}

mDNSexport DiscoveryRelayState *drConnected(void *context, DSOState *dso, mDNSBool connected)
{
	DiscoveryRelayConnectState *drc = context;
	DiscoveryRelayState *dr;

	if (!connected) {
		sleep(5);
		drConnect(drc);
		return NULL;
	}

	LogMsg("Connected to %s at %#a%%%d", dso->remoteName, &dso->remoteAddr, dso->remotePort);
	dr = drCreate(NULL, dso, drFinalize);
	if (dr == NULL) {
		LogMsg("RelayTest: drCreate for %s failed", dso->remoteName);
		return NULL;
	}
	dr->next = discoveryRelays;
	discoveryRelays = dr;

	// Request interface notifications.
	drRequestLinkNotifications(dr);
	return dr;
}

mDNSexport int main(int argc, char **argv)
{
    const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    int i;
    mStatus status;
	int connectPort;

#if defined(WIN32)
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);
#endif

    setlinebuf(stdout);             // Want to see lines as they appear, not block buffered

	if (argc != 3) {
		goto usage;
	}

	char *sp;
	connectPort = strtol(argv[2], &sp, 10);
	if (*sp != '\0' || connectPort < 1 || connectPort > 65535) {
		fprintf(stderr, "%s: invalid port number\n", argv[2]);
		goto usage;
	}

	mDNS_LoggingEnabled = 1;
    status = mDNSRelayTest(argv[1], connectPort);
	if (status == mStatus_Invalid) {
		goto usage;
	}
    fprintf(stderr, "%s: TestRelay failed %d\n", progname, (int)status);
	return status;

usage:
    fprintf(stderr, "\nmDNS Discovery Relay Tester\n");
	fprintf(stderr, "%s", argv[0]);
	for (i = 1; i < argc; i++)
		fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s <host> <port>\n", progname);
    fprintf(stderr, "\n");
    return(-1);
}

mDNSexport mStatus mDNS_RegisterInterface(mDNS *const m, NetworkInterfaceInfo *set,
										  InterfaceActivationSpeed activationSpeed)
{
    NetworkInterfaceInfo **p = &m->HostInterfaces;

	(void)activationSpeed;

	mDNS_Lock(m);

    // Assume this interface will be active now, unless we find a duplicate already in the list
    set->InterfaceActive = mDNStrue;
    set->IPv4Available   = (mDNSu8)(set->ip.type == mDNSAddrType_IPv4 && set->McastTxRx);
    set->IPv6Available   = (mDNSu8)(set->ip.type == mDNSAddrType_IPv6 && set->McastTxRx);

    // Scan list to see if this InterfaceID is already represented
    while (*p) {
        if (*p == set) {
            LogMsg("mDNS_RegisterInterface: called on a NetworkInterfaceInfo that's already in the list");
            mDNS_Unlock(m);
            return(mStatus_AlreadyRegistered);
        }

        if ((*p)->InterfaceID == set->InterfaceID) {
            // This InterfaceID already represented by a different interface in the list, so mark this
            // instance inactive for now
            set->InterfaceActive = mDNSfalse;
            if (set->ip.type == mDNSAddrType_IPv4 && set->McastTxRx) (*p)->IPv4Available = mDNStrue;
            if (set->ip.type == mDNSAddrType_IPv6 && set->McastTxRx) (*p)->IPv6Available = mDNStrue;
        }

        p=&(*p)->next;
    }

    set->next = mDNSNULL;
    *p = set;
    mDNS_Unlock(m);

	return mStatus_NoError;
}

mDNSexport void mDNS_DeregisterInterface(mDNS *const m, NetworkInterfaceInfo *set,
										 InterfaceActivationSpeed activationSpeed)
{
    NetworkInterfaceInfo **p = &m->HostInterfaces;
	(void)activationSpeed;

	mDNS_Lock(m);

	while (*p) {
		if (*p == set) {
			*p = set->next;
			set->next = NULL;
			break;
		}
	}
	mDNS_Unlock(m);
}

// called when a DNS Message comes in from a discovery relay
void drReceivedMDNSMessage(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family,
						   mDNSAddr *sourceAddress, mDNSu16 sourcePort, mDNSu8 *message, size_t length)
{
	(void)dr;
	(void)linkID;
	(void)family;
	(void)sourceAddress;
	(void)sourcePort;
	(void)message;
	(void)length;
	// Don't actually need to do anything.
}


void drLinkAvailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family, mDNSAddr *prefix, int preflen)
{
	(void)prefix;
	(void)preflen;
	drRequestLink(dr, linkID, family);	
}

void drLinkUnavailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family)
{
	(void)dr;
	(void)linkID;
	(void)family;
	// ??
}

#endif
