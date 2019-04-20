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
//
// This module provides the infrastructure required to have mDNSResponder connect to discovery relays,
// discover virtual "interfaces" on those relays (links), get mDNS traffic from those links, and send
// mDNS queries on those links.

//*************************************************************************************************************
// Headers

#include <stdio.h>          // For printf()
#include <stdlib.h>         // For malloc()
#include <string.h>         // For strrchr(), strcmp()
#include <time.h>           // For "struct tm" etc.
#include <signal.h>         // For SIGINT, SIGTERM
#include <assert.h>
#include <netdb.h>           // For gethostbyname()
#include <sys/socket.h>      // For AF_INET, AF_INET6, etc.
#include <net/if.h>          // For IF_NAMESIZE
#include <netinet/in.h>      // For INADDR_NONE
#include <netinet/tcp.h>     // For SOL_TCP, TCP_NOTSENT_LOWAT
#include <arpa/inet.h>       // For inet_addr()
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "RelayInterface.h"
#include "DSO.h"
#include "RelayProtocol.h"
#include "cfParse.h"

//*************************************************************************************************************
// Types and structures

typedef struct extrarelay {
	struct extrarelay *next;
	DiscoveryRelayState *relay;
} ExtraRelay;

typedef struct relaylink {
	struct relaylink *next;
	ExtraRelay *extras;
	LinkFamily family;
	mDNSu32 linkID;
	mDNSu32 ifix;
	mDNSAddr prefix;
	int preflen;
	DiscoveryRelayState *relay;
	char *name;
} RelayLink;

// Links are never freed, and therefore pointers to them can be safely stored in other data structures.
RelayLink *linksAvailable;
RelayLink *linksUnavailable;
static int ifi_base = 0x1000;


// Get a list of relays
// Connect to each relay
// When we get a link available TLV, announce it as a new interface
// When our connection to a relay drops, schedule a restart
// When our connection to a relay dies, we no longer have a way to send or receive on that "interface";
// messages that are "sent" are just dropped, and we trust the retry logic to recover.


DiscoveryRelayConnectState *configuredConnectStates;

// This is called by (currently) SetupInterfaceList in mDNSPosix.c to enumerate all of the known relay-provided links.
// The ifsetup function from mDNSPosix is SetupOneInterface.
mDNSexport void rciEnumerateInterfaces(mDNS *m, mDNSs32 utc,
									   int (*ifsetup)(mDNS *const m, mDNSAddr *addr, mDNSAddr *mask,
													  struct sockaddr *intfAddr, char *name,
													  int index, mDNSs32 utc, void *link))
{
	RelayLink *lp;
	mDNSAddr mask;

	for (lp = linksAvailable; lp; lp = lp->next) {
		if (lp->family == link_family_ipv4) {
			mask.type = mDNSAddrType_IPv4;
			prefixToMask(lp->preflen, sizeof mask.ip.v4.b, mask.ip.v4.b);
		} else if (lp->family == link_family_ipv6) {
			mask.type = mDNSAddrType_IPv4;
			prefixToMask(lp->preflen, sizeof mask.ip.v6.b, mask.ip.v6.b);
		} else {
			assert(0);	// This is a programming error.
		}
		ifsetup(m, &lp->prefix, &mask, NULL, lp->name, lp->ifix, utc, lp);
	}
}

// Called by mDNSResponder to send an mDNSMessage via a discovery relay.   The relay through which the message will be sent is not known
// to the mDNSResponder layer--mDNSResponder just specifies a link, which is a pointer we provided in rciEnumerateInterfaces.
mDNSexport mStatus rciSendMessage(const void *const msg, const mDNSu8 *const end, void *linkv)
{
	RelayLink *link = linkv;
	DSOMessage state;
	size_t messageLen;
    mDNSu8 *start = (mDNSu8 *)msg;
	DiscoveryRelayState *relay;
	DSOState *dso;
	mStatus status;

	relay = link->relay;
	dso = relay->dso;

	messageLen = end - start;
	// The actual thing we need to avoid is having messageLen be too big to represent in
	// sixteen bits; AbsoluteMaxDNSMessageData is quite a bit smaller than that, and is as
	// big as a DNS message we receive should ever get.
	assert(messageLen < (AbsoluteMaxDNSMessageData + sizeof (DNSMessageHeader)));

	status = DSOMakeMessage(&state, dso, mDNStrue, NULL);
	if (status != mStatus_NoError) {
		LogMsg("rciSendMessage: unable to make the message: %d", status);
		return status;
	}

	// Primary TLV is mDNSMessage
	DSOStartTLV(&state, kDSO_Type_mDNSMessage);
	DSOAddTLVBytesNoCopy(&state, start, messageLen);
	DSOFinishTLV(&state);
	
	// Add link identifier TLV for the destination link
	DSOStartTLV(&state, kDSO_Type_LinkIdentifier);
	DSOAddTLVByte(&state, link->family);
	DSOAddTLVu32(&state, link->linkID);
	DSOFinishTLV(&state);

	// Send this message to the relay; drop it if the output buffer is above the low water mark.
	(void)DSOMessageWrite(relay->dso, &state, mDNSfalse);
	// We aren't actually checking the status here, so it's conceivable that our write failed
	// and the connection is no more.   This should be handled through the process of deleting the
	// interface
	return mStatus_NoError;
}

mDNSexport mDNSs32 rciIdle(mDNS *const m, mDNSs32 nextTimerEvent)
{
	mDNSs32 timeoutNeeded = nextTimerEvent;
	mDNSs32 now = mDNS_TimeNow(m);
	DiscoveryRelayConnectState *drc;

	// Loop through the list of configured relays, checking to see if any of them need
	// reconnection; if we encounter a relay that needs reconnection sooner than the
	// nextTimerEvent value we got from the caller, note the earlier event time needed.
	for (drc = configuredConnectStates; drc; drc = drc->next) {
		if (drc->reconnectTime <= now) {
			if (drc->needsReconnect == mDNStrue) {
				drc->needsReconnect = mDNSfalse;
				
				if (!drConnect(drc)) {
					// Try again later.
					drc->reconnectTime = now + 30000;
					drc->needsReconnect = mDNStrue;
				}
            }
        }
        if (drc->needsReconnect) {
			LogMsg("rciIdle: drc->reconnectTime = %d  timeoutNeeded = %d", drc->reconnectTime, timeoutNeeded);
			if (drc->reconnectTime > now && drc->reconnectTime < timeoutNeeded) {
				timeoutNeeded = drc->reconnectTime;
			}
		}
	}
	return DSOIdle(timeoutNeeded);
}

// drFinalize is called by cleanupStaleDiscoveryProxies, which is only ever called when one of the IO event loop
// callbacks exits or in rciIdle.   Therefore, the big lock can be assumed to not be held by this thread.
mDNSlocal void drFinalize(DiscoveryRelayState *dr)
{
	RelayLink **lpp = &linksAvailable;
	mDNSBool interfacesChanged = mDNSfalse;
	DiscoveryRelayConnectState *drc;

	// For any links managed by this relay, either switch to a different relay or mark the link unavailable.
	while (*lpp) {
		if ((*lpp)->relay == dr) {
			ExtraRelay *xr = (*lpp)->extras;
			if (xr) {
				(*lpp)->relay = xr->relay;
				(*lpp)->extras = xr->next;
				free(xr);
			} else {
				RelayLink *lp = *lpp;
				*lpp = lp->next;
				lp->next = linksUnavailable;
				linksUnavailable = lp;
				interfacesChanged = mDNStrue;
				continue;
			}
		}
		lpp = &(*lpp)->next;
	}

	for (drc = configuredConnectStates; drc; drc = drc->next) {
		if (drc->relay == dr) {
			drc->reconnectTime = mDNS_TimeNow(drc->context) + 30 * mDNSPlatformOneSecond;
			drc->needsReconnect = mDNStrue;
			break;
		}
	}
	if (drc == NULL) {
		LogMsg("drFinalize: called on a relay that has no remembered connect state: %s", dr->dso->remoteName);
	}

	// Notify the interface code that the interface list has changed.
	if (interfacesChanged) {
		mDNSPlatformRefreshInterfaceList(dr->context);
	}
	free(dr);
}

// called when a DNS Message comes in from a discovery relay
mDNSexport void drReceivedMDNSMessage(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family,
									  mDNSAddr *sourceAddress, mDNSu16 sourcePort, mDNSu8 *message, size_t length)
{
	RelayLink *lp;
	mDNSInterfaceID InterfaceID;
	mDNSIPPort sPort;

	// Deliver the message.
	// Make sure that the interface is on the active list before delivering.

	for (lp = linksAvailable; lp; lp = lp->next) {
		if (lp->family == family && lp->linkID == linkID) {
			break;
		}
	}

	// If the link on which we received this message is not on the active list, that's kind of weird.
	// XXX think about whether this ought to be documented as a protocol error, or treated as an indication
	// XXX that the link is now active (I don't think so) or just ignored.
	if (!lp)
		return;

	
	// Make sure that some relay other than the one that we've chosen to relay for this link didn't send
	// this message; if it did, drop it.   I don't think this is a protocol error, because it could conceivably
	// happen during a reconfiguration, but there is a potential for an evil relay attack here.
	if (lp->relay != dr) {
		return;
	}

	// Get the interface ID (XXX storing a pointer would be faster, but involve more careful bookkeeping)
	InterfaceID = mDNSPlatformInterfaceIDfromInterfaceIndex(dr->context, lp->ifix);

	sPort.b[0] = sourcePort >> 8;
	sPort.b[1] = sourcePort & 255;
	
	// mDNSPosix increments a bunch of counters that we aren't incrementing here.  Should we call through
	// the platform layer to make that happen?
	mDNSCoreReceive(dr->context, (DNSMessage *)message, message + length, sourceAddress, sPort,
					(lp->family == link_family_ipv4 ? &AllDNSLinkGroup_v4 : &AllDNSLinkGroup_v6), MulticastDNSPort, InterfaceID);
}

mDNSexport void drLinkAvailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family,
								mDNSAddr *prefix, int preflen)
{
	RelayLink *link;
	ExtraRelay *xr;
	mDNSBool prefChanged = mDNSfalse;

	// See if we already have this link...
	for (link = linksAvailable; link; link = link->next) {
		if (link->linkID == linkID && link->family == family) {
			if (link->preflen != preflen || !maskEqual(preflen, prefix->ip.v6.b, link->prefix.ip.v6.b)) {
				prefChanged = mDNStrue;
				break;
			}
			// If another relay is also reporting this link, we need to record that this relay has it available
			// so that if we lose the other relay, we can switch to this one.   XXX right?
			for (xr = link->extras; xr; xr = xr->next) {
				if (xr->relay == dr)
					break;
			}
			if (!xr) {
				xr = malloc(sizeof *xr);
				memset(xr, 0, sizeof *xr);
				xr->next = link->extras;
				link->extras = xr;
				xr->relay = dr;
			}
			return;
		}
	}

	// Otherwise see if we've already seen it.
	if (!link) {
		RelayLink **lpp = &linksUnavailable;
		while (*lpp) {
			if ((*lpp)->linkID == linkID && (*lpp)->family == family) {
				// If we recognize it, move it to the list of available links.
				link = *lpp;
				*lpp = link->next;
				link->next = linksAvailable;
				linksAvailable = link;
				link->relay = dr;
				break;
			}
			lpp = &(*lpp)->next;
		}
	}

	// If we didn't match anything, we haven't seen this link before, so allocate a new data structure.
	if (!link) {
		// Add this interface to the list of available interfaces and call the "we have a new interface" entry point.
		int lnsize = strlen(dr->dso->remoteName) + 8;
		link = malloc((sizeof *link) + lnsize);
		memset(link, 0, sizeof *link);
		
#define LNARGS "%s-%4xv%s", dr->dso->remoteName, linkID, family == link_family_ipv4 ? "4" : "6"
		if (!link) {
			LogMsg("drLinkAvailable: no memory to add link " LNARGS);
			return;
		}

		link->relay = dr;
		link->ifix = ifi_base++;	// Each new link seen gets an index, which is never reused.
		link->name = (char *)(link + 1);
		snprintf(link->name, lnsize, LNARGS);
		link->linkID = linkID;
		link->family = family;
		link->next = linksAvailable;
		linksAvailable = link;
	}	

	memcpy(&link->prefix, prefix, sizeof *prefix);
	link->preflen = preflen;

	(void)prefChanged;
	// Right now the platform code doesn't have a way to be called when the prefix changed, so we
	// just have to kill and restore the interface, but it would be nice to have that finesse; if we
	// did, we could use prefChanged something like this:
	//if (prefChanged) {
	//	mDNSPlatformPrefixChanged(...);
	//} else {

	// Another nit here: in the posix code, when we connect to a new relay and it enumerates its interfaces,
	// we are going to re-scan the interface list N times, where N is the number of interfaces the relay
	// announces.  That's probably not going to cause any harm, but it might be a bit annoying, and it's not
	// behavior that would normally be seen, so it might break something.  In the long run, the Posix code
	// should do what the OSX code does anyway, and that may be a better way to address this than some
	// optimization of this side of the process.  Ideally, a new interface showing up should just add a new
	// interface to the interface list, the way we are doing here, and there shouldn't even be a need for
	// parallel structures.  The parallel structures at this layer are actually a hack to emulate the fact
	// that the posix code relies on the kernel keeping its own list of interfaces that can be enumerated
	// when rebuilding the interface list.
	//
	// Also, should file a radar bug and change mDNSPlatformPosixRefreshInterfaceList() to
	// mDNSPosixRefreshInterfaceList, since this isn't a cross-platform entry point.
	mDNSPlatformRefreshInterfaceList(dr->context);
    //}
	drRequestLink(dr, linkID, family);	
}

mDNSexport void drLinkUnavailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family)
{
	RelayLink **lpp = &linksAvailable;
	RelayLink *lp;

	while (*lpp) {
		if ((*lpp)->linkID == linkID && (*lpp)->family == family) {
			// If this relay is not the relay we're using for this link, it's no problem, but we need to
			// remove this relay from the link of other relays that support this link just in case the
			// current relay goes down or reports the link unavailable.
			if ((*lpp)->relay != dr) {
				ExtraRelay **xrp = &(*lpp)->extras;
				while (*xrp) {
					ExtraRelay *xr = *xrp;
					if (xr->relay == dr) {
						*xrp = xr->next;
						free(xr);
						return;
					}
					xrp = &(*xrp)->next;
					// It wasn't listed as an extra or as the current relay for this link.
					// XXX drop as protocol error?
					return;
				}
			} else {
				// If we have another relay providing service on this link, switch to that--no need for a
				// notification.
				ExtraRelay *xr = (*lpp)->extras;
				if (xr) {
					(*lpp)->relay = xr->relay;
					(*lpp)->extras = xr->next;
					free(xr);
					return;
				}
				break;
			}
			lpp = &(*lpp)->next;
		}
	}
	
	// This link was not found.
	if (*lpp == NULL) {
		// XXX drop as protocol error?
		return;
	}

	// Move this interface to the list of unavailable interfaces and call the "interface went away" entry point.
	lp = *lpp;
	*lpp = lp->next;
	lp->next = linksUnavailable;
	linksUnavailable = lp;

	mDNSPlatformRefreshInterfaceList(dr->context);
}

// Config file link mapping specification
mDNSlocal mDNSBool cfRelayHandler(void *context, const char *cfName, char **hunks, int numHunks, int lineno)
{
	char *eop;
	DiscoveryRelayConnectState *drc;
	int port = -1;
	char detail[64];
	
	(void)cfName;

	// Format: proxy <host-referent> <port>
	// host-referent can be an IP address or a name
	if (numHunks < 2) {
		LogMsg("cfRelayHandler: no host referent at line %d", hunks[2], lineno);
		return mDNSfalse;
	}

	// Parse the port (port may be provided by getaddrinfo, so it's not an error if it's not specified).
	if (numHunks == 3) {
		port = strtol(hunks[2], &eop, 10);
		if (eop == hunks[2] || *eop != '\0') {
			LogMsg("cfRelayHandler: invalid port number %s at line %d", hunks[2], lineno);
			return mDNSfalse;
		}
	}

	snprintf(detail, sizeof detail, "cfRelayHandler line %d", lineno);

	drc = drConnectStateCreate(context, hunks[1], port, 10, AbsoluteMaxDNSMessageData, 256, detail, drFinalize);
	if (drc == NULL) {
		return mDNSfalse;
	}
	drc->next = configuredConnectStates;
	configuredConnectStates = drc;
	drc->needsReconnect = mDNSfalse;
	return drConnect(drc);
}

mDNSexport DiscoveryRelayState *drConnected(void *context, DSOState *dso, mDNSBool connected)
{
	DiscoveryRelayConnectState *drc = context;
	DiscoveryRelayState *dr;

	if (!connected) {
	notConnected:
		drc->reconnectTime = mDNS_TimeNow(drc->context) + 30000; // XXX is this the right default?
		drc->needsReconnect = mDNStrue;
		return NULL;
	}

	dr = drCreate(drc->context, dso, drc->finalize);
	if (dr == NULL) {
		goto notConnected; // caller will clean up DSO object.
	}
	drc->needsReconnect = mDNSfalse;
	drc->relay = dr;
	
	// Request interface notifications.
	drRequestLinkNotifications(dr);
	return dr;
}

ConfigFileVerb cfVerbs[] = {
	{ "relay", 3, 4, cfRelayHandler }
};
#define NUMCFVERBS ((sizeof cfVerbs) / sizeof (ConfigFileVerb))

mDNSexport void rciInit(mDNS *const m)
{
	cfParse(m, "/etc/mdnsrelayclient.cf", cfVerbs, NUMCFVERBS);
}
