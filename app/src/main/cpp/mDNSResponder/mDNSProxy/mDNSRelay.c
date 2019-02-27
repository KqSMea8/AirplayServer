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

#include <stdio.h>          // For printf()
#include <stdlib.h>         // For malloc()
#include <string.h>         // For strrchr(), strcmp()
#include <time.h>           // For "struct tm" etc.
#include <sys/time.h>       // For gettimeofday()
#include <signal.h>         // For SIGINT, SIGTERM
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "mDNSPosix.h"
#include "cfParse.h"

//*************************************************************************************************************
// Types and structures

#include "DSO.h"
#include "RelayProtocol.h"

// Link info: maps a link identifier to an interface index.  It's
// possible for more than one interface to be on the same link.
// XXX How does mDNSResponder currently deal with that situation?
// XXX links and interfaces are two different things; treat them as two different things.
typedef struct linkinfo {
	struct linkinfo *next;
	LinkFamily family;
	mDNSu32 linkID;
	mDNSu32 ifix;
	mDNSAddr prefix;
	int preflen;
	DiscoveryRelayState **clients;
	int numClients, maxClients;
	mDNSBool down;
	// Must be last!!
	char name[1];
} LinkInfo;

typedef struct link_match {
	struct link_match *next;
	mDNSu32 linkID;		// Interface index
	enum matchType { match_ifname, match_ipv4, match_ipv6 } type;
	union {
		struct {
			LinkFamily family;
			char name[1];
		} ifname;
		struct {
			int len;
			union {
				struct in_addr v4;
				struct in6_addr v6;
			} ia;
		} prefix;
	} match;
} LinkMatch;

//*************************************************************************************************************
// Globals

const char ProgramName[] = "mdnsrelayd";

static void *listenContext;
static int foreground;
static int debugging;
static LinkInfo *links;
static LinkMatch *linkMatches;

static DiscoveryRelayState **linkSubscribers;
static int numLinkSubscribers, maxLinkSubscribers;

// When a DiscoveryRelayState connection goes away, clean up everything that references it
// Currently that's just links.
mDNSlocal void drFinalize(DiscoveryRelayState *dr)
{
	LinkInfo *li;
	int i;
	for (li = links; li; li = li->next) {
		mDNSBool copydown = mDNSfalse;
		for (i = 0; i < li->numClients; i++) {
			if (li->clients[i] == dr) {
				copydown = mDNStrue;
			}
			if (copydown && i + 1 < li->numClients) {
				li->clients[i] = li->clients[i + 1];
			}
		}
		if (copydown) {
			li->numClients--;
		}
	}
	for (i = 0; i < numLinkSubscribers; i++) {
		mDNSBool copydown = mDNSfalse;
		if (linkSubscribers[i] == dr) {
			copydown = mDNStrue;
		}
		if (copydown && i + 1 < numLinkSubscribers) {
			linkSubscribers[i] = linkSubscribers[i + 1];
		}
		if (copydown) {
			numLinkSubscribers--;
		}
	}
	free(dr);
}

// Config file link mapping specification
mDNSlocal mDNSBool cfLinkHandler(void *context, const char *cfName, char **hunks, int numHunks, int lineno)
{
	char *eop;
	mDNSu32 linkID;
	struct in_addr ia;
	struct in6_addr ia6;
	char *slash;
	int preflen;
	LinkMatch *match;
	

	(void)cfName;
	(void)context;

	// Parse the link ID
	linkID = strtoul(hunks[1], &eop, 16);
	if (*eop) {
		LogMsg("cfLinkHandler: %s is not a valid hexadecimal number at line %d", hunks[1], lineno);
		return mDNSfalse;
	}

	// Figure out if the link match expression is an interface name, an IPv4 prefix or an IPv6 prefix.
	slash = strchr(hunks[2], '/');
	if (slash != NULL) {
		if (numHunks != 3) {
			LogMsg("cfLinkHandler: extra data (%s) at line %d", hunks[2], lineno);
			return mDNSfalse;
		}
		preflen = strtol(slash + 1, &eop, 10);
		if (eop == slash + 1 || *eop != 0) {
			LogMsg("cfLinkHandler: invalid prefix length: %s at line %d", hunks[2], lineno);
			return mDNSfalse;
		}
		*slash = 0;
		if (inet_pton(AF_INET, hunks[2], &ia)) {
			if (preflen < 0 || preflen > 32) {
				LogMsg("cfLinkHandler: invalid IPv4 prefix length %d at line %d", preflen, lineno);
				return mDNSfalse;
			}
			match = malloc(sizeof *match);
			if (match == NULL) {
			oom:
				LogMsg("cfLinkHandler: out of memory");
				return mDNSfalse;
			}
			match->type = match_ipv4;
			match->match.prefix.ia.v4 = ia;
		} else if (inet_pton(AF_INET6, hunks[2], &ia6)) {
			if (preflen < 0 || preflen > 128)
			{
				LogMsg("cfLinkHandler: invalid IPv6 prefix length %d at line %d", preflen, lineno);
				return mDNSfalse;
			}
			match = malloc(sizeof *match);
			if (match == NULL)
				goto oom;
			match->type = match_ipv6;
			match->match.prefix.ia.v6 = ia6;
		} else {
			LogMsg("cfLinkHandler: invalid IP address: %s at line %d", hunks[2], lineno);
			return mDNSfalse;
		}
		match->match.prefix.len = preflen;
	} else {
		LinkFamily family;
		if (numHunks != 4) {
			LogMsg("cfLinkHandler: address family not specified at line %d", hunks[2], lineno);
			return mDNSfalse;
		}

		// Figure out the family
		if (!strcmp(hunks[2], "ipv4")) {
			family = link_family_ipv4;
		} else if (!strcmp(hunks[2], "ipv6")) {
			family = link_family_ipv6;
		} else {
			LogMsg("cfLinkHandler: unrecognized address family %s at line %d", hunks[2], lineno);
			return mDNSfalse;
		}

		// We're just going to assume that the hunk contains an interface name.
		match = malloc((sizeof *match) - (sizeof match->match) + sizeof match->match.ifname + strlen(hunks[3]));
		if (match == NULL)
			goto oom;
		strcpy(match->match.ifname.name, hunks[3]);
		match->type = match_ifname;
		match->match.ifname.family = family;
	}
	match->linkID = linkID;
	match->next = linkMatches;
	linkMatches = match;
	return mDNStrue;
}

ConfigFileVerb cfVerbs[] = {
	{ "link", 3, 4, cfLinkHandler }
};
#define NUMCFVERBS ((sizeof cfVerbs) / sizeof (ConfigFileVerb))

mDNSexport void mDNSCoreReceive(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end,
                                const mDNSAddr *srcaddr, mDNSIPPort srcport, const mDNSAddr *dstaddr,
								mDNSIPPort dstport, const mDNSInterfaceID InterfaceID)
{
	LinkInfo *li;
	int i;
	DSOMessage state;
	DSOState *dso = NULL;
	
	size_t messageLen;

    (void)dstaddr;  // Unused
    (void)dstport;  // Unused
	(void)m; // Unused
	(void)dstaddr;
	(void)dstport;

    mDNSu8 *start = (mDNSu8 *)msg;
	mDNSu32 ifix;

	// Validate that the packet we've received is a multicast packet and (important!) not a query.
	// The Relay Protocol isn't meant to support queries over mDNS.
	if ((msg->h.flags.b[0] & kDNSFlag0_QR_Mask) != kDNSFlag0_QR_Response)
		return;
	// IPv4 and not multicast.
	if (dstaddr->type == mDNSAddrType_IPv4 && memcmp(dstaddr->ip.v4.b, AllDNSLinkGroup_v4.ip.v4.b, 4))
		return;
	// IPv6 and not multicast.
	if (dstaddr->type == mDNSAddrType_IPv6 && memcmp(dstaddr->ip.v6.b, AllDNSLinkGroup_v6.ip.v6.b, 16))
		return;

	ifix = mDNSPlatformInterfaceIndexfromInterfaceID(m, InterfaceID, mDNSfalse);

	// This should never happen, since we received a message from this interface.
	if (ifix == 0) {
		LogMsg("mDNSCoreReceive: called with an invalid interface.");
		return;
	}

	messageLen = end - start;
	// The actual thing we need to avoid is having messageLen be too big to represent in
	// sixteen bits; AbsoluteMaxDNSMessageData is quite a bit smaller than that, and is as
	// big as a DNS message we receive should ever get.
	assert(messageLen < (AbsoluteMaxDNSMessageData + sizeof (DNSMessageHeader)));

	// Find the link on which this message arrived.
	for (li = links; li; li = li->next) {
		// We should never receive a message on an unfindable interface.
		if (li->ifix == ifix &&
			((li->family == link_family_ipv4 && srcaddr->type == mDNSAddrType_IPv4) ||
			 (li->family == link_family_ipv6 && srcaddr->type == mDNSAddrType_IPv6)))
			break;
	}
	if (li == NULL) {
		LogMsg("mDNSCoreReceive: received a message for an unrecognized interface (%d).", ifix);
		return;
	}
	
	// Forward this message to every client that's subscribed to this link.
	for (i = 0; i < li->numClients; i++) {
		// We construct the message in the output buffer of the first DSO.   If nobody's subscribed to
		// the link, we never get here and thus never do this work.
		if (dso == NULL) {
			dso = li->clients[i]->dso;

			DSOMakeMessage(&state, dso, mDNStrue, NULL);

			// Primary TLV is mDNSMessage
			DSOStartTLV(&state, kDSO_Type_mDNSMessage);
			DSOAddTLVBytesNoCopy(&state, start, messageLen);
			DSOFinishTLV(&state);
			
			// Also provide an IP Source TLV
			DSOStartTLV(&state, kDSO_Type_IPSourceAddress);
			DSOAddTLVBytes(&state, srcport.b, 2);
			if (srcaddr->type == mDNSAddrType_IPv4) {
				DSOAddTLVBytes(&state, srcaddr->ip.v4.b, sizeof srcaddr->ip.v4);
			} else {
				DSOAddTLVBytes(&state, srcaddr->ip.v6.b, sizeof srcaddr->ip.v6);
			}
			DSOFinishTLV(&state);

			// And a link identifier TLV.
			DSOStartTLV(&state, kDSO_Type_LinkIdentifier);
			DSOAddTLVByte(&state, li->family);
			DSOAddTLVu32(&state, li->linkID);
			DSOFinishTLV(&state);
		}

		(void)DSOMessageWrite(li->clients[i]->dso, &state, mDNSfalse);
		// It's possible that an error will occur here that will cause the DSO state to drop,
		// but the cleanup doesn't happen until we get back to the idle loop, so this should be
		// okay.
	}
}

// Realloc, but doesn't lose the chunk, and keeps everything up to date.
mDNSlocal mDNSBool makeBigger(void **hunks, size_t hunkSize, int *maxp, int increment)
{
	void *newHunks;
	int newMax;

	newMax = *maxp + increment;

	newHunks = malloc(newMax * hunkSize);
	if (newHunks == 0) {
		return mDNSfalse;
	}
	if (*maxp != 0) {
		memcpy(newHunks, *hunks, *maxp * hunkSize);
		free(*hunks);
	}
	memset((void *)((char *)newHunks + *maxp * hunkSize), 0, increment * hunkSize);
	*hunks = newHunks;
	*maxp = newMax;
	return mDNStrue;
}

// The Discovery Relay specification talks about links, not interfaces.  Generally interfaces are connected to
// links, and often there's a 1:1 correspondence, but this isn't necessarily the case.  For example, a host
// with an ethernet and a Wifi interface may be connected to a router that bridges Wifi and ethernet
// together, and may be connected to that Wifi and that ethernet.

// So we have a data structure for mapping from our configuration, which talks about links, to our
// interfaces.  This information is simply read from the static configuration, or provided by HNCP or some
// other orchestration protocol.

#if 0 // Not Yet
mDNSlocal mDNSInterfaceID mDNSPlatformInterfaceIDfromLinkID(mDNSu32 linkID)
{
	LinkInfo *link;
	for (link = links; link; link = link->next) {
		if (link->linkID == linkID) {
			// If more than one interface is attached to the same link, we are just going to return the
			// first match, which may not be the right thing to do.
			return mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, link->ifix);
		}
	}
	return 0;	// No such link.
}
#endif

// Find the subscription that matches an mDNS Link Request or mDNS Link Discontinue TLV.
// Calls to findRequestedLink must check the return status and if it's mDNSfalse, the dr
// object should be assumed to be dead and no more work should be done on it.   This doesn't
// mean it necessarily is dead, just that it must be assumed dead because it might be.
mDNSlocal mDNSBool findRequestedLink(DiscoveryRelayState *dr, DSOTLV *link,
									 mDNSBool (*inner)(DiscoveryRelayState *dr, LinkInfo *li, int index))
{
	mDNSu8 family;
	mDNSu32 linkID;
	int i;
	LinkInfo *li;

	// Identify the link being requested
	if (link->length != 5) {
		(void)DSOSendFormErr(dr->dso);
		return mDNSfalse;
	}
	family = link->payload[0];
	linkID = ((((mDNSu32)link->payload[1]) << 24) | (((mDNSu32)link->payload[2]) << 16) |
			  (((mDNSu32)link->payload[3]) << 8) | link->payload[4]);
		
	// See if we are already subscribed
	for (li = links; li; li = li->next) {
		if (li->family == family && li->linkID == linkID) {
			for (i = 0; i < li->numClients; i++) {
				if (li->clients[i] == dr) {
					return inner(dr, li, i);
				}
			}
			break;	// we exit the loop with li pointing to the right link
		}
	}
	return inner(dr, li, -1);
}

// DSO message, primary TLV is mDNS Link Request
mDNSlocal mDNSBool dsoLinkRequestInner(DiscoveryRelayState *dr, LinkInfo *li, int index)
{
	// If we get here and li is null, it means that we don't recognize the requested link.
	if (li == NULL) {
		(void)DSOSendNameError(dr->dso);
		return mDNSfalse;
	}

	// If index isn't -1, we're already subscribed to this link, so there is no work to do.
	if (index != -1) {
		(void)DSOSendNoError(dr->dso);
		return mDNStrue;
	}

	// Mark this DR as being subscribed to the link.
	if (li->numClients == li->maxClients || li->maxClients == 0) {
		// If there's no memory for the subscription, send SERVFAIL.
		if (!makeBigger((void **)&li->clients, sizeof li->clients, &li->maxClients, 10)) {
			(void)DSOSendServFail(dr->dso);
			return mDNSfalse;
		}
	}
	li->clients[li->numClients++] = dr;
	(void)DSOSendNoError(dr->dso);
	return mDNStrue;
}

mDNSlocal void linkRequest(DiscoveryRelayState *dr)
{
	findRequestedLink(dr, &dr->dso->primary, dsoLinkRequestInner);
}

// DSO message, primary TLV is mDNS Link Discontinue
mDNSlocal mDNSBool dsoLinkDiscontinueInner(DiscoveryRelayState *dr, LinkInfo *li, int index)
{
	int i;
	
	(void)dr; // unused
	
	// If we aren't subscribed to the link
	if (li == NULL || index == -1) {
		// Link Discontinue does not require a response, so if the client asks to discontinue
		// a link that was never requested, we do nothing.
		return mDNSfalse;

	// Otherwise, remove this discovery relay client from the list.
	} else {
		for (i = index; i + 1 < li->numClients; i++) {
			li->clients[i] = li->clients[i + 1];
		}
		li->clients[i] = 0;
	}

	// No need to indicate success either.
	return mDNStrue;
}

mDNSlocal void linkDiscontinue(DiscoveryRelayState *dr)
{
	findRequestedLink(dr, &dr->dso->primary, dsoLinkDiscontinueInner);
}

mDNSlocal mDNSBool dsoMDNSMessageInner(DiscoveryRelayState *dr, LinkInfo *li, int index)
{
	mDNSInterfaceID iid;
	mStatus status;
	DSOState *dso = dr->dso;

	(void)index; // unused
	
	// A named interface wasn't found.
	if (li == NULL) {
		return mDNStrue;
	}
	
	// Get the interface ID to use to DSOSend the message.
	iid = mDNSPlatformInterfaceIDfromInterfaceIndex(&mDNSStorage, li->ifix);
	if (iid == NULL) {
		// We've been asked to send a message on a link for which the interface doesn't exist.
		// If this happens it means that the Discovery Relay Client that we're talking to hasn't been
		// notified that we no longer provide service for this link.
		// XXX Discuss with Stuart: is this really the right design?
		return mDNStrue;
	}

	// Send the mDNS message.
	status = mDNSPlatformSendUDP(&mDNSStorage, dso->primary.payload, dso->primary.payload + dso->primary.length,
								 iid, mDNSNULL, (li->family == link_family_ipv4
												 ? &AllDNSLinkGroup_v4
												 : &AllDNSLinkGroup_v6), MulticastDNSPort, mDNSfalse);

	// mDNSPlatformSendUDP already logs a message if something goes wrong, so no action to take if status isn't
	// "success."
	(void)status;

	return mDNStrue;
}

// DSO message, primary TLV is mDNS Message
mDNSlocal void mDNSMessage(DiscoveryRelayState *dr)
{
	int i;
	DSOState *dso = dr->dso;
	
	// Find each of the links on which we're supposed to send this message.
	for (i = 0; i < dso->numAdditls; i++) {
		switch(dso->additl[i].opcode) {
		case kDSO_Type_LinkIdentifier:
			// We may be asked to send the message on more than one link.   If there
			// is an unrecoverable failure while sending the message, stop immediately.
			// It is assumed that if the failure can have been signaled, that will
			// have been done in dsoDNSMessageInner().
			if (!findRequestedLink(dr, &dso->additl[i], dsoMDNSMessageInner))
				return;
			break;

		default:	// We don't recognize this TLV, so we ignore it.
			break;
		}
	}
}

// Send a Link Available or Link Unavailable message to every Discovery Relay Client that is following
// link availability, or to a specific Discovery Relay Client (if client is not NULL).
mDNSlocal void sendLinkAvailability(DiscoveryRelayState *client, LinkInfo *li, mDNSBool available)
{
	DSOMessage state;
	DiscoveryRelayState *dr, **drp;
	int i, max;
	DSOState *dso = NULL;

	// We have a loop here in case we're sending notifications to all subscribers, but we also need
	// to be able to notify a single client that just subscribed.
	if (client != NULL) {
		drp = &client;
		max = 1;
	} else {
		drp = linkSubscribers;
		max = numLinkSubscribers;
	}
	
	// Cycle through the array (or through client, which we treat as an array of one element).
	for (i = 0; i < max; i++) {
		dr = drp[i];
		
		// Only construct the message once, in the output buffer of the first relay.
		if (dso == NULL) {
			dso = dr->dso;

			DSOMakeMessage(&state, dso, mDNStrue, NULL);

			// And a link identifier TLV.
			DSOStartTLV(&state, available ? kDSO_Type_mDNSLinkAvailable : kDSO_Type_mDNSLinkUnavailable);
			DSOAddTLVByte(&state, li->family);
			DSOAddTLVu32(&state, li->linkID);
			DSOFinishTLV(&state);

			// Provide a Link Prefix TLV if link is available.
			if (available) {
				DSOStartTLV(&state, kDSO_Type_LinkPrefix);
				if (li->prefix.type == mDNSAddrType_IPv4) {
					DSOAddTLVByte(&state, li->preflen);
					DSOAddTLVBytes(&state, li->prefix.ip.v4.b, sizeof li->prefix.ip.v4);
				} else {
					DSOAddTLVByte(&state, li->preflen);
					DSOAddTLVBytes(&state, li->prefix.ip.v6.b, sizeof li->prefix.ip.v6);
				}
				DSOFinishTLV(&state);
			}
		}

		// Send the link state message; disregard the low water mark.
		(void)DSOMessageWrite(dr->dso, &state, mDNStrue);
		LogMsg("sendLinkAvailability: reporting Link %s ID %x %#a/%d %s",
			   li->name, li->linkID, &li->prefix, li->preflen, available ? "available" : "gone");
		if (client != NULL) {
			break;
		}
	}
}

mDNSlocal void reportLinkChanges(DiscoveryRelayState *dr)
{
	LinkInfo *li;

	LogMsg("dsoReportLinkChanges: client %s sent Report Link Changes", dr->dso->remoteName);
	if (numLinkSubscribers == maxLinkSubscribers || maxLinkSubscribers == 0) {
		// If there's no memory for the subscription, send SERVFAIL.
		if (!makeBigger((void **)&linkSubscribers, sizeof linkSubscribers, &maxLinkSubscribers, 10)) {
			(void)DSOSendServFail(dr->dso);
			return;
		}
	}
	linkSubscribers[numLinkSubscribers++] = dr;
	(void)DSOSendNoError(dr->dso);

	// For now we are just going to send a Link Available for each link without checking whether
	// there's buffer space.  This is almost certainly safe for general purpose machines, but could
	// block on a small device.  The downside of blocking is that other relay work will pause until
	// all the link available messages have been written.  This is a small enough risk that I don't
	// think it's worth checking for writability.
	for (li = links; li; li = li->next) {
		// Report only on links that are not currently marked down.
		if (!li->down)
			sendLinkAvailability(dr, li, mDNStrue);
	}
}

mDNSlocal void stopLinkChanges(DiscoveryRelayState *dr)
{
	int i, j;
	LogMsg("stopLinkChanges: client %s sent Stop Reporting Link Changes", dr->dso->remoteName);

	// Sweep the relay out of the array.
	j = 0;
	for (i = 0; i < numLinkSubscribers; i++) {
		if (linkSubscribers[i] == dr) {
			continue;
		} else if (i != j) {
			linkSubscribers[j] = linkSubscribers[i];
		}
		j++;
	}
	if (i != j) {
		numLinkSubscribers--;
	} else {
		LogMsg("stopLinkChanges: relay %s was not following changes", dr->dso->remoteName);
		DSODrop(dr->dso);
	}
}

mDNSexport void drMessage(DiscoveryRelayState *dr, DNSHeaderUnpacked *header, DSOState *dso)
{
	// Decide what to do with this message.
	switch(dso->primary.opcode) {
	case kDSO_Type_mDNSLinkRequest:
		linkRequest(dr);
		break;
		
	case kDSO_Type_mDNSLinkDiscontinue:
		linkDiscontinue(dr);
		break;
		
	case kDSO_Type_mDNSMessage:
		mDNSMessage(dr);
		break;
		
	case kDSO_Type_mDNSReportLinkChanges:
		reportLinkChanges(dr);
		break;
		
	case kDSO_Type_mDNSStopLinkChanges:
		stopLinkChanges(dr);
		break;
		
	case kDSO_Type_mDNSLinkAvailable:
		LogMsg("drMessage: fatal: client %s sent Link Available", dr->dso->remoteName);
		DSODrop(dr->dso);
		break;

	case kDSO_Type_mDNSLinkUnavailable:
		LogMsg("drMessage: fatal: client %s sent Link Unavailable", dr->dso->remoteName);
		DSODrop(dr->dso);
		break;

	default:
		LogMsg("drDispatch: %s: unrecognized primary TLV (%d %d)",
			   dso->remoteName, dso->primary.opcode, dso->primary.length);

		// If we have a nonzero message ID, that means that this is an acknowledgment-requiring
		// primary, so return an error
		if (header->id != 0) {
			(void)DSOSendNotImplemented(dso);
			return;
		} else {
			// It's a programing error to send a non-acknowledgment-requiring DSO
			// message to a recipient that isn't known to support it, so we just
			// drop the connection at this point--the other end is crazy.
			// We NOT doing this when it's acknowledgment-requiring because it's /not/
			// an error for a DSO client to send an unrecognized acknowledgment-requiring
			// primary TLV.
			DSODrop(dso);
			return;
		}
	}
}

// The relay never sends messages that require responses, so in principle we should never get here.
// Since we match requests to responses, even if the client sends a bogus response, it shouldn't
// reach this far because it wouldn't match anything we sent.
mDNSexport void drResponse(void *context, DNSHeaderUnpacked *header, DSOState *dso)
{
	(void)context;
	(void)header;
	(void)dso;
	return;
}

mDNSexport DiscoveryRelayState *drConnected(void *context, DSOState *dso, mDNSBool connected)
{
	DiscoveryRelayListenState *dlc = context;
	DiscoveryRelayState *dr;

	// Shouldn't be possible.
	if (dlc == NULL || dso == NULL || !connected) {
		return NULL;
	}

	dr = drCreate(dlc->context, dso, dlc->finalize);
	if (dr == NULL) {
		LogMsg("mDNSRelay: drCreate returned NULL on connection from %s, dropping.", dso->remoteName);
		DSODrop(dso);
		return NULL;
	}
	return dr;
}

// Set up the initial server state and run the event loop.
mDNSlocal mStatus mDNSRelay(int port)
{
    sigset_t signals;
	mDNSBool gotSomething = mDNSfalse;
	// Set up mDNS listener/sender infrastructure
    mStatus status = mDNS_Init(&mDNSStorage, &PlatformStorage,
                               mDNS_Init_NoCache, mDNS_Init_ZeroCacheSize,
                               mDNS_Init_AdvertiseLocalAddresses,
                               mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
    if (status) {
		return(status);
	}

	listenContext = drListenStateCreate(&mDNSStorage, port, 1,
										AbsoluteMaxDNSMessageData, 256, "drListen", drFinalize);
	if (listenContext == NULL) {
		LogMsg("mDNSRelay: Unable to allocate memory for listen context.");
		return mStatus_NoMemoryErr;
	}
	status = drListen(listenContext);
	if (status != mStatus_NoError) {
		LogMsg("mDNSRelay: drListen returned failure: %d", status);
		return status;
	}

    gettimeofday(&tv_start, NULL);
	
    mDNSPosixListenForSignalInEventLoop(SIGINT);
    mDNSPosixListenForSignalInEventLoop(SIGTERM);

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

        mDNSPosixRunEventLoopOnce(&mDNSStorage, &timeout, &signals, &gotSomething);
    } while (!(sigismember(&signals, SIGINT) || sigismember(&signals, SIGTERM)));

    return(0);
}

mDNSexport int main(int argc, char **argv)
{
    const char *progname = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
    int i;
    mStatus status;
	const char *cfName = "/etc/mdnsrelay.cf";
	int port;

    setlinebuf(stdout);             // Want to see lines as they appear, not block buffered

    for (i=1; i<argc; i++) {
		if (i+1 < argc && !strcmp(argv[i], "-c")) {
			cfName = argv[i + 1];
			i++;
		}
		else if (i+1 < argc && !strcmp(argv[i], "-p")) {
			char *sp;
			port = strtol(argv[i + 1], &sp, 10);
			if (*sp != '\0' || port < 1 || port > 65535) {
				fprintf(stderr, "%s: invalid port number\n", argv[i + 1]);
				goto usage;
			}
			i++;
		} else if (!strcmp(argv[i], "-f")) {
			foreground = 1;
        } else if (!strcmp(argv[i], "-d")) {
			mDNS_DebugMode = mDNStrue;
			debugging = 1;
        } else {
			goto usage;
		}
    }

	// Parse the config file, fail if it doesn't parse or isn't there.
	if (!cfParse(NULL, cfName, cfVerbs, NUMCFVERBS)) {
		return -1;
	}

	mDNS_LoggingEnabled = 1;
    status = mDNSRelay(port);
    fprintf(stderr, "%s: mDNSRelay failed %d\n", progname, (int)status);
	return status;

usage:
    fprintf(stderr, "\nmDNS Discovery Relay\n");
	fprintf(stderr, "%s", argv[0]);
	for (i = 1; i < argc; i++)
		fprintf(stderr, " %s", argv[i]);
	fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-d] [-f] [-c <config filename>]\n", progname);
    fprintf(stderr, "Optional -p <port> parameter causes the relay to bind to the specified port\n");
    fprintf(stderr, "Optional -d parameter causes the relay to print debugging status information\n");
    fprintf(stderr, "Optional -f parameter causes the relay to run in the foreground\n");
    fprintf(stderr, "Optional -c <config filename> parameter causes the relay to get configuration\n");
    fprintf(stderr, "                              from the named file instead of /etc/mdnsrelayd.cf\n");

    fprintf(stderr, "\n");
    return(-1);
}

mDNSlocal LinkMatch *matchInterface(NetworkInterfaceInfo *set)
{
	LinkMatch *match;

	// Make a LinkInfo structure for this interface if we don't already have one.
	for (match = linkMatches; match; match = match->next) {
		switch(match->type) {
		case match_ifname:
			if (!strcmp(set->ifname, match->match.ifname.name) &&
				((match->match.ifname.family == link_family_ipv4 && set->ip.type == mDNSAddrType_IPv4) ||
				 (match->match.ifname.family == link_family_ipv6 && set->ip.type == mDNSAddrType_IPv6))) {
				return match;
			}
			break;
		case match_ipv4:
			if (set->ip.type == mDNSAddrType_IPv4 &&
				maskEqual(match->match.prefix.len, (mDNSu8 *)&match->match.prefix.ia.v4, set->ip.ip.v4.b)) {
				return match;
			}
			break;
		case match_ipv6:
			if (set->ip.type == mDNSAddrType_IPv6 &&
				maskEqual(match->match.prefix.len, (mDNSu8 *)&match->match.prefix.ia.v4, set->ip.ip.v6.b)) {
				return match;
			}
			break;
		}
	}
	return NULL;
}

mDNSexport mStatus mDNS_RegisterInterface(mDNS *const m, NetworkInterfaceInfo *set,
										  InterfaceActivationSpeed activationSpeed)
{
    (void)activationSpeed;
    NetworkInterfaceInfo **p = &m->HostInterfaces;

    if (!set->InterfaceID) {
		LogMsg("mDNS_RegisterInterface: Error! Called with a NetworkInterfaceInfo %#a with zero InterfaceID",
			   &set->ip);
		return(mStatus_Invalid);
	}

	
    if (!mDNSAddressIsValidNonZero(&set->mask)) {
		LogMsg("mDNS_RegisterInterface: Error! Called with a NetworkInterfaceInfo %#a with invalid mask %#a",
			   &set->ip, &set->mask);
		return(mStatus_Invalid);
	}

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

	// See if we have a link ID that matches this interface.
	LinkMatch *match = matchInterface(set);
	if (match != NULL) {
		LinkInfo *link;
		for (link = links; link; link = link->next) {
			if (link->linkID == match->linkID &&
				((link->family == link_family_ipv4 && set->ip.type == mDNSAddrType_IPv4) ||
				 (link->family == link_family_ipv6 && set->ip.type == mDNSAddrType_IPv6))) {
				break;
			}
		}

		// If we found a matching link ID but there's no LinkInfo structure for that link yet,
		// make one.
		if (link == NULL) {
			int ifix = mDNSPlatformInterfaceIndexfromInterfaceID(m, set->InterfaceID, mDNSfalse);
			if (ifix == 0) {
				LogInfo("mDNS_RegisterInterface: unable to get interface index for %s.", set->ifname);
			} else {
				link = malloc((sizeof *link) + strlen(set->ifname));
				if (link == NULL) {
					LogInfo("mDNS_RegisterInterface: no memory for LinkInfo.");
				} else {
					memset(link, 0, sizeof *link);
					link->preflen = maskToPrefix(&set->mask);
					if (set->ip.type == mDNSAddrType_IPv4) {
						link->family = link_family_ipv4;
						link->prefix.type = mDNSAddrType_IPv4;
						prefixCopy(link->preflen, sizeof link->prefix.ip.v4, link->prefix.ip.v4.b, set->ip.ip.v4.b);
					} else { 
						link->family = link_family_ipv6;
						link->prefix.type = mDNSAddrType_IPv6;
						prefixCopy(link->preflen, sizeof link->prefix.ip.v6, link->prefix.ip.v6.b, set->ip.ip.v6.b);
					}

					link->linkID = match->linkID;
					link->ifix = ifix;
					link->next = links;
					strcpy(link->name, set->ifname);
					links = link;

					LogInfo("mDNS_RegisterInterface: interface %s added at linkID %x/%d",
							set->ifname, link->linkID, link->family);
				}
			}
		} else {
			if (link->down) {
				LogInfo("mDNS_RegisterInterface: interface %s has come back up at linkID %x/%d",
						set->ifname, link->linkID, link->family);
				link->down = mDNSfalse;
				sendLinkAvailability(NULL, link, mDNStrue);
			} else {				
				LogInfo("mDNS_RegisterInterface: interface %s already listed at linkID %x/%d",
						set->ifname, link->linkID, link->family);
			}
		}
	} else {
		LogInfo("no match for interface %s", set->ifname);
	}
	
    LogInfo("mDNS_RegisterInterface: InterfaceID %p %s (%#a) %s",
            set->InterfaceID, set->ifname, &set->ip,
            set->InterfaceActive ?
            "not represented in list; marking active and retriggering queries" :
            "already represented in list; marking inactive for now");

    mDNS_Unlock(m);
	return mStatus_NoError;
}

mDNSexport void mDNS_DeregisterInterface(mDNS *const m, NetworkInterfaceInfo *set,
										 InterfaceActivationSpeed activationSpeed)
{
	LinkInfo *link;
    NetworkInterfaceInfo **p = &m->HostInterfaces;
	(void)activationSpeed;

	mDNS_Lock(m);

	mDNSu32 ifix = mDNSPlatformInterfaceIndexfromInterfaceID(m, set->InterfaceID, mDNSfalse);

	while (*p) {
		if (*p == set) {
			*p = set->next;
			set->next = NULL;
			break;
		}
	}

	for (link = links; link; link = link->next) {
		if (link->ifix == ifix &&
			((link->family == link_family_ipv4 && set->ip.type == mDNSAddrType_IPv4) ||
			 (link->family == link_family_ipv6 && set->ip.type == mDNSAddrType_IPv6))) {
			break;
		}
	}
	if (link) {
		link->down = mDNStrue;
		sendLinkAvailability(NULL, link, mDNSfalse);
	}

	mDNS_Unlock(m);
}
