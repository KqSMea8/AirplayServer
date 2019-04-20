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
#include "DSO.h"
#include "RelayProtocol.h"
#include "RelayInterface.h"

//*************************************************************************************************************
// Types and structures

// DSO message, primary TLV is mDNS Message
mDNSlocal void mDNSMessage(DiscoveryRelayState *dr, DSOState *dso)
{
	mDNSu32 linkID = 0;
	LinkFamily family = 0;
	mDNSAddr IPSource;
	mDNSu16 IPSourcePort = 0;
	int i;
	mDNSBool gotIPSourceAddress = mDNSfalse, gotLinkIdentifier = mDNSfalse;

	memset(&IPSource, 0, sizeof IPSource);

	for (i = 0; i < dso->numAdditls; i++) {
		switch(dso->additl[i].opcode) {
		case kDSO_Type_LinkIdentifier:
			if (dso->additl[i].length != 5) {
				LogMsg("TestRelay: mDNSMessage: link identifier length is bad: %d", dso->additl[i].length);
				DSODrop(dso);
				return;
			}
			family = dso->additl[i].payload[0];
			linkID = (((mDNSu32)dso->additl[i].payload[1] << 24) | ((mDNSu32)dso->additl[i].payload[2] << 16) |
					  ((mDNSu32)dso->additl[i].payload[3] << 8) | dso->additl[i].payload[4]);
			gotLinkIdentifier = mDNStrue;
			break;
		case kDSO_Type_IPSourceAddress:
			IPSourcePort = (((mDNSu16)dso->additl[i].payload[0]) << 8) | dso->additl[i].payload[1];
			if (dso->additl[i].length == 6) {
				IPSource.type = mDNSAddrType_IPv4;
				memcpy(&IPSource.ip.v4, &dso->additl[i].payload[2], 4);
			} else if (dso->additl[i].length == 18) {
				IPSource.type = mDNSAddrType_IPv6;
				memcpy(&IPSource.ip.v6, &dso->additl[i].payload[2], 16);
			} else {
				LogInfo("TestRelay: mDNSMessage: unknown source address length: %d", dso->additl[i].length);
				// not fatal
				return;
			}
			gotIPSourceAddress = mDNStrue;
			break;
		default:
			LogInfo("TestRelay: mDNSMessage: unexpected TLV, opcode %d", dso->additl[i].opcode);
			return;
		}
	}

	if (gotIPSourceAddress && gotLinkIdentifier) {
		LogInfo("Received a %d byte mDNSMessage DSO message on link %x/%d from %s",
				dso->primary.length, linkID, family, dso->remoteName);
		drReceivedMDNSMessage(dr, linkID, family, &IPSource, IPSourcePort,
							  dso->primary.payload, dso->primary.length);
	} else {
		if (gotLinkIdentifier) {
			LogInfo("Received a %d byte mDNSMessage DSO message on link %x/%d missing IP Source Address",
					dso->primary.length, linkID, family);
		} else if (gotIPSourceAddress) {
			LogInfo("Received a %d byte mDNSMessage DSO message missing Link Identifier from %s",
					dso->primary.length, dso->remoteName);
		} else {
			LogInfo("Received a %d byte mDNSMessage DSO message missing both IP Source address and Link Identifier",
					dso->primary.length);
		}
	}
}

mDNSexport void drRequestLink(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family)
{
	DSOState *dso = dr->dso;
	DSOMessage msg;

	if (DSOMakeMessage(&msg, dso, mDNSfalse, dr) != mStatus_NoError) {
		LogMsg("TestRelay: unable to craft a link request message.");
		DSODrop(dso);
		return;
	}
	
	DSOStartTLV(&msg, kDSO_Type_mDNSLinkRequest);
	DSOAddTLVByte(&msg, family);
	DSOAddTLVu32(&msg, linkID);
	DSOFinishTLV(&msg);
	(void)DSOMessageWrite(dso, &msg, mDNStrue);
}

mDNSlocal void linkAvailable(DiscoveryRelayState *dr, DSOState *dso)
{
	int i;
	mDNSAddr addr;
	mDNSu32 linkID = ((((mDNSu32)dso->primary.payload[1]) << 24) | (((mDNSu32)dso->primary.payload[2]) << 24) |
					  (((mDNSu32)dso->primary.payload[3]) << 8) | dso->primary.payload[4]);
	LinkFamily family = dso->primary.payload[0];
	DSOTLV *prefix = NULL;

	// Find the link prefix
	for (i = 0; i < dso->numAdditls; i++) {
		if (dso->additl[i].opcode == kDSO_Type_LinkPrefix) {
			prefix = &dso->additl[i];
		}
	}
				
	if (!prefix) {
		LogMsg("dsoLinkAvailable: fatal: Relay at %s sent Link Available, family %d id %d, no prefix",
			   &dso->remoteName, family, linkID);
		return;
	}

	if (prefix->length == 5) {
		if (family != link_family_ipv4) {
		badLength:
			LogMsg("dsoLinkAvailable: fatal: Relay at %s sent Link Available, linkID %u, family %d prefix address length %d",
				   dso->remoteName, linkID, family, prefix->length);
			DSODrop(dso);
			return;
		}
		addr.type = mDNSAddrType_IPv4;
		memcpy(&addr.ip.v4, &prefix->payload[1], sizeof addr.ip.v4);
	} else if (prefix->length == 17) {
		if (family != link_family_ipv6) {
			goto badLength;
		}
		addr.type = mDNSAddrType_IPv6;
		memcpy(&addr.ip.v6, &prefix->payload[1], sizeof addr.ip.v6);
	} else {
		goto badLength;
	}

	if (prefix) {
		LogMsg("dsoLinkAvailable: Relay at %s sent Link Available, family %d id %x, prefix %#a/%d",
			   dso->remoteName, family, linkID, &addr, prefix->payload[0]);
	}
	drLinkAvailable(dr, linkID, family, &addr, prefix->payload[0]);
}

mDNSlocal void linkUnavailable(DiscoveryRelayState *dr, DSOState *dso)
{
	mDNSu32 linkID = ((((mDNSu32)dso->primary.payload[1]) << 24) | (((mDNSu32)dso->primary.payload[2]) << 24) |
					  (((mDNSu32)dso->primary.payload[3]) << 8) | dso->primary.payload[4]);
	LinkFamily family = dso->primary.payload[0];
	LogMsg("dsoLinkUnavailable: Relay at %s sent Link Unavailable, linkID = %u family = %d",
		   dso->remoteName, linkID, family);
	drLinkUnavailable(dr, linkID, family);
}

mDNSexport void drMessage(DiscoveryRelayState *dr, DNSHeaderUnpacked *header, DSOState *dso)
{
	// Decide what to do with this message.
	switch(dso->primary.opcode) {
	case kDSO_Type_mDNSLinkRequest:
		LogMsg("dnsDispatch: Relay at %s sent Link Request, which is invalid", dso->remoteName);
		DSOSendNotImplemented(dso);	// We don't support
		break;
		
	case kDSO_Type_mDNSLinkDiscontinue:
		LogMsg("dnsDispatch: Relay at %s sent Link Discontinue, which is invalid", dso->remoteName);
		DSOSendNotImplemented(dso);
		break;
		
	case kDSO_Type_mDNSMessage:
		mDNSMessage(dr, dso);
		break;
		
	case kDSO_Type_mDNSReportLinkChanges:
		LogMsg("dnsDispatch: Relay at %s sent Report Link Changes, which is invalid", dso->remoteName);
		DSOSendNotImplemented(dso);
		break;
		
	case kDSO_Type_mDNSStopLinkChanges:
		LogMsg("dnsDispatch: Relay at %s sent Stop Link Changes, which is invalid", dso->remoteName);
		DSOSendNotImplemented(dso);
		break;
		
	case kDSO_Type_mDNSLinkAvailable:
		linkAvailable(dr, dso);
		break;

	case kDSO_Type_mDNSLinkUnavailable:
		linkUnavailable(dr, dso);
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

mDNSexport void drRequestLinkNotifications(DiscoveryRelayState *dr)
{
	DSOMessage msg;
	DSOState *dso = dr->dso;
	
	if (DSOMakeMessage(&msg, dso, mDNSfalse, dr) != mStatus_NoError) {
		LogMsg("TestRelay: unable to craft a Report Link Change message.");
		DSODrop(dso);
		return;
	}
	
	DSOStartTLV(&msg, kDSO_Type_mDNSReportLinkChanges);
	DSOFinishTLV(&msg);
	(void)DSOMessageWrite(dso, &msg, mDNStrue);
}

mDNSexport mDNSBool drConnect(DiscoveryRelayConnectState *drc)
{
	// XXX how does dr have a DSO?
	return DSOConnect(drc->connectState);
}

mDNSexport void drResponse(void *context, DNSHeaderUnpacked *header, DSOState *dso)
{
	DiscoveryRelayState *dr = context;
	
	LogMsg("drResponse: state %d, id %x, rcode %d", dr->testState, header->id, header->rcode);
	if (header->rcode != kDNSFlag1_RC_NoErr) {
		DSODrop(dso);
		return;
	}
}
