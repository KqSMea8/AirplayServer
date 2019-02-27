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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h>
#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "DSO.h"
#include "RelayProtocol.h"

//*************************************************************************************************************
// Globals

// This function is called either when an error has occurred requiring the a discovery relay connection be
// dropped, or else when a discovery relay connection has been cleanly closed and is ready to be
// dropped for that reason.

mDNSlocal void drEventCallback(void *context, DNSHeaderUnpacked *header, DSOState *dso, DSOEventType eventType)
{
	DiscoveryRelayState *dr;
    DSOConnectState *dsoc;
	
	switch(eventType) {
	case kDSO_EventType_DNSMessage:
		// This is a protocol error
		LogMsg("drEventCallback: DNS Message (opcode=%d) received from %s", header->opcode, dso->remoteName);
		DSODrop(dso);
		break;
	case kDSO_EventType_DNSResponse:
		// This is a protocol error
		LogMsg("drEventCallback: DNS Response (opcode=%d) received from %s", header->opcode, dso->remoteName);
		DSODrop(dso);
		break;
	case kDSO_EventType_DSOMessage:
        dr = context;
		drMessage(dr, header, dso);
		break;
	case kDSO_EventType_Finalize:
        dr = context;
        if (dr->finalize) {
			dr->finalize(dr);
		}
		break;
	case kDSO_EventType_DSOResponse:
		// Here context is the context that was passed in to DSOMakeMessage, so if there's a need
		// to track individual responses, state can be placed there to manage that.
		drResponse(context, header, dso);
		break;

	case kDSO_EventType_Connected:
        dsoc = context;
		dr = drConnected(dsoc->context, dso, mDNStrue);
		if (dr) {
			DSOSetCallback(dso, dr, drEventCallback);
		} else {
			DSODrop(dso);
		}
		break;

	case kDSO_EventType_ConnectFailed:
        dsoc = context;
		(void)drConnected(dsoc->context, dso, mDNSfalse);
		break;
	}
}

// Create a DiscoveryRelayState structure
// If the finalize function is provided, it is responsible for freeing the DiscoveryRelayState object
// when it's done finalizing it.  It is also allowed to reuse it, for example to queue a later
// attempt to reconnect.   If dso is not NULL, numOutstandingQueries, bufsize, remoteName are ignored.
mDNSexport DiscoveryRelayState *drCreate(void *context, DSOState *dso, void (*finalize)(DiscoveryRelayState *dr))
{
	DiscoveryRelayState *dr;

	// We allocate everything in a single hunk so that we can free it together as well.
	dr = malloc(sizeof *dr);
	if (dr == NULL) {
		return NULL;
	}
	memset(dr, 0, sizeof *dr);
	dr->context = context;
	dr->finalize = finalize;
	dr->dso = dso;
	return dr;
}

mDNSlocal void drListenCallback(void *context, DNSHeaderUnpacked *header, DSOState *dso, DSOEventType eventType)
{
	DiscoveryRelayState *dr;
	DiscoveryRelayConnectState *drc = context;
	(void)header;
	
	switch(eventType) {
	case kDSO_EventType_Connected:
		dr = drConnected(drc, dso, mDNStrue);
		if (dr) {
			DSOSetCallback(dso, dr, drEventCallback);
		} else {
			DSODrop(dso);
		}
		break;
	default:
		LogMsg("Impossible event in drListenCallback: %d", eventType);
		break;
	}
}

mDNSexport mStatus drListen(DiscoveryRelayConnectState *drc)
{
	return DSOListen(drc->connectState);
}

mDNSlocal DiscoveryRelayConnectState *drConnectStateCreateInternal(void *context, const char *host, mDNSu16 port,
																   int numOutstandingQueries, size_t inbufsize,
																   size_t outbufsize, const char *detail,
																   void (*finalize)(DiscoveryRelayState *dr),
																   DSOEventCallback callback)
{
	DiscoveryRelayConnectState *drc;
	DSOConnectState *cs;
	cs = DSOConnectStateCreate(host, port, numOutstandingQueries, inbufsize, outbufsize, (void **)&drc, sizeof *drc,
							   callback, detail);
	if (cs == NULL)
		return NULL;
	memset(drc, 0, sizeof *drc);
	drc->connectState = cs;
	drc->finalize = finalize;
	drc->context = context;
	return drc;
}

mDNSexport DiscoveryRelayConnectState *drConnectStateCreate(void *context, const char *host, mDNSu16 port,
															int numOutstandingQueries, size_t inbufsize,
															size_t outbufsize, const char *detail,
															void (*finalize)(DiscoveryRelayState *dr))
{
	return drConnectStateCreateInternal(context, host, port, numOutstandingQueries, inbufsize, outbufsize,
										detail, finalize, drEventCallback);
}

mDNSexport DiscoveryRelayListenState *drListenStateCreate(void *context, mDNSu16 port,
														  int numOutstandingQueries, size_t inbufsize,
														  size_t outbufsize, const char *detail,
														  void (*finalize)(DiscoveryRelayState *dr))
{
	return drConnectStateCreateInternal(context, NULL, port, numOutstandingQueries, inbufsize, outbufsize,
										detail, finalize, drListenCallback);
}

// The mDNSResponder code uses bit masks rather than prefixes.   However, the wire protocol for the mDNS Relay uses
// prefixes.   Consequently, we need to be able to easily work with both, and these functions provide that capability.
// Masks can in principle be non-contiguous (zero bits to the left of one bits) but we currently believe that support
// for such masks is not necessary: that in practice we will never see a mask that can't be represented as a prefix.

// Return true if the first preflen bits of lhs and rhs are the same.
mDNSexport mDNSBool maskEqual(int preflen, mDNSu8 *lhs, mDNSu8 *rhs)
{
	int i = 0;
	while (i < (preflen >> 3)) {
		if (lhs[i] != rhs[i])
			return mDNSfalse;
		i++;
	}
	if ((i << 3) < preflen) {
		int pref = preflen - (i << 3);
		int mask = 0xFF ^ (0xFF >> pref);
		if ((lhs[i] & mask) != (rhs[i] & mask))
			return mDNSfalse;
	}
	return mDNStrue;
}

// Copy the bits of the prefix length from src to dest; all bits not in the prefix are copied as zeroes.
// Bytes is the number of bytes in the prefix, typically four or sixteen.
mDNSexport void prefixCopy(int preflen, int bytes, mDNSu8 *dest, mDNSu8 *src)
{
	int i = 0;

	// Complete bytes of prefix
	while (i < bytes && i < (preflen >> 3)) {
		dest[i] = src[i];
		i++;
	}
	// Partial byte of prefix
	if (i < bytes && (i << 3) < preflen) {
		int pref = preflen - (i << 3);
		int mask = 0xFF ^ (0xFF >> pref);
		dest[i] = src[i] & mask;
		++i;
	}
	// Rest of prefix
	while (i < bytes) {
		dest[i++] = 0;
	}
}

// Generate a mask from a prefix.
mDNSexport void prefixToMask(int preflen, int bytes, mDNSu8 *dest)
{
	int i = 0;

	// Complete bytes of prefix
	while (i < bytes && i < (preflen >> 3)) {
		dest[i] = 0xFF;
		i++;
	}
	// Partial byte of prefix
	if (i < bytes && (i << 3) < preflen) {
		int pref = preflen - (i << 3);
		int mask = 0xFF ^ (0xFF >> pref);
		dest[i] = mask;
		++i;
	}
	// Rest of prefix
	while (i < bytes) {
		dest[i++] = 0;
	}
}

mDNSexport int maskToPrefix(mDNSAddr *mask)
{
	int i, j;
	mDNSu8 *b;

	if (mask->type == mDNSAddrType_IPv4) {
		i = 3;
		b = &mask->ip.v4.b[0];
	} else if (mask->type == mDNSAddrType_IPv6) {
		i = 15;
		b = &mask->ip.v6.b[0];
	} else {
		// Dunno how wide a non-IP mask would be.
		return 0;
	}

	// Find the least significant nonzero byte.
	while (i >= 0) {
		if (b[i] != 0) {
			break;
		}
		--i;
	}

	if (i == -1)
		return 0;

	for (j = 0; j < 8; j++) {
		if (b[i] & (1<<j))
			return ((i + 1) << 3) - j;
	}
	// It should not be possible to exit the for loop above.
	assert(0);
}
