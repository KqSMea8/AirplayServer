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

#ifndef __RelayProtocol_h
#define __RelayProtocol_h

// Although this code is written in C, an attempt has been made to be somewhat object-oriented in how the
// code flows.  The DiscoveryRelayState object is effectively a subclass of the DSOState object.  The
// DSOState object handles all DSO-related work, and passes the rest to the DiscoveryRelayState object
// implementation using the DSOState callback.  A callback is used here so as to be as general as possible.
//
// The DiscoveryRelayState object itself is then effectively subclassed by the DiscoveryRelayState Server code, the
// Discovery Relay Client code, and that is further subclassed by the Discovery Relay Interface code and the
// Discovery Relay Test code.  Subclassing of the discovery relay is done by downcalls from the Discovery Relay
// code into the client or relay code, e.g. drMessage() and drResponse().  However, finalization of
// DiscoveryRelayState objects uses a callback; this is inconsistent and maybe should be made consistent, one way
// or the other.  Using the same style of callback that the DSO code uses would be an option.  This was not
// done essentially out of convenience: having an extra demultiplexing step seems unnecessary.

typedef struct dr {
	struct dr *next;			// Next Discovery Relay
	void *context;				// In the mDNSResponder code, this will be (mDNS *).
	DSOState *dso;				// Discovery Relay runs over DNS Stateless Operations, the state of which is managed here.
	int testState;				// Used by TestRelay.c
	void (*finalize)(struct dr *dr);	// Called before discovery relay structure is freed.
} DiscoveryRelayState;

// Context for connecting to Discovery Relay
typedef struct drc {
	struct drc *next;
	DSOConnectState *connectState;
	void *relay;				// Used for matching only.
	mDNSBool needsReconnect;	// True if we need to reconnect.
	mDNSs32 reconnectTime;		// On the client side, if needsReconnect is true, when to try.
	int configPort;				// Port number from configuration
	void (*finalize)(struct dr *dr);	// Passed to drCreate() when creating the Discovery Relay State.
	void *context;				// Ditto
} DiscoveryRelayConnectState;	
typedef DiscoveryRelayConnectState DiscoveryRelayListenState;

typedef enum link_family { link_family_ipv4 = 1, link_family_ipv6 = 2} LinkFamily;

extern mDNS mDNSStorage;
extern mDNS_PlatformSupport PlatformStorage;
extern struct timeval tv_start, tv_end, tv_interval;

// Provided by RelayShim.c
mDNSexport void mDNSCoreReceive(mDNS *const m, DNSMessage *const msg, const mDNSu8 *const end,
								const mDNSAddr *const srcaddr, const mDNSIPPort srcport,
								const mDNSAddr *dstaddr, const mDNSIPPort dstport,
								const mDNSInterfaceID InterfaceID);
mDNSexport void drReceivedMDNSMessage(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family,
									  mDNSAddr *sourceAddress, mDNSu16 sourcePort, mDNSu8 *message, size_t length);
mDNSexport void drLinkAvailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family,
								mDNSAddr *prefix, int preflen);
mDNSexport void drLinkUnavailable(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family);



// Provided by the main module (mDNSRelay.c or RelayClient.c)
mDNSexport void drMessage(DiscoveryRelayState *dr, DNSHeaderUnpacked *header, DSOState *dso);
mDNSexport void drResponse(void *context, DNSHeaderUnpacked *header, DSOState *dso);
mDNSexport DiscoveryRelayState *drConnected(void *context, DSOState *dso, mDNSBool connected);

// Provided by RelayProtocol.c
mDNSexport void DNSUnpackHeader(DNSHeaderUnpacked *header, mDNSu8 *message);
mDNSexport void DNSPackHeader(DNSHeaderUnpacked *header, mDNSu8 *message);
mDNSexport mDNSBool maskEqual(int preflen, mDNSu8 *lhs, mDNSu8 *rhs);

mDNSexport DiscoveryRelayState *drCreate(void *context, DSOState *dso, void (*finalize)(DiscoveryRelayState *dr));
mDNSexport mStatus drListen(DiscoveryRelayListenState *drc);
mDNSexport DiscoveryRelayConnectState *drConnectStateCreate(void *context, const char *host, mDNSu16 port,
															int numOutstandingQueries, size_t inbufsize,
															size_t outbufsize, const char *detail,
															void (*finalize)(DiscoveryRelayState *dr));
mDNSexport DiscoveryRelayListenState *drListenStateCreate(void *context, mDNSu16 port, int numOutstandingQueries,
														  size_t inbufsize, size_t outbufsize, const char *detail,
														  void (*finalize)(DiscoveryRelayState *dr));
mDNSexport void prefixCopy(int preflen, int bytes, mDNSu8 *dest, mDNSu8 *src);
mDNSexport void prefixToMask(int preflen, int bytes, mDNSu8 *dest);
mDNSexport int maskToPrefix(mDNSAddr *mask);

// Provided by RelayClient.c
mDNSexport mDNSBool drConnect(DiscoveryRelayConnectState *drc);
mDNSexport void drRequestLink(DiscoveryRelayState *dr, mDNSu32 linkID, LinkFamily family);
mDNSexport void drRequestLinkNotifications(DiscoveryRelayState *dr);

#endif // __RelayProtocol_h
