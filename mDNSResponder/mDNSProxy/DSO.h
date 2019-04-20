/* -*- Mode: C; tab-width: 4; c-file-style: "bsd"; c-basic-offset: 4; fill-column: 108; indent-tab-mode: nil -*-
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

#ifndef __DSO_h
#define __DSO_h

#define MAX_ADDITLS 10

typedef enum {
	kDSO_Type_Keepalive = 1,
	kDSO_Type_RetryDelay = 2,
	kDSO_Type_EncryptionPadding = 3,
	kDSO_Type_mDNSLinkRequest = 0xF901,
	kDSO_Type_mDNSLinkDiscontinue = 0xF902,
	kDSO_Type_mDNSMessage = 0xF903,
	kDSO_Type_LinkIdentifier = 0xF904,
	kDSO_Type_L2SourceAddress = 0xF905,
	kDSO_Type_IPSourceAddress = 0xF906,
	kDSO_Type_mDNSReportLinkChanges = 0xF907,
	kDSO_Type_mDNSStopLinkChanges = 0xF908,
	kDSO_Type_mDNSLinkAvailable = 0xF900,
	kDSO_Type_mDNSLinkUnavailable = 0xF90a,
	kDSO_Type_LinkPrefix = 0xf90b
} DSO_Types;

typedef struct {
	mDNSu16 id;
	mDNSBool response;			// False = query, true = response
	mDNSu8 opcode;
	mDNSBool authoritative;
	mDNSBool truncated;
	mDNSBool recurse;
	mDNSBool canRecurse;
	mDNSBool zero;
	mDNSBool authentic;
	mDNSBool checkingDisabled;
	mDNSu8 rcode;
	mDNSu16 qdcount;
	mDNSu16 ancount;
	mDNSu16 nscount;
	mDNSu16 arcount;
} DNSHeaderUnpacked;

// When a DSO message arrives, or one that was sent is acknowledged, or the state of the DSO connection
// changes, we need to call the user of the DSO connection.
typedef enum {
	kDSO_EventType_DNSMessage,	// A DNS message that is not a DSO message
	kDSO_EventType_DNSResponse,	// A DNS response that is not a DSO response
	kDSO_EventType_DSOMessage,	// DSOState.primary and DSOState.additl will contain the message TLVs; header will contain the DNS header
	kDSO_EventType_Finalize,	// The DSO connection to the other DSO endpoint has terminated and we are in the idle handler.
	kDSO_EventType_DSOResponse,	// DSOState.primary and DSOState.additl contain any TLVs in the response; header contains the DNS header
	kDSO_EventType_Connected,	// We succeeded in making a connection
	kDSO_EventType_ConnectFailed	// We failed to get a connection
} DSOEventType;

typedef struct dso_outstanding_query {
	mDNSu16 id;
	void *context;
} DSOOutstandingQuery;

typedef struct dso_outstanding_query_state {
	int outstandingQueryCount;
	int maxOutstandingQueries;
	DSOOutstandingQuery queries[0];
} DSOOutstandingQueryState;

// Structure to represent received DSO TLVs
typedef struct dsotlv {
	unsigned opcode;
	size_t length;
	mDNSu8 *payload;
} DSOTLV;

// DSO message under construction
typedef struct dso_message {
	mDNSu8 *buf;				// The buffer in which we are constructing the message
	size_t max;					// Size of the buffer
	size_t cur;					// Current position in the buffer
	mDNSBool buildingTLV;		// True if we have started and not finished building a TLV
	int outstandingQueryNumber;	// Number of the outstanding query state entry for this message, or -1
	size_t tlvLen;				// Current length of the TLV we are building.
	size_t tlvLenOffset;		// Where to store the length of the current TLV when finished.
	const mDNSu8 *noCopyBytes;	// One TLV can have data that isn't copied into the buffer
	size_t noCopyBytesLen;		// Length of that data, if any.
	size_t noCopyBytesOffset;	// Where in the buffer the data should be interposed.
} DSOMessage;

// Record of ongoing activity
typedef struct dso_activity DSOActivity;
struct dso_activity {
	DSOActivity *next;
	void (*finalize)(DSOActivity *activity);
	const char *activityType;	// Name of the activity type, must be the same pointer for all activities of a type.
	void *context;				// Activity implementation's context (if any).
	char *name;					// Name of the individual activity
};

typedef struct dso DSOState;
typedef void (*DSOEventCallback)(void *context, DNSHeaderUnpacked *header, DSOState *dso, DSOEventType eventType);

// DNS Stateless Operations state
struct dso {
	DSOState *next;
	void *context;				// The context of the next layer up (e.g., a Discovery Proxy)
	DSOEventCallback cb;		// Called when an event happens
	void *eventContext;			// I/O event context
	char *remoteName;			// A string describing the remote endpoint, could be hostname or address+port
	mDNSAddr remoteAddr;		// The IP address to which we have connected
	int remotePort;				// The port to which we have connected
	TCPSocket *connection;		// Socket connected to Discovery Proxy

	mDNSBool isServer;			// True if the endpoint represented by this DSO state is a server (according to the DSO spec)
	mDNSBool hasSession;		// True if DSO session establishment has happened for this DSO endpoint
	mDNSBool needLength;		// True if we need a 2-byte length
	mDNSs32 responseAwaited;	// If we are waiting for a session-establishing response, when it's expected;
								// otherwise zero.
	mDNSs32 keepaliveInterval;	// Time between keepalives (to be sent, on client, expected, on server)
	mDNSs32 inactiveInterval;	// Session can't be inactive more than this amount of time.
	mDNSs32 keepaliveDue;		// When the next keepalive is due (to be received or sent)
	mDNSs32 inactiveTimeout;	// When the next activity has to happen for the connection to remain active
	DSOActivity *activities;	// Outstanding DSO activities.

	size_t bytesNeeded;
	size_t messageLength;		// Length of message we are currently accumulating, if known
	mDNSu8 *inbuf;				// Buffer for incoming messages.
	size_t inbufsize;
	mDNSu8 *inbufp;				// Current read pointer (may not be in inbuf)

	mDNSu8 lenbuf[2];			// Buffer for storing the length in a DNS TCP message
	mDNSu8 *outbuf;				// Output buffer for sending DSO messages
	size_t outbufsize;

//	DSOMessage outMsg;			// Current message being constructed (if any).
	DSOTLV primary;				// Primary TLV for current message
	DSOTLV additl[MAX_ADDITLS];	// Additional TLVs
	int numAdditls;				// Number of additional TLVs in this message
#define MAX_WRITE_HUNKS 4		// When writing a DSO message, we need this many separate hunks.
	const mDNSu8 *toWrite[MAX_WRITE_HUNKS];
	ssize_t writeLengths[MAX_WRITE_HUNKS];
	int numToWrite;

	// outstandingQueries MUST be at the end of this structure
	DSOOutstandingQueryState *outstandingQueries;
};

typedef struct {
	struct addrinfo *ai, *aip;
	mDNSAddr addr;
	int sock;
	int configPort, connectPort;
	char *detail;
	char *host;
	void *context;
	void *eventContext;
	int numOutstandingQueries;
	size_t inbufsize, outbufsize;
	DSOEventCallback callback;
	DSOState *dso;
} DSOConnectState;

// Provided by DSO.c
mDNSexport void DSODrop(DSOState *dso);
mDNSexport mDNSs32 DSOIdle(mDNSs32 nextTimerEvent);
mDNSexport mStatus DSOSetConnection(DSOState *dso, TCPSocket *socket);
mDNSexport void DSOSetCallback(DSOState *dso, void *context, DSOEventCallback cb);
mDNSexport void DSORelease(DSOState **dsop);
mDNSexport void DSOStartTLV(DSOMessage *state, int opcode);
mDNSexport void DSOAddTLVBytes(DSOMessage *state, const mDNSu8 *bytes, size_t len);
mDNSexport void DSOAddTLVBytesNoCopy(DSOMessage *state, const mDNSu8 *bytes, size_t len);
mDNSexport void DSOAddTLVByte(DSOMessage *state, mDNSu8 byte);
mDNSexport void DSOAddTLVu16(DSOMessage *state, mDNSu16 u16);
mDNSexport void DSOAddTLVu32(DSOMessage *state, mDNSu32 u32);
mDNSexport void DSOFinishTLV(DSOMessage *state);
mDNSexport DSOActivity *DSOAddActivity(DSOState *dso, const char *name, const char *activityType,
									   size_t extra, void (*finalize)(DSOActivity *));
mDNSexport void DSODropActivity(DSOState *dso, DSOActivity *activity);
mDNSexport mStatus DSOMakeMessage(DSOMessage *state, DSOState *dso, mDNSBool unidirectional, void *callbackState);
mDNSexport size_t DSOMessageLength(DSOMessage *state);
mDNSexport mDNSBool DSOWriteStart(DSOState *dso, size_t length);
mDNSexport mDNSBool DSOWriteFinish(DSOState *dso);
mDNSexport void DSOWrite(DSOState *dso, const mDNSu8 *buf, size_t length);
mDNSexport mStatus DSOMessageWrite(DSOState *dso, DSOMessage *msg, mDNSBool disregardLowWater);
mDNSexport void DSOReadCallback(TCPSocket *sock, void *context, mDNSBool ConnectionEstablished, mStatus err);
mDNSexport mDNSBool DSOSendSimpleResponse(DSOState *dso, int rcode, const char *pres);
mDNSexport mDNSBool DSOSendNotImplemented(DSOState *dso);
mDNSexport mDNSBool DSOSendRefused(DSOState *dso);
mDNSexport mDNSBool DSOSendFormErr(DSOState *dso);
mDNSexport mDNSBool DSOSendServFail(DSOState *dso);
mDNSexport mDNSBool DSOSendNameError(DSOState *dso);
mDNSexport mDNSBool DSOSendNoError(DSOState *dso);
mDNSexport DSOConnectState *DSOConnectStateCreate(const char *host, mDNSu16 port, int numOutstandingQueries,
												  size_t inbufsize, size_t outbufsize,
												  void **context, size_t contextSize,
												  DSOEventCallback callback, const char *detail);
mDNSexport mDNSBool DSOConnect(DSOConnectState *connectState);
mDNSexport mStatus DSOListen(DSOConnectState *listenContext);

#define REALLY_FUSSY_MALLOC_DEBUG

#ifdef REALLY_FUSSY_MALLOC_DEBUG
mDNSexport void *mymalloc(size_t length);
mDNSexport void myfree(void *thunkv);
mDNSexport void *mycalloc(size_t count, size_t size);
mDNSexport char *mystrdup(const char *str);


#define malloc mymalloc
#define free myfree
#define calloc mycalloc
#define strdup mystrdup
#endif

#endif // !defined(__DSO_h)
