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

//*************************************************************************************************************
// Headers

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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

//*************************************************************************************************************
// Remaining work TODO

// - Add keepalive/inactivity timeout support
// - Notice if it takes a long time to get a response when establishing a session, and treat that
//   as "DSO not supported."
// - TLS support
// - Actually use Network Framework
// - Merge my malloc debugging code with the existing mDNS malloc debugging code, which does most of the same
//   stuff


//*************************************************************************************************************
// Globals

DSOState *dsoConnections;
DSOState *dsoConnectionsNeedingCleanup; // List of DSO connections that have been shut down but aren't yet freed.


mDNSlocal void DNSUnpackHeader(DNSHeaderUnpacked *header, mDNSu8 *message)
{
    header->id = (((mDNSu16)message[0]) << 8) | message[1];
    header->response = (message[2] & kDNSFlag0_QR_Mask) ? mDNStrue : mDNSfalse;
    header->opcode = (message[2] & kDNSFlag0_OP_Mask) >> 3;
    header->authoritative = (message[2] & kDNSFlag0_AA) ? mDNStrue : mDNSfalse;
    header->truncated = (message[2] & kDNSFlag0_TC) ? mDNStrue : mDNSfalse;
    header->recurse = (message[2] & kDNSFlag0_RD) ? mDNStrue : mDNSfalse;
    header->canRecurse = (message[3] & kDNSFlag1_RA) ? mDNStrue : mDNSfalse;
    header->zero = (message[3] & kDNSFlag1_Zero) ? mDNStrue : mDNSfalse;
    header->authentic = (message[3] & kDNSFlag1_AD) ? mDNStrue : mDNSfalse;
    header->checkingDisabled = (message[3] & kDNSFlag1_CD) ? mDNStrue : mDNSfalse;
    header->rcode = message[3] & kDNSFlag1_RC_Mask;
    header->qdcount = (((mDNSu16)message[4]) << 8) | message[5];
    header->ancount = (((mDNSu16)message[6]) << 8) | message[7];
    header->nscount = (((mDNSu16)message[8]) << 8) | message[9];
    header->arcount = (((mDNSu16)message[10]) << 8) | message[11];
}

#if 0 // I think we need this for later, but maybe not.
mDNSlocal void DNSPackHeader(DNSHeaderUnpacked *header, mDNSu8 *message)
{
    message[0] = header->id >> 8;
    message[1] = header->id & 255;
    message[2] = ((header->opcode & kDNSFlag0_OP_Mask) |
                  (header->response ? kDNSFlag0_QR_Response : 0) |
                  (header->authoritative ? kDNSFlag0_AA : 0) |
                  (header->truncated ? kDNSFlag0_TC : 0) |
                  (header->recurse ? kDNSFlag0_RD : 0));
    message[3] = ((header->canRecurse ? kDNSFlag1_RA : 0) |
                  (header->zero ? kDNSFlag1_Zero : 0) |
                  (header->authentic ? kDNSFlag1_AD : 0) |
                  (header->checkingDisabled ? kDNSFlag1_CD : 0) |
                  (header->rcode & kDNSFlag1_RC_Mask));
    message[4] = header->qdcount >> 8;
    message[5] = header->qdcount & 255;
    message[6] = header->ancount >> 8;
    message[7] = header->ancount & 255;
    message[8] = header->nscount >> 8;
    message[9] = header->nscount & 255;
    message[10] = header->arcount >> 8;
    message[11] = header->arcount & 255;
}
#endif

// This function is called either when an error has occurred requiring the a DSO connection be
// dropped, or else when a connection to a DSO endpoint has been cleanly closed and is ready to be
// dropped for that reason.

mDNSexport void DSODrop(DSOState *dso)
{
    DSOState *dsop;
    
    if (dsoConnections == dso) {
        dsoConnections = dso->next;
    } else {
        for (dsop = dsoConnections; dsop != NULL && dsop->next != dso; dsop = dsop->next) {
            LogMsg("dsop = %p dsop->next = %p dso = %p", dsop, dsop->next, dso);
        }
        if (dsop) {
            dsop->next = dso->next;
        // If we get to the end of the list without finding dso, it means that it's already
        // been dropped.
        } else {
            return;
        }
    }
    dso->next = dsoConnectionsNeedingCleanup;
    dsoConnectionsNeedingCleanup = dso;
    if (dso->connection != NULL) {
        mDNSPlatformTCPCloseConnection(dso->connection);
        dso->connection = NULL;
    }
}

// We do all of the finalization for the dso state object and any objects it depends on here in the
// DSOIdle function because it avoids the possibility that some code on the way out to the event loop
// _after_ the DSO connection has been dropped might still write to the DSO structure or one of the
// dependent structures and corrupt the heap, or indeed in the unlikely event that this memory was
// freed and then reallocated before the exit to the event loop, there could be a bad pointer
// dereference.
//
// If there is a finalize function, that function MUST either free its own state that references the
// DSO state, or else must NULL out the pointer to the DSO state.
mDNSexport mDNSs32 DSOIdle(mDNSs32 nextTimerEvent)
{
    DSOState *dso, *next;
    DSOActivity *ap;
    
    for (dso = dsoConnectionsNeedingCleanup; dso; dso = next) {
        next = dso->next;
        // Finalize and then free any activities.
        for (ap = dso->activities; ap; ap = ap->next) {
            if (ap->finalize) {
                ap->finalize(ap);
            }
            free(ap);
        }
        if (dso->cb) {
            dso->cb(dso->context, NULL, dso, kDSO_EventType_Finalize);
        }
        free(dso);
    }
    dsoConnectionsNeedingCleanup = NULL;
    return nextTimerEvent;
}

// Called when something happens that establishes a DSO session.
mDNSlocal void dsoSessionEstablished(DSOState *dso)
{
    dso->hasSession = mDNStrue;
    // Set up inactivity timer and keepalive timer...
}

// If a DSO was created by an incoming connection, the creator of the listener can use this function
// to supply context and a callback for future events.
mDNSexport void DSOSetCallback(DSOState *dso, void *context, DSOEventCallback cb)
{
    dso->cb = cb;
    dso->context = context;
}

// Create a DSOState structure
mDNSlocal DSOState *dsoCreate(TCPSocket *sock, mDNSBool isServer, void *context, int numOutstandingQueries,
							  size_t inbufsize_in, size_t outbufsize_in, const char *remoteName, DSOEventCallback cb)
{
	DSOState *dso;
	size_t outbufsize;
	size_t inbufsize;
	size_t namesize = strlen(remoteName) + 1;
	int eventsize = mDNSPlatformEventContextSize();
	size_t outsize;
	mDNSu8 *dsop;
	mStatus status;

	// There's no point in a DSO that doesn't have a callback.
	if (!cb) {
		return NULL;
	}

	outbufsize = outbufsize_in + 256; // Space for additional TLVs
	inbufsize = inbufsize_in + 2;	  // Space for length
	outsize = (sizeof (DSOOutstandingQueryState)) + numOutstandingQueries * sizeof (DSOOutstandingQuery);

	// We allocate everything in a single hunk so that we can free it together as well.
	dsop = malloc((sizeof *dso) + outsize + eventsize + inbufsize + outbufsize + namesize);
	if (dsop == NULL) {
		dso = NULL;
		goto out;
	}
	dso = (DSOState *)dsop;
	memset(dso, 0, sizeof *dso);
	dsop += sizeof *dso;

	dso->outstandingQueries = (DSOOutstandingQueryState *)dsop;
	memset(dso->outstandingQueries, 0, outsize);
	dso->outstandingQueries->maxOutstandingQueries = numOutstandingQueries;
	dsop += outsize;

	dso->eventContext = dsop;
	memset(dso->eventContext, 0, eventsize);
	dsop += eventsize;

	dso->inbuf = dsop;
	dso->inbufsize = inbufsize;
	dsop += inbufsize;

	dso->outbuf = dsop;
	dso->outbufsize = outbufsize;
	dsop += outbufsize;

	dso->remoteName = (char *)dsop;
	memcpy(dso->remoteName, remoteName, namesize);

	dso->context = context;
	dso->cb = cb;
	dso->connection = sock;
	dso->isServer = isServer;

	status = mDNSPlatformTCPSocketSetCallback(sock, DSOReadCallback, dso);
	if (status != mStatus_NoError) {
		LogMsg("dsoCreate: unable to set callback: %d", status);
		free(dso);
		return NULL;
	}

	dso->next = dsoConnections;
	dsoConnections = dso;
out:
	return dso;
}

// Start building a TLV in an outgoing dso message.
mDNSexport void DSOStartTLV(DSOMessage *state, int opcode)
{
    // Make sure there's room for the length and the TLV opcode.
    if (state->cur + 4 >= state->max) {
        LogMsg("startTLV called when no space in output buffer!");
        assert(0);
    }

    // We need to not yet have a TLV.
    if (state->buildingTLV)
    {
        LogMsg("startTLV called while already building a TLV!");
        assert(0);
    }
    state->buildingTLV = mDNStrue;
    state->tlvLen = 0;
    
    // Set up the TLV header.
    state->buf[state->cur] = opcode >> 8;
    state->buf[state->cur + 1] = opcode & 255;
    state->tlvLenOffset = state->cur + 2;
    state->cur += 4;
}

// Add some bytes to a TLV that's being built, but don't copy them--just remember the
// pointer to the buffer.   This is used so that when we have a message to forward, we
// don't copy it into the output buffer--we just use scatter/gather I/O.
mDNSexport void DSOAddTLVBytesNoCopy(DSOMessage *state, const mDNSu8 *bytes, size_t len)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVBytes called when not building a TLV!");
        assert(0);
    }
    if (state->noCopyBytesLen) {
        LogMsg("addTLVBytesNoCopy called twice on the same DSO message.");
        assert(0);
    }
    state->noCopyBytesLen = len;
    state->noCopyBytes = bytes;
    state->noCopyBytesOffset = state->cur;
    state->tlvLen += len;
}

// Add some bytes to a TLV that's being built.
mDNSexport void DSOAddTLVBytes(DSOMessage *state, const mDNSu8 *bytes, size_t len)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVBytes called when not building a TLV!");
        assert(0);
    }
    if (state->cur + len > state->max) {
        LogMsg("addTLVBytes called with no room in output buffer.");
        assert(0);
    }
    memcpy(&state->buf[state->cur], bytes, len);
    state->cur += len;
    state->tlvLen += len;
}

// Add a single byte to a TLV that's being built.
mDNSexport void DSOAddTLVByte(DSOMessage *state, mDNSu8 byte)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVByte called when not building a TLV!");
        assert(0);
    }
    if (state->cur + 1 > state->max) {
        LogMsg("addTLVByte called with no room in output buffer.");
        assert(0);
    }
    state->buf[state->cur++] = byte;
    state->tlvLen++;
}

// Add an mDNSu16 to a TLV that's being built.
mDNSexport void DSOAddTLVu16(DSOMessage *state, mDNSu16 u16)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVu16 called when not building a TLV!");
        assert(0);
    }
    if ((state->cur + sizeof u16) > state->max) {
        LogMsg("addTLVu16 called with no room in output buffer.");
        assert(0);
    }
    state->buf[state->cur++] = u16 >> 8;
    state->buf[state->cur++] = u16 & 255;
    state->tlvLen += 2;
}

// Add an mDNSu32 to a TLV that's being built.
mDNSexport void DSOAddTLVu32(DSOMessage *state, mDNSu32 u32)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVu32 called when not building a TLV!");
        assert(0);
    }
    if ((state->cur + sizeof u32) > state->max) {
        LogMsg("addTLVu32 called with no room in output buffer.");
        assert(0);
    }
    state->buf[state->cur++] = u32 >> 24;
    state->buf[state->cur++] = (u32 >> 16) & 255;
    state->buf[state->cur++] = (u32 >> 8) & 255;
    state->buf[state->cur++] = u32 & 255;
    state->tlvLen += 4;
}

// Finish building a TLV.
mDNSexport void DSOFinishTLV(DSOMessage *state)
{
    if (!state->buildingTLV) {
        LogMsg("addTLVBytes called when not building a TLV!");
        assert(0);
    }

    // A TLV can't be longer than this.
    if (state->tlvLen > 65535) {
        LogMsg("addTLVBytes was given more than 65535 bytes of TLV payload!");
        assert(0);
    }
    state->buf[state->tlvLenOffset] = state->tlvLen >> 8;
    state->buf[state->tlvLenOffset + 1] = state->tlvLen & 255;
    state->tlvLen = 0;
    state->buildingTLV = mDNSfalse;
}

// Make an activity structure to hang off the DSO.
mDNSexport DSOActivity *DSOAddActivity(DSOState *dso, const char *name, const char *activityType,
                                       size_t extra, void (*finalize)(DSOActivity *))
{
    size_t namelen = strlen(name) + 1;
    size_t len;
    DSOActivity *activity;
    void *ap;

    len = extra + namelen + sizeof *activity;
    ap = malloc(len);
    if (ap == NULL) {
        return NULL;
    }
    activity = (DSOActivity *)ap;
    ap = (char *)ap + sizeof *activity;
    memset(activity, 0, sizeof *activity);
    if (extra) {
        activity->context = ap;
        ap = (char *)ap + extra;
    } else {
        activity->context = NULL;
    }
    activity->name = ap;
    ap = (char *)ap + namelen;
    memcpy(activity->name, name, namelen);
    
    activity->activityType = activityType;
    activity->finalize = finalize;

    // Retain this activity on the list.
    activity->next = dso->activities;
    dso->activities = activity;
    return activity;
}

mDNSexport void DSODropActivity(DSOState *dso, DSOActivity *activity)
{
    DSOActivity **app = &dso->activities;
    mDNSBool matched = mDNSfalse;

    // Remove this activity from the list.
    while (*app) {
        if (*app == activity) {
            *app = activity->next;
            matched = mDNStrue;
        } else {
            app = &((*app)->next);
        }
    }

    // If an activity that's not on the DSO list is passed here, it's an internal consistency
    // error that probably indicates something is corrupted.
    if (!matched) {
        LogMsg("DSODropActive: FATAL: activity that's not on the list has been dropped!");
        assert(0);
    }

    activity->finalize(activity);
    free(activity);
}

mDNSexport mStatus DSOMakeMessage(DSOMessage *state, DSOState *dso, mDNSBool unidirectional, void *callbackState)
{
    DNSMessageHeader msgHeader;
    DSOOutstandingQueryState *midState = dso->outstandingQueries;

    memset(state, 0, sizeof *state);
    state->buf = dso->outbuf;
    state->max = dso->outbufsize;

    // The DNS header for a DSO message is mostly zeroes
    memset(&msgHeader, 0, sizeof msgHeader);
    msgHeader.flags.b[0] = kDNSFlag0_QR_Query | (kDNSFlag0_OP_DSO << 3);

    // Servers can't send DSO messages until there's a DSO session.
    if (dso->isServer && !dso->hasSession) {
        return mStatus_DSONoSession;
    }

    // Response-requiring messages need to have a message ID.
    if (!unidirectional) {
        mDNSBool msgIDOK = mDNStrue;
        mDNSu16 messageID;
        int looping = 0;
        int i, avail = 0;

        // If we don't have room for another outstanding message, the caller should try
        // again later.
        if (midState->outstandingQueryCount == midState->maxOutstandingQueries) {
            return mStatus_NoMemoryErr;
        }
        // Generate a random message ID.   This doesn't really need to be cryptographically sound
        // (right?) because we're encrypting the whole data stream in TLS.
        do {
            // This would be a surprising fluke, but let's not get killed by it.
            if (looping++ > 1000) {
                return mStatus_TransientErr;
            }
            messageID = mDNSRandom(65536);
            msgIDOK = mDNStrue;
            if (messageID == 0) {
                msgIDOK = mDNSfalse;
            } else {
                for (i = 0; i < midState->maxOutstandingQueries; i++) {
                    if (midState->queries[i].id == 0 && avail == 0) {
                        avail = i;
                    } else if (midState->queries[i].id == messageID) {
                        msgIDOK = mDNSfalse;
                    }
                }
            }
        } while (!msgIDOK);
        midState->queries[avail].id = messageID;
        midState->queries[avail].context = callbackState;
        midState->outstandingQueryCount++;
        msgHeader.id.b[0] = messageID >> 8;
        msgHeader.id.b[1] = messageID & 255;
        state->outstandingQueryNumber = avail;
    } else {
        // Clients aren't allowed to send unidirectional messages until there's a session.
        if (!dso->hasSession) {
            return mStatus_DSONoSession;
        }
        state->outstandingQueryNumber = -1;
    }

    // We need space for the TCP message length plus the DNS header.
    if (state->max < sizeof msgHeader) {
        LogMsg("makeDSOMessage: called without enough buffer space to store a DNS header!");
        assert(0);
    }
    memcpy(state->buf, &msgHeader, sizeof msgHeader);
    state->cur = sizeof msgHeader;
    return mStatus_NoError;
}

mDNSexport size_t DSOMessageLength(DSOMessage *state)
{
    return state->cur + state->noCopyBytesLen;
}

// This is called before writing a DSO message to the output buffer.  length is the length of the message.
// Returns mDNStrue if we have successfully selected for write (which means that we're under TCP_NOTSENT_LOWAT).
// Otherwise returns mDNSfalse.   It is valid to write even if it returns false, but there is a risk that
// the write will return EWOULDBLOCK, at which point we'd have to blow away the connection.   It is also
// valid to give up at this point and not write a message; as long as DSOWriteFinish isn't called, a later
// call to DSOWriteStart will overwrite the length that was stored by the previous invocation.
//
// The circumstance in which this would occur is that we have filled the kernel's TCP output buffer for this
// connection all the way up to TCP_NOTSENT_LOWAT, and then we get a query from the Discovery Proxy to which we
// need to respond.  Because TCP_NOTSENT_LOWAT is fairly low, there should be a lot of room in the TCP output
// buffer for small responses; it would need to be the case that we are getting requests from the proxy at a
// high rate for us to fill the output buffer to the point where a write of a 12-byte response returns
// EWOULDBLOCK; in that case, things are so dysfunctional that killing the connection isn't any worse than
// allowing it to continue.

// An additional note about the motivation for this code: the idea originally was that we'd do scatter/gather
// I/O here: this lets us write everything out in a single sendmsg() call.   However, the mDNSPlatformTCP
// code doesn't support scatter/gather, and the current mDNSMacOSX TLS code probably doesn't either,
// so right now this code isn't using scatter/gather.   However, it did work with sendmsg(), and it's
// most likely worth using the functionality if it becomes available again later, e.g. with the
// network framework.   So I'm leaving this in for now, but we could shorten the code quite a bit later
// by taking it out of the scatter/gather feature is not needed.

mDNSexport mDNSBool DSOWriteStart(DSOState *dso, size_t length)
{
    // The transport doesn't support messages outside of this range.
    if (length < 12 || length > 65535) {
        return mDNSfalse;
    }

    dso->lenbuf[0] = length >> 8;
    dso->lenbuf[1] = length & 255;

    dso->toWrite[0] = dso->lenbuf;
    dso->writeLengths[0] = 2;
    dso->numToWrite = 1;

    return mDNSPlatformTCPWritable(dso->connection);
}

// Called to finish a write (DSOWriteStart .. DSOWrite .. [ DSOWrite ... ] DSOWriteFinish).  The
// write must completely finish--if we get a partial write, this means that the connection is stalled, and
// so we drop it.  Since this can call DSODrop, the caller must not reference the DSO state object
// after this call if the return value is mDNSfalse.
mDNSexport mDNSBool DSOWriteFinish(DSOState *dso)
{
    ssize_t result, total = 0;
    int i;

    if (dso->numToWrite > MAX_WRITE_HUNKS) {
        LogMsg("DSOWriteFinish: fatal internal programming error: called %d times (more than limit of %d)", 
               dso->numToWrite, MAX_WRITE_HUNKS);
        DSODrop(dso);
        return mDNSfalse;
    }

    // This is our ersatz scatter/gather I/O.
    for (i = 0; i < dso->numToWrite; i++) {
        result = mDNSPlatformWriteTCP(dso->connection, (const char *)dso->toWrite[i], dso->writeLengths[i]);
        if (result != dso->writeLengths[i]) {
            if (result < 0) {
                LogMsg("DSOWriteFinish: fatal: mDNSPlatformWrite on %s returned %d", dso->remoteName, errno);
            } else {
                LogMsg("DSOWriteFinish: fatal: mDNSPlatformWrite: short write on %s: %d < %d", dso->remoteName, result, total);
            }
            DSODrop(dso);
            return mDNSfalse;
        }
    }
    return mDNStrue;
}

// This function may only be called after a previous call to DSOWriteStart; it records the length of and
// pointer to the write buffer.  These buffers must remain valid until DSOWriteFinish() is called.  The
// caller is responsible for managing the memory they contain.  The expected control flow for writing is:
// DSOWriteStart(); DSOWrite(); DSOWrite(); DSOWrite(); DSOWriteFinished(); There should be one or more calls to
// DSOWrite; these will ideally be translated into a single scatter/gather sendmsg call (or equivalent) to the
// kernel.
mDNSexport void DSOWrite(DSOState *dso, const mDNSu8 *buf, size_t length)
{
    // We'll report this in DSOWriteFinish();
    if (dso->numToWrite >= MAX_WRITE_HUNKS) {
        dso->numToWrite++;
        return;
    }

    dso->toWrite[dso->numToWrite] = buf;
    dso->writeLengths[dso->numToWrite] = length;
    dso->numToWrite++;
}

// Write a DSO message
mStatus DSOMessageWrite(DSOState *dso, DSOMessage *msg, mDNSBool disregardLowWater)
{
    if (DSOWriteStart(dso, DSOMessageLength(msg)) || disregardLowWater) {
        DSOWrite(dso, msg->buf, msg->noCopyBytesOffset);
        DSOWrite(dso, msg->noCopyBytes, msg->noCopyBytesLen);
        DSOWrite(dso, &msg->buf[msg->noCopyBytesOffset], msg->cur - msg->noCopyBytesOffset);
        return DSOWriteFinish(dso);
    }
    return mStatus_NoMemoryErr;
}

// Replies to some message we were sent with a response code and no data.
// This is a convenience function for replies that do not require that a new
// packet be constructed.   It takes advantage of the fact that the message
// to which this is a reply is still in the input buffer, and modifies that
// message in place to turn it into a response.

mDNSexport mDNSBool DSOSendSimpleResponse(DSOState *dso, int rcode, const char *pres)
{
    (void)pres; // might want this later.
    mDNSu8 *msg = &dso->inbuf[2];
    
    // Just return the message, with no questions, answers, etc.
    msg[3] = (msg[3] & 0xf0) | rcode;
    msg[2] |= 0x80;
    // QDCOUNT=ANCOUNT=NSCOUNT=ADCOUNT=0
    memset(&msg[4], 0, 8);

    // Buffered write back to discovery proxy
    (void)DSOWriteStart(dso, 12);
    DSOWrite(dso, msg, 12);
    if (!DSOWriteFinish(dso)) {
        return mDNSfalse;
    }
    return mDNStrue;
}

// DSO Message we received has a primary TLV that's not implemented.
// XXX is this what we're supposed to do here? check draft.
mDNSexport mDNSBool DSOSendNotImplemented(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_DSOTypeNI, "DSOTYPENI");
}

// Non-DSO message we received is refused.
mDNSexport mDNSBool DSOSendRefused(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_Refused, "REFUSED");
}

mDNSexport mDNSBool DSOSendFormErr(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_FormErr, "FORMERR");
}

mDNSexport mDNSBool DSOSendServFail(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_ServFail, "SERVFAIL");
}

mDNSexport mDNSBool DSOSendNameError(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_NXDomain, "NXDOMAIN");
}

mDNSexport mDNSBool DSOSendNoError(DSOState *dso)
{
    return DSOSendSimpleResponse(dso, kDNSFlag1_RC_NoErr, "NOERROR");
}

// We received a DSO message; validate it, parse it and, if implemented, dispatch it.
mDNSlocal void DSOMessageReceived(DSOState *dso, DNSHeaderUnpacked *header)
{
    int i;
    size_t offset;
    mDNSu8 *msg = &dso->inbuf[2];

    // See if we have sent a message for which a response is expected.
    if (header->response) {
        for (i = 0; i < dso->outstandingQueries->maxOutstandingQueries; i++) {
            // A zero ID on a response is not permitted.
            if (header->id == 0) {
                LogMsg("DSOMessageReceive: response with id==0 received from %s", dso->remoteName);
                DSODrop(dso);
                goto out;
            }
            if (dso->outstandingQueries->queries[i].id == header->id) {
                // If we are a client, and we just got an acknowledgment, a session has been established.
                if (!dso->isServer && !dso->hasSession) {
                    dsoSessionEstablished(dso);
                }
                if (dso->cb) {
                    dso->outstandingQueries->queries[i].id = 0;
                    dso->outstandingQueries->outstandingQueryCount--;
                    dso->cb(dso->context, header, dso, kDSO_EventType_DSOResponse);
                    if (dso->outstandingQueries->outstandingQueryCount < 0) {
                        LogMsg("DSOMessageReceive: programming error: outstandingQueryCount went negative.");
                        assert(0);
                    }
                    goto out;
                }
            }
        }

        // This is fatal because we've received a response to a message we didn't send, so
        // it's not just that we don't understand what was sent.
        LogMsg("DSOMessageReceived: fatal: %s sent %d byte message, QR=1", dso->remoteName, dso->messageLength);
        DSODrop(dso);
        goto out;
    }

    // Make sure that the DNS header is okay (QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT are all zero)
    for (i = 0; i < 4; i++) {
        if (msg[4 + i * 2] != 0 || msg[4 + i * 2 + 1] != 0) {
            LogMsg("DSOMessageReceived: fatal: %s sent %d byte DSO message, %s is nonzero",
                   dso->remoteName, dso->messageLength,
                   (i == 0 ? "QDCOUNT" : (i == 1 ? "ANCOUNT" : ( i == 2 ? "NSCOUNT" : "ARCOUNT"))));
            DSODrop(dso);
            goto out;
        }
    }

    // Check that there is space for there to be a primary TLV
    if (dso->messageLength < 16) {
        LogMsg("DSOMessageReceived: fatal: %s sent short (%d byte) DSO message", dso->remoteName, dso->messageLength);

        // Short messages are a fatal error. XXX check DSO document
        DSODrop(dso);
        goto out;
    }
    
    // If we are a server, and we don't have a session, and this is a message, then we have now established a session.
    if (!dso->hasSession && dso->isServer && !header->response) {
        dsoSessionEstablished(dso);
    }

    // If a DSO session isn't yet established, make sure the message is a request (if isServer) or a
    // response (if not).
    if (!dso->hasSession && ((dso->isServer && header->response) || (!dso->isServer && !header->response))) {
        LogMsg("DNSMessageReceived: received a %s with no established session from %s",
               header->response ? "response" : "request", dso->remoteName);
        DSODrop(dso);
    }

    // Get the primary TLV and count how many TLVs there are in total
    offset = 12;
    do {
        // Get the TLV opcode
        int opcode = (((unsigned)msg[offset]) << 8) + msg[offset + 1];
        // And the length
        size_t length = (((unsigned)msg[offset + 2]) << 8) + msg[offset + 3];

        // Is there room for the contents of this TLV?
        if (length + offset > dso->messageLength) {
            LogMsg("DSOMessageReceived: fatal: %s: TLV (%d %d) extends past end (%d)",
                   dso->remoteName, opcode, length, dso->messageLength);

            // Short messages are a fatal error. XXX check DSO document
            DSODrop(dso);
            goto out;
        }

        // Is this the primary TLV?
        if (offset == 12) {
            dso->primary.opcode = opcode;
            dso->primary.length = length;
            dso->primary.payload = &msg[offset + 4];
            dso->numAdditls = 0;
        } else {
            if (dso->numAdditls < MAX_ADDITLS) {
                dso->additl[dso->numAdditls].opcode = opcode;
                dso->additl[dso->numAdditls].length = length;
                dso->additl[dso->numAdditls].payload = &msg[offset + 4];
                dso->numAdditls++;
            } else {
                // XXX MAX_ADDITLS should be enough for all possible additional TLVs, so this
                // XXX should never happen; if it does, maybe it's a fatal error.
                LogMsg("DSOMessageReceived: %s: ignoring additional TLV (%d %d) in excess of %d",
                       dso->remoteName, opcode, length, MAX_ADDITLS);
            }
        }
        offset += 4 + length;
    } while (offset < dso->messageLength);

    // Handle standard DSO messages
    switch(dso->primary.opcode) {
    default:
        // This should never be NULL; if it is, maybe crashing is the right thing to do.
        if (dso->cb) {
            dso->cb(dso->context, header, dso, kDSO_EventType_DSOMessage);
        }
    }
out:
    ;
}

// This code is currently assuming that we won't get a DNS message, but that's not true.   Fix.
mDNSlocal void DNSMessageReceived(DSOState *dso)
{
    DNSHeaderUnpacked header;
    mDNSu8 *msg = &dso->inbuf[2];

    DNSUnpackHeader(&header, msg);
    
    // Validate the length of the DNS message.
    if (dso->messageLength < 12) {
        LogMsg("dnsDispatch: fatal: %s sent short (%d byte) message",
               dso->remoteName, dso->messageLength);

        // Short messages are a fatal error.
        DSODrop(dso);
        return;
    }
    
    // This is not correct for the general case.
    if (header.opcode != kDNSFlag0_OP_DSO) {
        LogMsg("DNSMessageReceived: %s sent %d byte %s, QTYPE=%d",
               dso->remoteName, dso->messageLength, header.response ? "response" : "request", header.opcode);
        if (dso->cb) {
            dso->cb(dso->context, &header, dso, header.response ? kDSO_EventType_DNSMessage : kDSO_EventType_DNSResponse);
        }
    } else {
        DSOMessageReceived(dso, &header);
    }
}

// Called whenever there's data available on a DSO connection
mDNSexport void DSOReadCallback(TCPSocket *sock, void *context, mDNSBool ConnectionEstablished, mStatus err)
{
    DSOState *dso = context;
    mDNSBool closed = mDNSfalse;

    // This shouldn't ever happen.
    if (err) {
        LogMsg("DSOReadCallback: error %d", err);
        DSODrop(dso);
        goto out;
    }

    // Connection is already established by the time we set this up.
    if (ConnectionEstablished) goto out;
    
    // This will be true either if we have never read a message or
    // if the last thing we did was to finish reading a message and
    // process it.
    if (dso->messageLength == 0) {
        dso->needLength = mDNStrue;
        dso->inbufp = dso->inbuf;
        dso->bytesNeeded = 2;
    }
    
    // Read up to bytesNeeded bytes.
    ssize_t count = mDNSPlatformReadTCP(sock, dso->inbufp, dso->bytesNeeded, &closed);
    // LogMsg("read(%d, %p:%p, %d) -> %d", fd, dso->inbuf, dso->inbufp, dso->bytesNeeded, count);
    if (count < 0) {
        LogMsg("DSOReadCallback: read from %s returned %d", dso->remoteName, errno);
        DSODrop(dso);
        goto out;
    }

    // If we get selected for read and there's nothing to read, the remote end has closed the
    // connection.
    if (closed) {
        DSODrop(dso);
        goto out;
    }
    dso->inbufp += count;
    dso->bytesNeeded -= count;

    // If we read all the bytes we wanted, do what's next.
    if (dso->bytesNeeded == 0) {
        // We just finished reading the complete length of a DNS-over-TCP message.
        if (dso->needLength) {
            // Get the number of bytes in this DNS message
            dso->bytesNeeded = (((int)dso->inbuf[0]) << 8) | dso->inbuf[1];

            // Under no circumstances can length be zero.
            if (dso->bytesNeeded == 0) {
                LogMsg("DSOReadCallback: %s sent zero-length message.", dso->remoteName);
                DSODrop(dso);
                goto out;
            }

            // The input buffer size is AbsoluteMaxDNSMessageData, which is around 9000 bytes on
            // big platforms and around 1500 bytes on smaller ones.   If the remote end has sent
            // something larger than that, it's an error from which we can't recover.
            if (dso->bytesNeeded > dso->inbufsize - 2) {
                LogMsg("DSOReadCallback: fatal: Proxy at %s sent a too-long (%d bytes) message", dso->remoteName, dso->bytesNeeded);
                DSODrop(dso);
                goto out;
            }

            dso->messageLength = dso->bytesNeeded;
            dso->inbufp = dso->inbuf + 2;
            dso->needLength = mDNSfalse;

        // We just finished reading a complete DNS-over-TCP message.
        } else {
            DNSMessageReceived(dso);
            dso->messageLength = 0;
        }
    }
out:
    ;
}

// This should all be replaced with Network Framework connection setup.

mDNSexport DSOConnectState *DSOConnectStateCreate(const char *host, mDNSu16 port, int numOutstandingQueries,
												  size_t inbufsize, size_t outbufsize,
												  void **context, size_t contextSize,
												  DSOEventCallback callback, const char *detail)
{
    int detlen = strlen(detail) + 1;
    int hostlen = host == NULL ? 0 : strlen(host) + 1;
    int eventContextSize = mDNSPlatformEventContextSize();
    int len;
    DSOConnectState *cs;
    char *csp;

	// Enforce Some Minimums (Xxx these are a bit arbitrary, maybe not worth doing?)
	if (inbufsize < MaximumRDSize || outbufsize < 128 ||
		numOutstandingQueries < 1 || (context == NULL && contextSize != 0)) {
		return 0;
	}

    len = (sizeof *cs) + detlen + hostlen + eventContextSize + contextSize;
 	csp = malloc(len);
	if (!csp) {
		return NULL;
	}
	cs = (DSOConnectState *)csp;
	memset(cs, 0, sizeof *cs);
	csp += sizeof *cs;

	cs->eventContext = (void *)csp;
	memset(csp, 0, eventContextSize);
	csp += eventContextSize;
	if (contextSize) {
		*context = (void *)csp;
		csp += contextSize;
	} else {
		if (context != NULL) {
			*context = NULL;
		}
	}
	cs->detail = csp;
	memcpy(cs->detail, detail, detlen);
	csp += detlen;
	if (hostlen) {
		cs->host = csp;
		memcpy(cs->host, host, hostlen);
		csp += hostlen;
	} else {
		cs->host = NULL;
	}

	cs->configPort = port;
	cs->numOutstandingQueries = numOutstandingQueries;
	cs->inbufsize = inbufsize;
	cs->outbufsize = outbufsize;
	cs->context = *context;
	cs->callback = callback;

	cs->connectPort = -1;
	cs->sock = -1;
	
	return cs;
}

mDNSlocal void dsoConnectCallback(TCPSocket *sock, void *context, mDNSBool connected, mStatus err)
{
    DSOConnectState *cs = context;
    struct addrinfo *aip;
    char *detail;
    int rc;
    mStatus status;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    mDNSu16 *pport;
    int lowat = 32768; // XXX parameterize: is this a good value?
    mDNSIPPort port;
    DSOState *dso;

    (void)connected;
    aip = cs->aip;
    detail = cs->detail;
    
    // If aip is not NULL, we have already tried to connect, so see if we succeeded.
    if (sock != NULL) {
        if (err != mStatus_NoError) {
            mDNSPlatformTCPCloseConnection(sock);
            LogMsg("dsoConnectCallback: connect %p failed (%d)", cs, err);
        again:
            aip = aip->ai_next;
            if (aip == NULL) {
                LogMsg("dsoConnectCallback: connect %p: no addresses left to try", cs);
            fail:
                freeaddrinfo(cs->ai);
                cs->ai = NULL;
				if (cs->callback) {
					cs->callback(cs, NULL, NULL, kDSO_EventType_ConnectFailed);
				}
				return;
			}
			cs->aip = aip;
		} else {
		success:
			// We got a connection.
			dso = dsoCreate(sock, mDNSfalse, cs->context, cs->numOutstandingQueries,
							cs->inbufsize, cs->outbufsize, cs->host, cs->callback);
			if (dso == NULL) {
				LogMsg("dsoConnectCallback: dsoCreate failed");
				goto fail;
			}
			freeaddrinfo(cs->ai);
            cs->ai = NULL;

            // Call the "we're connected" callback, which will start things up.
            if (dso->cb) {
                dso->cb(cs, NULL, dso, kDSO_EventType_Connected);
            }
            return;
        }
    }

    // Various connect methods we don't support, which will probably never be returned anyway, but if
    // they are, we are ready!
    if ((aip->ai_socktype != 0 && aip->ai_socktype != SOCK_STREAM)) {
        err = mStatus_UnsupportedErr;
        LogMsg("dsoConnectCallback: getaddrinfo returned a non-stream (%d) protocol--skipping", aip->ai_socktype);
        goto again;
    } else if (aip->ai_protocol != 0 && aip->ai_protocol != IPPROTO_TCP) {
        err = mStatus_UnsupportedErr;
        LogMsg("dsoConnectCallback: getaddrinfo returned a non-tcp (%d) protocol--skipping", aip->ai_protocol);
        goto again;
    } else if (aip->ai_family == AF_INET) {
        sin = (struct sockaddr_in *)aip->ai_addr;
        assert(aip->ai_addrlen == sizeof *sin);
        cs->addr.type = mDNSAddrType_IPv4;
        memcpy(&cs->addr.ip.v4, &sin->sin_addr, sizeof cs->addr.ip.v4);
        pport = &sin->sin_port;
    } else if (aip->ai_protocol == AF_INET6) {
        sin6 = (struct sockaddr_in6 *)aip->ai_addr;
        assert(aip->ai_addrlen == sizeof *sin6);
        cs->addr.type = mDNSAddrType_IPv6;
        memcpy(&cs->addr.ip.v6, &sin6->sin6_addr, sizeof cs->addr.ip.v6);
        pport = &sin6->sin6_port;
    } else {
        err = mStatus_UnsupportedErr;
        LogMsg("dsoConnectCallback: getaddrinfo returned a non-internet (%d) address--skipping", aip->ai_family);
        goto again;
    }

    if (cs->configPort == -1 && *pport == 0) {
        LogMsg("drConnectCallback: missing port number%s", detail);
        err = mStatus_BadParamErr;
    } else if (cs->configPort != -1 && *pport != 0) {
        LogMsg("drConnectCallback: port number%s superseded by getaddrinfo response", detail);
        // This isn't an error--it's possible that some getaddrinfo responses will provide ports and
        // others won't, although I don't know if that can actually happen in practice.
    } else {
        *pport = htons(cs->configPort);
    }
    port.NotAnInteger = *pport;

    sock = mDNSPlatformTCPSocket(kTCPSocketFlags_Zero, cs->addr.type, NULL, NULL, mDNSfalse);
    if (sock == NULL) {
        LogMsg("drConnectCallback: couldn't get a socket for %s: %s%s",
               cs->host, strerror(errno), detail);
        goto fail;
    }

    rc = setsockopt(mDNSPlatformTCPGetFD(sock), IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof lowat);
    if (rc < 0) {
        LogMsg("dsoConnectCallback: TCP_NOTSENT_LOWAT returned %d", errno);
        mDNSPlatformTCPCloseConnection(sock);
        goto fail;
    }

    LogMsg("DSOConnectCallback: Attempting to connect to %#a%%%d", &cs->addr, ntohs(*pport));

    status = mDNSPlatformTCPConnect(sock, &cs->addr, port, NULL, dsoConnectCallback, cs);
    if (status == mStatus_NoError || status == mStatus_ConnEstablished) {
        goto success;
    } else if (status == mStatus_ConnPending) {
        // We should get called back when the connection succeeds or fails.
        return;
    }
    LogMsg("dsoConnectCallback: failed to connect to %s: %s%s", cs->host, strerror(errno), detail);
    goto fail;
}

mDNSexport mDNSBool DSOConnect(DSOConnectState *cs)
{
    int rc;
    
    // Note that this blocks, which is bad, and needs to be fixed.
    rc = getaddrinfo(cs->host, NULL, NULL, &cs->ai);
    if (rc < 0) {
        LogMsg("DSOConnect: resolution on %s failed for %s: %s", cs->host, cs->detail, strerror(errno));
        return mDNSfalse;
    }   
    cs->aip = cs->ai;
    dsoConnectCallback(NULL, cs, mDNSfalse, mStatus_NoError);
    return mDNStrue;
}

// Called whenever we get a connection on the DNS TCP socket
mDNSlocal void dsoListenCallback(int fd, short filter, void *context, mDNSBool encounteredEOF)
{
    struct sockaddr_in6 sin6;
    socklen_t slen = sizeof sin6;
    int remoteSock;
    mDNSAddr_Type addrFamily;
    TCPSocket *sock;
    DSOState *dso;
    int failed;
    int lowat = 32768; // XXX this should really be the BDP, not pulled out of a hat.
                       // Worst case scenario, we could block because we picked a too-large low water mark.
    char namebuf[INET6_ADDRSTRLEN + 1 + 5 + 1];
    char *nbp;
    int i;
    DSOConnectState *lc = context;
    
    (void)fd; // Unused
    (void)filter; // Unused
    (void)encounteredEOF; // Unused
    
    remoteSock = accept(lc->sock, (struct sockaddr *)&sin6, &slen);
    if (remoteSock < 0) {
        LogMsg("dsoListenCallback: accept returned %d", remoteSock);
        goto out;
    }

    failed = fcntl(remoteSock, F_SETFL, O_NONBLOCK);
    if (failed < 0) {
        close(remoteSock);
        LogMsg("dsoListenCallback: fcntl returned %d", errno);
        goto out;
    }

    failed = setsockopt(remoteSock, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowat, sizeof lowat);
    if (failed < 0) {
        close(remoteSock);
        LogMsg("dsoListenCallback: TCP_NOTSENT_LOWAT returned %d", errno);
        goto out;
    }

    // Is this an IPv4-in-IPv6 address?
    addrFamily = mDNSAddrType_IPv4;
    for (i = 0; i < 10; i++) {
        if (sin6.sin6_addr.s6_addr[i] != 0) {
            addrFamily = mDNSAddrType_IPv6;
            goto nope;
        }
    }
    if (sin6.sin6_addr.s6_addr[10] != 0xFF || sin6.sin6_addr.s6_addr[11] != 0xFF) {
        addrFamily = mDNSAddrType_IPv6;
    }
nope:
	if (addrFamily == mDNSAddrType_IPv6) {
		if (inet_ntop(sin6.sin6_family, &sin6.sin6_addr, namebuf, INET6_ADDRSTRLEN + 1) == NULL) {
			strcpy(namebuf, ":unknown:");
		}
	} else {
		if (inet_ntop(AF_INET, &sin6.sin6_addr.s6_addr[12], namebuf, INET6_ADDRSTRLEN + 1) == NULL) {
			strcpy(namebuf, ":unknown:");
		}
	}		
	nbp = namebuf + strlen(namebuf);
	*nbp++ = '%';
	snprintf(nbp, 6, "%u", ntohs(sin6.sin6_port));

	sock = mDNSPlatformTCPAccept(kTCPSocketFlags_Zero, remoteSock);
	if (sock == NULL) {
		LogMsg("dsoListenCallback: mDNSPlatformTCPAccept returned NULL; dropping connection from %s", namebuf);
		close(remoteSock);
		goto out;
	}

	dso = dsoCreate(sock, mDNStrue, lc->context, lc->numOutstandingQueries,
					lc->inbufsize, lc->outbufsize, namebuf, lc->callback);
	if (dso == NULL) {
		mDNSPlatformTCPCloseConnection(sock);
		LogMsg("No memory for new DSO connection from %s", namebuf);
		goto out;
	}

	dso->remoteAddr.type = addrFamily;
	if (addrFamily == mDNSAddrType_IPv4) {
		memcpy(dso->remoteAddr.ip.v4.b, &sin6.sin6_addr.s6_addr[12], 4);
	} else {
		memcpy(dso->remoteAddr.ip.v6.b, sin6.sin6_addr.s6_addr, 16);
	}
	dso->remotePort = ntohs(sin6.sin6_port);
	if (dso->cb) {
		dso->cb(lc->context, 0, dso, kDSO_EventType_Connected);
	}
	LogMsg("DSO connection from %s", dso->remoteName);
out:
    ;
}

// Listen for connections; each time we get a connection, make a new DSOState object with the specified
// parameters and call the callback.   Port can be zero to leave it unspecified.

mDNSexport mStatus DSOListen(DSOConnectState *listenContext)
{
    struct sockaddr_in6 sin6;
    int failed;
    mStatus status;

    // Set up DNS listener socket
    listenContext->sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listenContext->sock < 0) {
		LogMsg("mDNSRelay: socket call failed %d", errno);
		return mStatus_TransientErr; // we hope!
	}

	// If we've been given a listen port, use SO_REUSEADDR so that we don't get stymied by
	// an old connection.
	if (listenContext->configPort) {
		int one = 1;
		failed = setsockopt(listenContext->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		if (failed < 0) {
			LogMsg("mDNSRelay: SO_REUSEADDR failed %d", errno);
		fail:
			close(listenContext->sock);
			listenContext->sock = -1;
			return mStatus_TransientErr;
		}
	}
	
	// Bind to INADDR_ANY on the specified listen port.
	memset(&sin6, 0, sizeof sin6);
	sin6.sin6_port = htons(listenContext->configPort);
	sin6.sin6_family = AF_INET6;
	failed = bind(listenContext->sock, (struct sockaddr *)&sin6, sizeof sin6);
	if (failed < 0) {
		LogMsg("mDNSRelay: bind failed %d", errno);
		goto fail;
	}

	// If there was no specified listen port, we need to know what port we got.
	if (listenContext->configPort) { 
		listenContext->connectPort = listenContext->configPort;
	} else {
		socklen_t slen = sizeof sin6;
		failed = getsockname(listenContext->sock, (struct sockaddr *)&sin6, &slen);
		if (failed < 0) {
			LogMsg("mDNSRelay: getsockname failed %d", errno);
			goto fail;
		}
		listenContext->connectPort = ntohs(sin6.sin6_port);
	}
	failed = listen(listenContext->sock, 5);
	
	LogMsg("DSOListen: Listening on %#a%%%d", &sin6.sin6_addr, listenContext->connectPort);
	
	// When we get a connection, dsoListenCallback will be called.
	status = mDNSPlatformRequestReadEvents(listenContext->sock, "mDNSRelay::dsoListenCallback",
										   dsoListenCallback, listenContext, listenContext->eventContext);
	if (status) {
		LogMsg("DSOListen: mDNSRequestReadEvents returned %d", status);
		goto fail;
	}
	return mStatus_NoError;
}

#ifdef REALLY_FUSSY_MALLOC_DEBUG
// Just in case we want to find a malloc bug and the system library isn't giving us what we need.
typedef struct mymalloc_hunk {
    size_t length;
    unsigned guard;
    struct mymalloc_hunk *next;
} MyMallocHunk;

// This would be pathetically inefficient if we did a lot of mallocs, but we don't.
MyMallocHunk *myMallocHunkChain;

#undef malloc
#undef free
#undef calloc
#undef strdup

mDNSexport void *mycalloc(size_t count, size_t size)
{
    void *data = mymalloc(count * size);
    if (data != NULL)
        memset(data, 0, count * size);
    return data;
}

mDNSexport char *mystrdup(const char *str)
{
    size_t len = strlen(str);
    char *nstr = mymalloc(len + 1);
    if (nstr != NULL)
        strcpy(nstr, str);
    return nstr;
}
    
mDNSlocal void mymalloc_hunk_chain_validate(MyMallocHunk *find)
{
    MyMallocHunk **phunk = &myMallocHunkChain;

    while (*phunk) {
        MyMallocHunk *hunk = *phunk;
        if (hunk->length != hunk[hunk->length + 1].length ||
            hunk->guard != 0xDEADBEEF || hunk[hunk->length + 1].guard != 0xFEEDCAFE) {
            LogMsg("mymalloc_hunk_chain_validate encountered a hunk with smashed boundaries");
            assert(0);
        }
        if (hunk == find) {
            *phunk = hunk->next;
        } else {
            phunk = &hunk->next;
        }
    }
}
    
mDNSexport void *mymalloc(size_t length)
{
    size_t extra = (sizeof (MyMallocHunk)) - (length % sizeof (MyMallocHunk));
    MyMallocHunk *hunk;

    mymalloc_hunk_chain_validate(NULL);
    hunk = malloc(length + extra + 2 * sizeof (MyMallocHunk));
    if (hunk == NULL)
        return hunk;
    hunk->length = (length + extra) / sizeof (MyMallocHunk);
    hunk->guard = 0xDEADBEEF;
    hunk[hunk->length + 1].length = hunk->length;
    hunk[hunk->length + 1].guard = 0xFEEDCAFE;
    hunk->next = myMallocHunkChain;
    myMallocHunkChain = hunk;
    LogMsg("mymalloc: hunk length %d at %p", hunk->length * sizeof (MyMallocHunk), hunk);
    return (void *)(hunk + 1);
}

mDNSexport void myfree(void *hunkv)
{
    MyMallocHunk *hunk;

    hunk = hunkv;
    hunk--;
    LogMsg("myfree:   hunk length %d %d at %p guards %x %x",
           hunk->length * sizeof (MyMallocHunk), hunk[hunk->length + 1].length * sizeof (MyMallocHunk),
           hunk, hunk->guard, hunk[hunk->length + 1].guard);
    if (hunk->guard == 0xFACEDEED) {
        LogMsg("myfree called on the same object twice.");
        assert(0);
    }
    mymalloc_hunk_chain_validate(hunk);
    hunk->guard = 0xFACEDEED;
    hunk[hunk->length + 1].guard = 0xDECADDED;
    free(hunk);
}
#endif
