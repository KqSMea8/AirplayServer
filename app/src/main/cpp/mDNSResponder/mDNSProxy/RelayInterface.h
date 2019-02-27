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

#ifndef __RelayInterface_h
#define __RelayInterface_h

// This header defines the public API of the RelayInterface code, which is consumed by mDNSResponder.
// Private stuff is in RelayProtocol.h.

mDNSexport void rciEnumerateInterfaces(mDNS *m, mDNSs32 utc,
									   int (*ifsetup)(mDNS *const m, mDNSAddr *addr, mDNSAddr *mask,
													  struct sockaddr *intfAddr, char *name,
													  int index, mDNSs32 utc, void *link));
mDNSexport mStatus rciSendMessage(const void *const msg, const mDNSu8 *const end, void *linkv);
mDNSexport void rciInit(mDNS *const m);
mDNSexport mDNSs32 rciIdle(mDNS *const m, mDNSs32 nextTimerEvent);
#endif // __RelayInterface_h
