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
// General purpose stupid little parser, currently used by mDNSRelay for its configuration file and
// by mDNSResponder for its config file; obviously this second use case isn't the right long term solution
// on MacOSX and probably the first use case isn't either, but for now both the responder and the relay
// use /etc/mdnsproxy.cf and /etc/mdnsrelay.cf.

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

#include "cfParse.h"

// Parse one line of a config file.
// A line consists of a verb followed by one or more hunks of text.
// We parse the verb first, then that tells us how many hunks of text to expect.
// Each hunk is space-delineated; the last hunk can contain spaces.
mDNSlocal mDNSBool cfParseLine(void *context, const char *cfName, char *line, int lineno, ConfigFileVerb *verbs, int numVerbs)
{
	char *sp;
#define MAXCFHUNKS 5
	char *hunks[MAXCFHUNKS];
	int numHunks = 0;
	ConfigFileVerb *cfVerb = NULL;
	int i;

	sp = line;
	do {
		// Skip leading spaces.
		while (*sp && (*sp == ' ' || *sp == '\t'))
			sp++;
		if (numHunks == 0) {
			// If this is a blank line with spaces on it or a comment line, we ignore it.
			if (!*sp || *sp == '#')
				return mDNStrue;
		}
		hunks[numHunks++] = sp;
		// Find EOL or hunk
		while (*sp && (*sp != ' ' && *sp != '\t')) {
			sp++;
		}
		if (*sp) {
			*sp++ = 0;
		}
		if (numHunks == 1) {
			for (i = 0; i < numVerbs; i++) {
				if (!strcmp(verbs[i].name, hunks[0]))
					cfVerb = &verbs[i];
			}
			if (cfVerb == NULL) {
				LogMsg("cfParseLine: unknown verb %s at line %d", hunks[0], lineno);
				return mDNSfalse;
			}
		}				
	} while (*sp && numHunks < MAXCFHUNKS && cfVerb->maxHunks > numHunks);
	
	// If we didn't get the hunks we needed, bail.
	if (cfVerb->minHunks > numHunks) {
		LogMsg("cfParseLine: error: verb %s requires between %d and %d modifiers; %d given at line %d",
			   hunks[0], cfVerb->minHunks, cfVerb->maxHunks, numHunks, lineno);
		return mDNSfalse;
	}

	return cfVerb->handler(context, cfName, hunks, numHunks, lineno);
}

// Parse a configuration file
mDNSexport mDNSBool cfParse(void *context, const char *cfName, ConfigFileVerb *verbs, int numVerbs)
{
	int file;
	char *buf, *line, *eof, *eol, *nextCR, *nextNL;
	off_t flen, have;
    ssize_t len;
    int lineno;
	mDNSBool success = mDNStrue;

	file = open(cfName, O_RDONLY);
	if (file < 0) {
		LogMsg("cfParse: fatal: %s: %s", cfName, strerror(errno));
		return mDNSfalse;
	}

	// Get the length of the file.
	flen = lseek(file, 0, SEEK_END);
	lseek(file, 0, SEEK_SET);
	buf = malloc(flen + 1);
	if (buf == NULL) {
		LogMsg("cfParse: fatal: not enough memory for %s", cfName);
		goto outclose;
	}
	
	// Just in case we have a read() syscall that doesn't always read the whole file at once
	have = 0;
	while (have < flen) {
		len = read(file, &buf[have], flen - have);
		if (len < 0) {
			LogMsg("cfParse: fatal: read of %s at %d len %d: %s", cfName, have, flen - have, strerror(errno));
			goto outfree;
		}
		if (len == 0) {
			LogMsg("cfParse: fatal: read of %s at %d len %d: zero bytes read", cfName, have, flen - have);
		outfree:
			free(buf);
		outclose:
			close(file);
			return mDNSfalse;
		}
		have += len;
	}
	close(file);
	buf[flen] = 0; // NUL terminate.
	eof = buf + flen;
	
	// Parse through the file line by line.
	line = buf;
	lineno = 1;
	while (line < eof) { // < because NUL at eof could be last eol.
		nextCR = strchr(line, '\r');
		nextNL = strchr(line, '\n');

		// Added complexity for CR/LF agnostic line endings.   Necessary?
		if (nextNL != NULL) {
			if (nextCR != NULL && nextCR < nextNL)
				eol = nextCR;
			else
				eol = nextNL;
		} else {
			if (nextCR != NULL)
				eol = nextCR;
			else
				eol = buf + flen;
		}

		// If this isn't a blank line or a comment line, parse it.
		if (eol - line != 1 && line[0] != '#') {
			*eol = 0;
			// If we get a bad config line, we're going to return failure later, but continue parsing now.
			if (!cfParseLine(context, cfName, line, lineno, verbs, numVerbs))
				success = mDNSfalse;
        }
        line = eol + 1;
        lineno++;
	}		
	free(buf);
	return success;
}

