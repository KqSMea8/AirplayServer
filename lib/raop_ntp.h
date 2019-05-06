/*
 * Copyright (c) 2019 dsafa22, modified by Florian Draschbacher,
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef RAOP_NTP_H
#define RAOP_NTP_H

#include "logger.h"

typedef struct raop_ntp_s raop_ntp_t;

raop_ntp_t *raop_ntp_init(logger_t *logger, const unsigned char *remote_addr, int remote_addr_len, unsigned short timing_rport);

void raop_ntp_start(raop_ntp_t *raop_ntp, unsigned short *timing_lport);

void raop_ntp_stop(raop_ntp_t *raop_ntp);

unsigned short raop_ntp_get_port(raop_ntp_t *raop_ntp);

void raop_ntp_destroy(raop_ntp_t *raop_rtp);

#endif //RAOP_NTP_H
