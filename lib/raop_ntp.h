//
// Created by Florian Draschbacher on 2019-04-27.
//

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
