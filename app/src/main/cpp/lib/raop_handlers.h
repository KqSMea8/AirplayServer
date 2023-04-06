/**
 *  Copyright (C) 2018  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include "plist/plist/plist.h"
#include <ctype.h>
#include <stdlib.h>
/* This file should be only included from raop.c as it defines static handler
 * functions and depends on raop internals */

typedef void (*raop_handler_t)(raop_conn_t *, http_request_t *,
                               http_response_t *, char **, int *);

static void
raop_handler_info(raop_conn_t *conn,
					   http_request_t *request, http_response_t *response,
					   char **response_data, int *response_datalen)
{
	const char *data;
	int datalen;
	data = http_request_get_data(request, &datalen);

	char info[] = {0x62,0x70,0x6c,0x69,0x73,0x74,0x30,0x30,0x10,0x0e,0x12,0x01,0xff,0xff,0xfc,0x59
			,0x61,0x75,0x64,0x69,0x6f,0x54,0x79,0x70,0x65,0xdf,0x10,0x0f,0x01,0x03,0x05,0x07
			,0x08,0x0a,0x0c,0x0e,0x0f,0x11,0x1b,0x24,0x26,0x28,0x2a,0x02,0x04,0x06,0x06,0x09
			,0x0b,0x0d,0x0d,0x10,0x12,0x1c,0x25,0x27,0x29,0x2b,0x54,0x74,0x79,0x70,0x65,0x58
			,0x64,0x69,0x73,0x70,0x6c,0x61,0x79,0x73,0x54,0x75,0x75,0x69,0x64,0x5f,0x10,0x11
			,0x61,0x75,0x64,0x69,0x6f,0x49,0x6e,0x70,0x75,0x74,0x46,0x6f,0x72,0x6d,0x61,0x74
			,0x73,0x58,0x66,0x65,0x61,0x74,0x75,0x72,0x65,0x73,0x5b,0x72,0x65,0x66,0x72,0x65
			,0x73,0x68,0x52,0x61,0x74,0x65,0xd4,0x1e,0x20,0x22,0x16,0x1f,0x21,0x21,0x1a,0x5f
			,0x10,0x11,0x61,0x61,0x3a,0x35,0x34,0x3a,0x30,0x31,0x3a,0x61,0x66,0x3a,0x63,0x33
			,0x3a,0x63,0x31,0x10,0x1e,0x10,0x64,0x55,0x6d,0x6f,0x64,0x65,0x6c,0x10,0x3c,0x56
			,0x68,0x65,0x69,0x67,0x68,0x74,0x5a,0x41,0x70,0x70,0x6c,0x65,0x54,0x56,0x32,0x2c
			,0x31,0x5d,0x73,0x6f,0x75,0x72,0x63,0x65,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x5f
			,0x10,0x11,0x6b,0x65,0x65,0x70,0x41,0x6c,0x69,0x76,0x65,0x4c,0x6f,0x77,0x50,0x6f
			,0x77,0x65,0x72,0xdc,0x2d,0x2f,0x31,0x32,0x33,0x34,0x35,0x36,0x28,0x39,0x3b,0x3c
			,0x2e,0x30,0x21,0x21,0x21,0x30,0x2e,0x37,0x38,0x3a,0x21,0x3d,0x5d,0x77,0x69,0x64
			,0x74,0x68,0x50,0x68,0x79,0x73,0x69,0x63,0x61,0x6c,0x56,0x32,0x32,0x30,0x2e,0x36
			,0x38,0xd3,0x14,0x16,0x18,0x15,0x17,0x15,0x5b,0x6f,0x76,0x65,0x72,0x73,0x63,0x61
			,0x6e,0x6e,0x65,0x64,0x5b,0x77,0x69,0x64,0x74,0x68,0x50,0x69,0x78,0x65,0x6c,0x73
			,0x4f,0x10,0x20,0xb0,0x77,0x27,0xd6,0xf6,0xcd,0x6e,0x08,0xb5,0x8e,0xde,0x52,0x5e
			,0xc3,0xcd,0xea,0xa2,0x52,0xad,0x9f,0x68,0x3f,0xeb,0x21,0x2e,0xf8,0xa2,0x05,0x24
			,0x65,0x54,0xe7,0x5a,0x6d,0x61,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73,0x10,0x02
			,0xa1,0x2c,0x10,0x04,0xa2,0x13,0x19,0x5c,0x61,0x75,0x64,0x69,0x6f,0x46,0x6f,0x72
			,0x6d,0x61,0x74,0x73,0x54,0x6e,0x61,0x6d,0x65,0x08,0x52,0x76,0x76,0x13,0x00,0x00
			,0x00,0x1e,0x5a,0x7f,0xff,0xf7,0x5f,0x10,0x12,0x69,0x6e,0x70,0x75,0x74,0x4c,0x61
			,0x74,0x65,0x6e,0x63,0x79,0x4d,0x69,0x63,0x72,0x6f,0x73,0x5b,0x73,0x74,0x61,0x74
			,0x75,0x73,0x46,0x6c,0x61,0x67,0x73,0x57,0x41,0x70,0x70,0x6c,0x65,0x54,0x56,0xd4
			,0x1e,0x20,0x22,0x16,0x1f,0x21,0x21,0x17,0x57,0x64,0x65,0x66,0x61,0x75,0x6c,0x74
			,0x5f,0x10,0x24,0x32,0x65,0x33,0x38,0x38,0x30,0x30,0x36,0x2d,0x31,0x33,0x62,0x61
			,0x2d,0x34,0x30,0x34,0x31,0x2d,0x39,0x61,0x36,0x37,0x2d,0x32,0x35,0x64,0x64,0x34
			,0x61,0x34,0x33,0x64,0x35,0x33,0x36,0xd3,0x14,0x16,0x18,0x15,0x1a,0x15,0x5f,0x10
			,0x13,0x6f,0x75,0x74,0x70,0x75,0x74,0x4c,0x61,0x74,0x65,0x6e,0x63,0x79,0x4d,0x69
			,0x63,0x72,0x6f,0x73,0x5e,0x61,0x75,0x64,0x69,0x6f,0x4c,0x61,0x74,0x65,0x6e,0x63
			,0x69,0x65,0x73,0x58,0x72,0x6f,0x74,0x61,0x74,0x69,0x6f,0x6e,0x10,0x01,0x5c,0x68
			,0x65,0x69,0x67,0x68,0x74,0x50,0x69,0x78,0x65,0x6c,0x73,0x56,0x6d,0x61,0x78,0x46
			,0x50,0x53,0x58,0x64,0x65,0x76,0x69,0x63,0x65,0x49,0x44,0x5f,0x10,0x12,0x61,0x75
			,0x64,0x69,0x6f,0x4f,0x75,0x74,0x70,0x75,0x74,0x46,0x6f,0x72,0x6d,0x61,0x74,0x73
			,0x5f,0x10,0x24,0x65,0x30,0x66,0x66,0x38,0x61,0x32,0x37,0x2d,0x36,0x37,0x33,0x38
			,0x2d,0x33,0x64,0x35,0x36,0x2d,0x38,0x61,0x31,0x36,0x2d,0x63,0x63,0x35,0x33,0x61
			,0x61,0x63,0x65,0x65,0x39,0x32,0x35,0x5f,0x10,0x18,0x6b,0x65,0x65,0x70,0x41,0x6c
			,0x69,0x76,0x65,0x53,0x65,0x6e,0x64,0x53,0x74,0x61,0x74,0x73,0x41,0x73,0x42,0x6f
			,0x64,0x79,0x5e,0x68,0x65,0x69,0x67,0x68,0x74,0x50,0x68,0x79,0x73,0x69,0x63,0x61
			,0x6c,0x10,0x65,0x55,0x77,0x69,0x64,0x74,0x68,0x52,0x70,0x69,0x52,0x70,0x6b,0xa2
			,0x1d,0x23,0x11,0x04,0x38,0x11,0x07,0x80,0x00,0x19,0x00,0xb1,0x00,0xfa,0x01,0x8b
			,0x01,0x52,0x01,0x43,0x00,0x7f,0x02,0x22,0x01,0x64,0x01,0x97,0x01,0x6a,0x01,0x4e
			,0x00,0xbf,0x02,0x0c,0x02,0x67,0x02,0x99,0x01,0xb0,0x01,0x57,0x01,0x54,0x01,0x01
			,0x02,0x2b,0x00,0x0a,0x00,0x3a,0x00,0x95,0x00,0x4d,0x01,0xd7,0x02,0x91,0x01,0xf4
			,0x02,0x9f,0x01,0x9f,0x00,0x0f,0x01,0xa8,0x01,0x76,0x01,0x69,0x01,0xde,0x00,0x76
			,0x02,0x9c,0x01,0x20,0x00,0x97,0x00,0xa6,0x00,0x61,0x01,0x6d,0x00,0x3f,0x01,0x50
			,0x00,0xd3,0x00,0x9f,0x02,0xa2,0x02,0x93,0x02,0xa5,0x02,0x03,0x00,0xec,0x02,0x82
			,0x01,0x14,0x02,0x0e,0x00,0x6a,0x00,0x9d,0x00,0x08,0x02,0x1b,0x00,0x93,0x01,0x08
			,0x00,0x48,0x02,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x01,0x00,0x00,0x00,0x00
			,0x00,0x00,0x00,0x3e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
			,0x00,0x00,0x02,0xa8
	};
	size_t len = sizeof(info);
	*response_data = malloc(len);
	memcpy(*response_data, info, len);
	if (*response_data) {
        http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
        //http_response_add_header(response, "Date", "Sun, 27 Jan 2019 10:32:17 GMT");
		*response_datalen = len;
	}
}

static void
raop_handler_pairsetup(raop_conn_t *conn,
                       http_request_t *request, http_response_t *response,
                       char **response_data, int *response_datalen)
{
	unsigned char public_key[32];
	const char *data;
	int datalen;

	data = http_request_get_data(request, &datalen);
	if (datalen != 32) {
		logger_log(conn->raop->logger, LOGGER_ERR, "Invalid pair-setup data");
		return;
	}

	pairing_get_public_key(conn->raop->pairing, public_key);
    pairing_session_set_setup_status(conn->pairing);

	*response_data = malloc(sizeof(public_key));
	if (*response_data) {
		http_response_add_header(response, "Content-Type", "application/octet-stream");
		memcpy(*response_data, public_key, sizeof(public_key));
		*response_datalen = sizeof(public_key);
	}
}

static void
raop_handler_pairverify(raop_conn_t *conn,
                        http_request_t *request, http_response_t *response,
                        char **response_data, int *response_datalen)
{
    if (pairing_session_check_handshake_status(conn->pairing)) {
        return;
    }
	unsigned char public_key[32];
	unsigned char signature[64];
	const unsigned char *data;
	int datalen;

	data = (unsigned char *) http_request_get_data(request, &datalen);
	if (datalen < 4) {
		logger_log(conn->raop->logger, LOGGER_ERR, "Invalid pair-verify data");
		return;
	}
	switch (data[0]) {
	case 1:
		if (datalen != 4 + 32 + 32) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Invalid pair-verify data");
			return;
		}
		/* We can fall through these errors, the result will just be garbage... */
		if (pairing_session_handshake(conn->pairing, data + 4, data + 4 + 32)) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Error initializing pair-verify handshake");
		}
		if (pairing_session_get_public_key(conn->pairing, public_key)) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Error getting ECDH public key");
		}
		if (pairing_session_get_signature(conn->pairing, signature)) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Error getting ED25519 signature");
		}
		*response_data = malloc(sizeof(public_key) + sizeof(signature));
		if (*response_data) {
			http_response_add_header(response, "Content-Type", "application/octet-stream");
			memcpy(*response_data, public_key, sizeof(public_key));
			memcpy(*response_data + sizeof(public_key), signature, sizeof(signature));
			*response_datalen = sizeof(public_key) + sizeof(signature);
		}
		break;
	case 0:
		if (datalen != 4 + 64) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Invalid pair-verify data");
			return;
		}

		if (pairing_session_finish(conn->pairing, data + 4)) {
			logger_log(conn->raop->logger, LOGGER_ERR, "Incorrect pair-verify signature");
			http_response_set_disconnect(response, 1);
			return;
		}
        http_response_add_header(response, "Content-Type", "application/octet-stream");
		break;
	}
}

static void
raop_handler_fpsetup(raop_conn_t *conn,
                        http_request_t *request, http_response_t *response,
                        char **response_data, int *response_datalen)
{
	const unsigned char *data;
	int datalen;

	data = (unsigned char *) http_request_get_data(request, &datalen);
	if (datalen == 16) {
		*response_data = malloc(142);
		if (*response_data) {
            http_response_add_header(response, "Content-Type", "application/octet-stream");
			if (!fairplay_setup(conn->fairplay, data, (unsigned char *) *response_data)) {
				*response_datalen = 142;
			} else {
				// Handle error?
				free(*response_data);
				*response_data = NULL;
			}
		}
	} else if (datalen == 164) {
		*response_data = malloc(32);
		if (*response_data) {
            http_response_add_header(response, "Content-Type", "application/octet-stream");
			if (!fairplay_handshake(conn->fairplay, data, (unsigned char *) *response_data)) {
				*response_datalen = 32;
			} else {
				// Handle error?
				free(*response_data);
				*response_data = NULL;
			}
		}
	} else {
		logger_log(conn->raop->logger, LOGGER_ERR, "Invalid fp-setup data length");
		return;
	}
}

static void
raop_handler_options(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen)
{
	http_response_add_header(response, "Public", "SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER");
}

static int setup = 0;

static void
raop_handler_setup(raop_conn_t *conn,
                   http_request_t *request, http_response_t *response,
                   char **response_data, int *response_datalen)
{
    unsigned short remote_cport=0, remote_tport=0;

    const char *transport;
    char buffer[1024];
    int use_udp;
    const char *dacp_id;
    const char *active_remote_header;

    const char *data;
    int datalen;

    data = http_request_get_data(request, &datalen);

    dacp_id = http_request_get_header(request, "DACP-ID");
    active_remote_header = http_request_get_header(request, "Active-Remote");

    if (dacp_id && active_remote_header) {
        logger_log(conn->raop->logger, LOGGER_DEBUG, "DACP-ID: %s", dacp_id);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "Active-Remote: %s", active_remote_header);
        if (conn->raop_rtp) {
            raop_rtp_remote_control_id(conn->raop_rtp, dacp_id, active_remote_header);
        }
    }

    transport = http_request_get_header(request, "Transport");
    if (transport) {
        logger_log(conn->raop->logger, LOGGER_INFO, "Transport: %s", transport);
        use_udp = strncmp(transport, "RTP/AVP/TCP", 11);
    } else {
        logger_log(conn->raop->logger, LOGGER_INFO, "Transport: null");
        use_udp = 0;
    }


    // Parsing bplist
    plist_t root_node = NULL;
    plist_from_bin(data, datalen, &root_node);
    plist_t streams_note = plist_dict_get_item(root_node, "streams");
    if (setup == 0) {
		unsigned char aesiv[16];
		unsigned char aeskey[16];
        setup++;
        logger_log(conn->raop->logger, LOGGER_DEBUG, "SETUP 1");
        // First setup
        plist_t eiv_note = plist_dict_get_item(root_node, "eiv");
        char* eiv= NULL;
        uint64_t eiv_len = 0;
        plist_get_data_val(eiv_note, &eiv, &eiv_len);
        memcpy(aesiv, eiv, 16);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "eiv_len = %llu", eiv_len);
        plist_t ekey_note = plist_dict_get_item(root_node, "ekey");
        char* ekey= NULL;
        uint64_t ekey_len = 0;
        plist_get_data_val(ekey_note, &ekey, &ekey_len);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "ekey_len = %llu", ekey_len);
        // Time port
		uint64_t timing_rport;
        plist_t time_note = plist_dict_get_item(root_node, "timingPort");
        plist_get_uint_val(time_note, &timing_rport);
		logger_log(conn->raop->logger, LOGGER_DEBUG, "timing_rport = %llu", timing_rport);
        // ekey is 72 bytes
        int ret = fairplay_decrypt(conn->fairplay, ekey, aeskey);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "fairplay_decrypt ret = %d", ret);
		unsigned char ecdh_secret[32];
        pairing_get_ecdh_secret_key(conn->pairing, ecdh_secret);
        conn->raop_rtp = raop_rtp_init(conn->raop->logger, &conn->raop->callbacks, conn->remote, conn->remotelen, aeskey, aesiv, ecdh_secret, timing_rport);
		conn->raop_rtp_mirror = raop_rtp_mirror_init(conn->raop->logger, &conn->raop->callbacks, conn->remote, conn->remotelen, aeskey, ecdh_secret, timing_rport);
    } else if (setup == 1) {
		unsigned short tport=0, dport=0;
        setup++;
        logger_log(conn->raop->logger, LOGGER_DEBUG, "SETUP 2");
		plist_t stream_note = plist_array_get_item(streams_note, 0);
		plist_t type_note = plist_dict_get_item(stream_note, "type");
        uint64_t type;
        plist_get_uint_val(type_note, &type);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "type = %llu", type);
		plist_t stream_id_note = plist_dict_get_item(stream_note, "streamConnectionID");
		uint64_t streamConnectionID;
		plist_get_uint_val(stream_id_note, &streamConnectionID);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "streamConnectionID = %llu", streamConnectionID);


        if (conn->raop_rtp_mirror) {
			raop_rtp_init_mirror_aes(conn->raop_rtp_mirror, streamConnectionID);
			raop_rtp_start_mirror(conn->raop_rtp_mirror, use_udp, remote_tport, &tport, &dport);
            logger_log(conn->raop->logger, LOGGER_DEBUG, "RAOP initialized success");
        } else {
            logger_log(conn->raop->logger, LOGGER_ERR, "RAOP not initialized at SETUP, playing will fail!");
            http_response_set_disconnect(response, 1);
        }
        plist_t r_node = plist_new_dict();
        plist_t s_node = plist_new_array();
        plist_t s_sub_node = plist_new_dict();
        plist_t data_port_node = plist_new_uint(dport);
        plist_t type_node = plist_new_uint(110);
        plist_t event_port_node = plist_new_uint(conn->raop->port);
        plist_t timing_port_node = plist_new_uint(tport);
        plist_dict_set_item(s_sub_node, "dataPort", data_port_node);
        plist_dict_set_item(s_sub_node, "type", type_node);
        plist_array_append_item(s_node, s_sub_node);
        plist_dict_set_item(r_node, "eventPort", event_port_node);
        plist_dict_set_item(r_node, "timingPort", timing_port_node);
        plist_dict_set_item(r_node, "streams", s_node);
        uint32_t len = 0;
        char* rsp = NULL;
        plist_to_bin(r_node, &rsp, &len);
        logger_log(conn->raop->logger, LOGGER_DEBUG, "SETUP 2 len = %d", len);
        http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
        *response_data = malloc(len);
        memcpy(*response_data, rsp, len);
        *response_datalen = len;
        logger_log(conn->raop->logger, LOGGER_INFO, "dport = %d, tport = %d", dport, tport);
    } else {
        logger_log(conn->raop->logger, LOGGER_DEBUG, "SETUP 3");
        unsigned short cport = 0, tport = 0, dport = 0;

        if (conn->raop_rtp) {
            raop_rtp_start_audio(conn->raop_rtp, use_udp, remote_cport, remote_tport, &cport, &tport, &dport);
            logger_log(conn->raop->logger, LOGGER_DEBUG, "RAOP initialized success");
        } else {
            logger_log(conn->raop->logger, LOGGER_ERR, "RAOP not initialized at SETUP, playing will fail!");
            http_response_set_disconnect(response, 1);
        }
        // Need to return port
		/**
		 * <dict>
	<key>streams</key>
	<array>
		<dict>
			<key>dataPort</key>
			<integer>42820</integer>
			<key>controlPort</key>
			<integer>46440</integer>
			<key>type</key>
			<integer>96</integer>
		</dict>
	</array>

	<key>timingPort</key>
	<integer>46440</integer>
</dict>
</plist>
		 */
		plist_t r_node = plist_new_dict();
		plist_t s_node = plist_new_array();
		plist_t s_sub_node = plist_new_dict();
		plist_t data_port_node = plist_new_uint(dport);
		plist_t type_node = plist_new_uint(96);
		plist_t control_port_node = plist_new_uint(cport);
		plist_t timing_port_node = plist_new_uint(tport);
		plist_dict_set_item(s_sub_node, "dataPort", data_port_node);
		plist_dict_set_item(s_sub_node, "type", type_node);
		plist_dict_set_item(s_sub_node, "controlPort", control_port_node);
		plist_array_append_item(s_node, s_sub_node);
		plist_dict_set_item(r_node, "timingPort", timing_port_node);
		plist_dict_set_item(r_node, "streams", s_node);
		uint32_t len = 0;
		char* rsp = NULL;
		plist_to_bin(r_node, &rsp, &len);
		logger_log(conn->raop->logger, LOGGER_DEBUG, "SETUP 3 len = %d", len);
		http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
		*response_data = malloc(len);
		memcpy(*response_data, rsp, len);
		*response_datalen = len;

		logger_log(conn->raop->logger, LOGGER_INFO, "dport = %d, tport = %d, cport = %d", dport, tport, cport);
    }

}

static void
raop_handler_get_parameter(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen)
{
	const char *content_type;
	const char *data;
	int datalen;

	content_type = http_request_get_header(request, "Content-Type");
	data = http_request_get_data(request, &datalen);
	if (!strcmp(content_type, "text/parameters")) {
		const char *current = data;

		while (current) {
			const char *next;
			int handled = 0;

			/* This is a bit ugly, but seems to be how airport works too */
			if (!strncmp(current, "volume\r\n", 8)) {
				const char volume[] = "volume: 0.0\r\n";

				http_response_add_header(response, "Content-Type", "text/parameters");
				*response_data = strdup(volume);
				if (*response_data) {
					*response_datalen = strlen(*response_data);
				}
				handled = 1;
			}

			next = strstr(current, "\r\n");
			if (next && !handled) {
				logger_log(conn->raop->logger, LOGGER_WARNING,
				           "Found an unknown parameter: %.*s", (next - current), current);
				current = next + 2;
			} else if (next) {
				current = next + 2;
			} else {
				current = NULL;
			}
		}
	}
}

static void
raop_handler_set_parameter(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen)
{
	const char *content_type;
	const char *data;
	int datalen;

	content_type = http_request_get_header(request, "Content-Type");
	data = http_request_get_data(request, &datalen);
	if (!strcmp(content_type, "text/parameters")) {
		char *datastr;
		datastr = calloc(1, datalen+1);
		if (data && datastr && conn->raop_rtp) {
			memcpy(datastr, data, datalen);
			if (!strncmp(datastr, "volume: ", 8)) {
				float vol = 0.0;
				sscanf(datastr+8, "%f", &vol);
				raop_rtp_set_volume(conn->raop_rtp, vol);
			} else if (!strncmp(datastr, "progress: ", 10)) {
				unsigned int start, curr, end;
				sscanf(datastr+10, "%u/%u/%u", &start, &curr, &end);
				raop_rtp_set_progress(conn->raop_rtp, start, curr, end);
			}
		} else if (!conn->raop_rtp) {
			logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER");
		}
		free(datastr);
	} else if (!strcmp(content_type, "image/jpeg") || !strcmp(content_type, "image/png")) {
		logger_log(conn->raop->logger, LOGGER_INFO, "Got image data of %d bytes", datalen);
		if (conn->raop_rtp) {
			raop_rtp_set_coverart(conn->raop_rtp, data, datalen);
		} else {
			logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER coverart");
		}
	} else if (!strcmp(content_type, "application/x-dmap-tagged")) {
		logger_log(conn->raop->logger, LOGGER_INFO, "Got metadata of %d bytes", datalen);
		if (conn->raop_rtp) {
			raop_rtp_set_metadata(conn->raop_rtp, data, datalen);
		} else {
			logger_log(conn->raop->logger, LOGGER_WARNING, "RAOP not initialized at SET_PARAMETER metadata");
		}
	}
}


static void
raop_handler_feedback(raop_conn_t *conn,
                           http_request_t *request, http_response_t *response,
                           char **response_data, int *response_datalen)
{
    logger_log(conn->raop->logger, LOGGER_DEBUG, "raop_handler_feedback");
}

static void
raop_handler_record(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    logger_log(conn->raop->logger, LOGGER_DEBUG, "raop_handler_record");
    http_response_add_header(response, "Audio-Latency", "11025");
    http_response_add_header(response, "Audio-Jack-Status", "connected; type=analog");
}