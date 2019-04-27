//
// Created by Florian Draschbacher on 2019-04-27.
//

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "raop_ntp.h"
#include "threads.h"
#include "compat.h"
#include "netutils.h"
#include "byteutils.h"

struct raop_ntp_s {
    logger_t *logger;

    thread_handle_t thread;
    mutex_handle_t run_mutex;
    mutex_handle_t time_mutex;
    cond_handle_t time_cond;

    // Socket address of the AirPlay client
    struct sockaddr_storage remote_saddr;
    socklen_t remote_saddr_len;

    // The remote port of the NTP server on the AirPlay client
    unsigned short timing_rport;

    // The local port of the NTP client on the AirPlay server
    unsigned short timing_lport;

    /* MUTEX LOCKED VARIABLES START */
    /* These variables only edited mutex locked */
    int running;
    int joined;

    // UDP socket
    int tsock;
};

static int
raop_ntp_parse_remote_address(raop_ntp_t *raop_ntp, const unsigned char *remote_addr, int remote_addr_len)
{
    char current[25];
    int family;
    int ret;
    assert(raop_ntp);
    if (remote_addr_len == 4) {
        family = AF_INET;
    } else if (remote_addr_len == 16) {
        family = AF_INET6;
    } else {
        return -1;
    }
    memset(current, 0, sizeof(current));
    sprintf(current, "%d.%d.%d.%d", remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3]);
    logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp_parse_remote ip = %s", current);
    ret = netutils_parse_address(family, current,
                                 &raop_ntp->remote_saddr,
                                 sizeof(raop_ntp->remote_saddr));
    if (ret < 0) {
        return -1;
    }
    raop_ntp->remote_saddr_len = ret;
    return 0;
}

raop_ntp_t *raop_ntp_init(logger_t *logger, const unsigned char *remote_addr, int remote_addr_len, unsigned short timing_rport) {
    raop_ntp_t *raop_ntp;

    assert(logger);

    raop_ntp = calloc(1, sizeof(raop_ntp_t));
    if (!raop_ntp) {
        return NULL;
    }
    raop_ntp->logger = logger;
    raop_ntp->timing_rport = timing_rport;

    if (raop_ntp_parse_remote_address(raop_ntp, remote_addr, remote_addr_len) < 0) {
        free(raop_ntp);
        return NULL;
    }

    // Set port on the remote address struct
    ((struct sockaddr_in *) &raop_ntp->remote_saddr)->sin_port = htons(timing_rport);

    raop_ntp->running = 0;
    raop_ntp->joined = 1;

    MUTEX_CREATE(raop_ntp->run_mutex);
    MUTEX_CREATE(raop_ntp->time_mutex);
    COND_CREATE(raop_ntp->time_cond);
    return raop_ntp;
}

void
raop_ntp_destroy(raop_ntp_t *raop_ntp)
{
    if (raop_ntp) {
        raop_ntp_stop(raop_ntp);
        MUTEX_DESTROY(raop_ntp->run_mutex);
        MUTEX_DESTROY(raop_ntp->time_mutex);
        COND_DESTROY(raop_ntp->time_cond);
        free(raop_ntp);
    }
}

unsigned short raop_ntp_get_port(raop_ntp_t *raop_ntp) {
    return raop_ntp->timing_lport;
}

static int
raop_ntp_init_socket(raop_ntp_t *raop_ntp, int use_ipv6)
{
    int tsock = -1;
    unsigned short tport = 0;

    assert(raop_ntp);

    tsock = netutils_init_socket(&tport, use_ipv6, 1);

    if (tsock == -1) {
        goto sockets_cleanup;
    }

    /* Set socket descriptors */
    raop_ntp->tsock = tsock;

    /* Set port values */
    raop_ntp->timing_lport = tport;
    return 0;

    sockets_cleanup:
    if (tsock != -1) closesocket(tsock);
    return -1;
}

static THREAD_RETVAL
raop_ntp_thread(void *arg)
{
    raop_ntp_t *raop_ntp = arg;
    assert(raop_ntp);
    unsigned char response[128];
    unsigned int response_len;
    unsigned char request[32] = {0x80, 0xd2, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint64_t start_time = now_us();
    uint64_t rec_pts = 0;

    while (1) {
        MUTEX_LOCK(raop_ntp->run_mutex);
        if (!raop_ntp->running) {
            MUTEX_UNLOCK(raop_ntp->run_mutex);
            break;
        }
        MUTEX_UNLOCK(raop_ntp->run_mutex);

        // Send request
        uint64_t send_time = now_us() - start_time + rec_pts;
        byteutils_put_time_stamp(request, 24, send_time);
        int send_len = sendto(raop_ntp->tsock, (char *)request, sizeof(request), 0,
                (struct sockaddr *) &raop_ntp->remote_saddr, raop_ntp->remote_saddr_len);
        logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp_thread send_len = %d", send_len);

        // Read response
        response_len = recvfrom(raop_ntp->tsock, (char *)response, sizeof(response), 0,
                             (struct sockaddr *) &raop_ntp->remote_saddr, &raop_ntp->remote_saddr_len);
        int type = response[1] & ~0x80;
        logger_log(raop_ntp->logger, LOGGER_DEBUG, "raop_ntp_thread receive time type_t 0x%02x, packetlen = %d", type, response_len);
        if (type == 0x53) {

        }

        // 9-16 Local time of the sender when the NTP request packet leaves the sender. T1
        uint64_t origin_timestamp = byteutils_read_time_stamp(response, 8);
        // 17-24 Local time of the receiving end when the NTP request packet arrives at the receiving end. T2
        uint64_t receive_timestamp = byteutils_read_time_stamp(response, 16);
        // 25-32 Transmit Timestamp: The local time of the responder when the response message leaves the responder. T3
        uint64_t transmit_timestamp = byteutils_read_time_stamp(response, 24);

        // TODO: Implement clock sync
        rec_pts = receive_timestamp;

        // Sleep for 3 seconds
        struct timeval now;
        struct timespec wait_time;
        MUTEX_LOCK(raop_ntp->time_mutex);
        gettimeofday(&now, NULL);
        wait_time.tv_sec = now.tv_sec + 3;
        wait_time.tv_nsec = now.tv_usec * 1000;
        pthread_cond_timedwait(&raop_ntp->time_cond, &raop_ntp->time_mutex, &wait_time);
        MUTEX_UNLOCK(raop_ntp->time_mutex);
    }

    logger_log(raop_ntp->logger, LOGGER_INFO, "Exiting UDP raop_ntp_thread thread");
    return 0;
}

void
raop_ntp_start(raop_ntp_t *raop_ntp, unsigned short *timing_lport)
{
    logger_log(raop_ntp->logger, LOGGER_INFO, "raop_ntp_start");
    int use_ipv6 = 0;

    assert(raop_ntp);

    MUTEX_LOCK(raop_ntp->run_mutex);
    if (raop_ntp->running || !raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        return;
    }

    /* Initialize ports and sockets */
    if (raop_ntp->remote_saddr.ss_family == AF_INET6) {
        use_ipv6 = 1;
    }
    use_ipv6 = 0;
    if (raop_ntp_init_socket(raop_ntp, use_ipv6) < 0) {
        logger_log(raop_ntp->logger, LOGGER_INFO, "Initializing timing socket failed");
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        return;
    }
    if (timing_lport) *timing_lport = raop_ntp->timing_lport;

    /* Create the thread and initialize running values */
    raop_ntp->running = 1;
    raop_ntp->joined = 0;

    THREAD_CREATE(raop_ntp->thread, raop_ntp_thread, raop_ntp);
    MUTEX_UNLOCK(raop_ntp->run_mutex);
}

void
raop_ntp_stop(raop_ntp_t *raop_ntp)
{
    assert(raop_ntp);

    /* Check that we are running and thread is not
     * joined (should never be while still running) */
    MUTEX_LOCK(raop_ntp->run_mutex);
    if (!raop_ntp->running || raop_ntp->joined) {
        MUTEX_UNLOCK(raop_ntp->run_mutex);
        return;
    }
    raop_ntp->running = 0;
    MUTEX_UNLOCK(raop_ntp->run_mutex);

    /* Join the thread */
    THREAD_JOIN(raop_ntp->thread);

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "Stopping time thread");

    MUTEX_LOCK(raop_ntp->time_mutex);
    COND_SIGNAL(raop_ntp->time_cond);
    MUTEX_UNLOCK(raop_ntp->time_mutex);

    THREAD_JOIN(raop_ntp->thread);

    logger_log(raop_ntp->logger, LOGGER_DEBUG, "Stopped time thread");

    if (raop_ntp->tsock != -1) closesocket(raop_ntp->tsock);

    /* Mark thread as joined */
    MUTEX_LOCK(raop_ntp->run_mutex);
    raop_ntp->joined = 1;
    MUTEX_UNLOCK(raop_ntp->run_mutex);
}