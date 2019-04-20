#include <stddef.h>
#include "lib/raop.h"
#include "log.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include <malloc.h>
#include <cstring>
#include "lib/dnssd.h"

int start_server();
int stop_server();

int main(int argc, char *argv[]) {}

dnssd_t *dnssd;
raop_t *raop;

// Server callbacks
extern "C" void
audio_process(void *cls, pcm_data_struct *data)
{}

extern "C" void
video_process(void *cls, h264_decode_struct *data)
{}

extern "C" void
log_callback(void *cls, int level, const char *msg) {
    switch (level) {
        case LOGGER_DEBUG: {
            LOGD("%s", msg);
            break;
        }
        case LOGGER_WARNING: {
            LOGW("%s", msg);
            break;
        }
        case LOGGER_INFO: {
            LOGI("%s", msg);
            break;
        }
        case LOGGER_ERR: {
            LOGE("%s", msg);
            break;
        }
        default:break;
    }

}

int start_server() {
    raop_callbacks_t raop_cbs;
    memset(&raop_cbs, 0, sizeof(raop_cbs));
    raop_cbs.audio_process = audio_process;
    raop_cbs.video_process = video_process;
    raop = raop_init(10, &raop_cbs);
    if (raop == NULL) {
        LOGE("raop = NULL");
        return -1;
    } else {
        LOGD("raop init success");
    }

    raop_set_log_callback(raop, log_callback, NULL);
    raop_set_log_level(raop, RAOP_LOG_DEBUG);

    unsigned short port = 0;
    raop_start(raop, &port);
    raop_set_port(raop, port);
    LOGD("raop port = % d", raop_get_port(raop));

    int error;
    dnssd = dnssd_init(&error);
    if (error) {
        LOGE("ERROR: Could not initialize dnssd library!\n");
        LOGE("------------------------------------------\n");
        LOGE("You could try the following resolutions based on your OS:\n");
        LOGE("Windows: Try installing http://support.apple.com/kb/DL999\n");
        LOGE("Debian/Ubuntu: Try installing libavahi-compat-libdnssd-dev package\n");
        return -2;
    }

    const char hwaddr[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    dnssd_register_raop(dnssd, "Test", port, hwaddr, sizeof(hwaddr), 0);
    dnssd_register_airplay(dnssd, "Test", port + 1, hwaddr, sizeof(hwaddr));
    return 0;
}

int stop_server() {
    raop_destroy(raop);
    dnssd_unregister_raop(dnssd);
    dnssd_unregister_airplay(dnssd);
    return 0;
}
