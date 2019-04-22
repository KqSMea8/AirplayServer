#include <stddef.h>
#include <cstring>
#include <signal.h>
#include <unistd.h>

#include "log.h"
#include "lib/raop.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include "lib/dnssd.h"
#include "renderers/video_renderer.h"

int start_server();
int stop_server();

static int running;
dnssd_t *dnssd;
raop_t *raop;
video_renderer_t *video_renderer;

static void signal_handler(int sig) {
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        running = 0;
        break;
    }
}

static void init_signals(void) {
    struct sigaction sigact;

    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
}

int main(int argc, char *argv[]) {
    init_signals();

    if (start_server() != 0) {
        return 1;
    }

    running = true;
    while (running) {
        sleep(1);
    }

    printf("Stopping...\n");
    stop_server();
}

// Server callbacks
extern "C" void audio_process(void *cls, aac_decode_struct *data) {}

extern "C" void video_process(void *cls, h264_decode_struct *data) {
    video_renderer_render_buffer(video_renderer, data->data, data->data_len);
}

extern "C" void log_callback(void *cls, int level, const char *msg) {
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
    logger_t *render_logger = logger_init();
    logger_set_callback(render_logger, log_callback, NULL);
    logger_set_level(render_logger, LOGGER_DEBUG);
    if ((video_renderer = video_renderer_init(render_logger)) == NULL) {
        LOGE("Could not init video renderer\n");
        return -1;
    }

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
    raop_set_log_level(raop, RAOP_LOG_ERR);

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
