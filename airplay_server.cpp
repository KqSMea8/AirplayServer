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

#define DEFAULT_NAME "RPiPlay"
#define DEFAULT_SHOW_BACKGROUND true

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

    bool show_background = DEFAULT_SHOW_BACKGROUND;
    std::string server_name = DEFAULT_NAME;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-n") {
            if (i == argc - 1) continue;
            server_name = std:.string(argv[++i]);
        } else if (arg == "-b") {
            show_background = !show_background;  
        }
    }


    if (start_server(server_name, show_background) != 0) {
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

int start_server(std::string name, bool show_background) {
    logger_t *render_logger = logger_init();
    logger_set_callback(render_logger, log_callback, NULL);
    logger_set_level(render_logger, LOGGER_DEBUG);
    if ((video_renderer = video_renderer_init(render_logger, show_background)) == NULL) {
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
    dnssd_register_raop(dnssd, name.c_str(), port, hwaddr, sizeof(hwaddr), 0);
    dnssd_register_airplay(dnssd, name.c_str(), port + 1, hwaddr, sizeof(hwaddr));

    return 0;
}

int stop_server() {
    raop_destroy(raop);
    dnssd_unregister_raop(dnssd);
    dnssd_unregister_airplay(dnssd);
    return 0;
}
