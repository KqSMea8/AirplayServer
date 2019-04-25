/**
 * RPiPlay - An open-source AirPlay mirroring server for Raspberry Pi
 * Copyright (C) 2019 Florian Draschbacher
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#include <stddef.h>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <fstream>

#include "log.h"
#include "lib/raop.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include "lib/dnssd.h"
#include "renderers/video_renderer.h"
#include "renderers/audio_renderer.h"

#define VERSION "1.0"

#define DEFAULT_NAME "RPiPlay"
#define DEFAULT_SHOW_BACKGROUND true
#define DEFAULT_AUDIO_DEVICE AUDIO_DEVICE_HDMI
#define DEFAULT_HW_ADDRESS { 0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22 }

int start_server(std::vector<char> hw_addr, std::string name, bool show_background, audio_device_t audio_device);
int stop_server();

static bool running = false;
static dnssd_t *dnssd = NULL;
static raop_t *raop = NULL;
static video_renderer_t *video_renderer = NULL;
static audio_renderer_t *audio_renderer = NULL;

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

static int parse_hw_addr(std::string str, std::vector<char> &hw_addr) {
    for (int i = 0; i < str.length(); i+=3) {
        hw_addr.push_back((char) stol(str.substr(i), NULL, 16));
    }
    return 0;
}

std::string find_mac() {
    std::ifstream iface_stream("/sys/class/net/eth0/address");
    if (!iface_stream) {
        iface_stream.open("/sys/class/net/wlan0/address");
    }
    if (!iface_stream) return "";

    std::string mac_address;
    iface_stream >> mac_address;
    iface_stream.close();
    return mac_address;
}

void print_info(char* name) {
    printf("RPiPlay %s: An open-source AirPlay mirroring server for Raspberry Pi\n", VERSION);
    printf("Usage: %s [-b] [-n name] [-a (hdmi|analog|off)]\n", name);
    printf("Options:\n");
    printf("-n name               Specify the network name of the AirPlay server\n");
    printf("-b                    Hide the black background behind the video\n");
    printf("-a (hdmi|analog|off)  Set audio output device\n");
    printf("-v/-h                 Displays this help and version information\n");
}

int main(int argc, char *argv[]) {
    init_signals();

    bool show_background = DEFAULT_SHOW_BACKGROUND;
    std::string server_name = DEFAULT_NAME;
    std::vector<char> server_hw_addr = DEFAULT_HW_ADDRESS;
    audio_device_t audio_device = DEFAULT_AUDIO_DEVICE;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        if (arg == "-n") {
            if (i == argc - 1) continue;
            server_name = std::string(argv[++i]);
        } else if (arg == "-b") {
            show_background = !show_background;  
        } else if (arg == "-a") {
            if (i == argc - 1) continue;
            std::string audio_device_name(argv[++i]);
            audio_device = audio_device_name == "hdmi" ? AUDIO_DEVICE_NONE : 
                           audio_device_name == "analog" ? AUDIO_DEVICE_ANALOG:
                           AUDIO_DEVICE_NONE;
        } else if (arg == "-h" || arg == "-v") {
            print_info(argv[0]);
            exit(0);
        }
    }

    std::string mac_address = find_mac();
    if (!mac_address.empty()) {
        server_hw_addr.clear();
        parse_hw_addr(mac_address, server_hw_addr);
    }
 
    if (start_server(server_hw_addr, server_name, show_background, audio_device) != 0) {
        return 1;
    }

    running = true;
    while (running) {
        sleep(1);
    }

    LOGI("Stopping...", msg);
    stop_server();
}

// Server callbacks
extern "C" void audio_process(void *cls, aac_decode_struct *data) {
    if (audio_renderer != NULL) {
        audio_renderer_render_buffer(audio_renderer, data->data, data->data_len);
    }
}

extern "C" void video_process(void *cls, h264_decode_struct *data) {
    video_renderer_render_buffer(video_renderer, data->data, data->data_len, data->pts);
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

int start_server(std::vector<char> hw_addr, std::string name, bool show_background, audio_device_t audio_device) {
    logger_t *render_logger = logger_init();
    logger_set_callback(render_logger, log_callback, NULL);
    logger_set_level(render_logger, LOGGER_DEBUG);
    if ((video_renderer = video_renderer_init(render_logger, show_background)) == NULL) {
        LOGE("Could not init video renderer");
        return -1;
    }

    if (audio_device == AUDIO_DEVICE_NONE) {
        LOGI("Audio disabled");
    } else if ((audio_renderer = audio_renderer_init(render_logger, audio_device)) == NULL) {
        LOGE("Could not init audio renderer");
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
        LOGE("Could not initialize dnssd library!");
        return -2;
    }

    dnssd_register_raop(dnssd, name.c_str(), port, hw_addr.data(), hw_addr.size(), 0);
    dnssd_register_airplay(dnssd, name.c_str(), port + 1, hw_addr.data(), hw_addr.size());

    return 0;
}

int stop_server() {
    raop_destroy(raop);
    dnssd_unregister_raop(dnssd);
    dnssd_unregister_airplay(dnssd);
    video_renderer_destroy(video_renderer);
    audio_renderer_destroy(audio_renderer);
    return 0;
}
