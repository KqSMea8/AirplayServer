//
// Created by Florian Draschbacher on 2019/04/22
//

#include "video_renderer.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "bcm_host.h"
#include "ilclient.h"

/* 
 * H264 renderer using OpenMAX for hardware accelerated decoding
 * on the Raspberry Pi. 
 * Based on the hello_video sample from the Raspberry Pi project.
*/

struct video_renderer_t {
    logger_t *logger;

    ILCLIENT_T *client = NULL;
    COMPONENT_T *video_decoder = NULL;
    COMPONENT_T *video_renderer = NULL;
    TUNNEL_T *decoder_tunnel = NULL;
    OMX_VIDEO_PARAM_PORTFORMATTYPE format;

    COMPONENT_T *components[3] = {NULL, NULL, NULL};
    TUNNEL_T tunnels[2] = {NULL, NULL};

    bool first_packet = true;
};

int video_renderer_init_decoder(video_renderer_t *renderer) {
    bcm_host_init();

    if ((renderer->client = ilclient_init()) == NULL) {
      return -3;
    }

    if (OMX_Init() != OMX_ErrorNone) {
        ilclient_destroy(client);
        return -4;
    }

    // Create video_decode
    if (ilclient_create_component(client, &renderer->video_decoder, "video_decode", 
      ILCLIENT_DISABLE_ALL_PORTS | ILCLIENT_ENABLE_INPUT_BUFFERS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[0] = renderer->video_decoder;

    // Create video_renderer
    if (ilclient_create_component(client, &renderer->video_renderer, "video_render", 
            ILCLIENT_DISABLE_ALL_PORTS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[1] = renderer->video_renderer;

    set_tunnel(tunnel, renderer->video_decoder, 131, renderer->video_renderer, 90);
    ilclient_change_component_state(renderer->video_decoder, OMX_StateIdle);

    // Set decoder format
    memset(&format, 0, sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE));
    format.nSize = sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE);
    format.nVersion.nVersion = OMX_VERSION;
    format.nPortIndex = 130;
    format.eCompressionFormat = OMX_VIDEO_CodingAVC;

    if (OMX_SetParameter(ILC_GET_HANDLE(renderer->video_decoder), OMX_IndexParamVideoPortFormat, &format) != OMX_ErrorNone ||
            ilclient_enable_port_buffers(renderer->video_decoder, 130, NULL, NULL, NULL) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -15;
    }

    ilclient_change_component_state(renderer->video_decoder, OMX_StateExecuting);
}

void video_renderer_destroy_decoder(video_renderer_t *renderer) {
    ilclient_disable_tunnel(renderer->tunnels);
    ilclient_disable_port_buffers(renderer->video_decoder, 130, NULL, NULL, NULL);
    ilclient_teardown_tunnels(renderer->tunnels);

    ilclient_state_transition(renderer->components, OMX_StateIdle);
    ilclient_state_transition(renderer->components, OMX_StateLoaded);
    ilclient_cleanup_components(renderer->components);

    OMX_Deinit();
    ilclient_destroy(client);
}

video_renderer_t *video_renderer_init(logger_t *logger) {
    video_renderer_t *renderer;
    renderer = calloc(1, sizeof(video_renderer_t));
    if (!renderer) {
        return NULL;
    }
    renderer->logger = logger;
    return renderer;
}

void video_renderer_render_buffer(video_renderer_t *renderer, unsigned char* data, int datalen) {
    if (datalen == 0) return;

    OMX_BUFFERHEADERTYPE *buffer = ilclient_get_input_buffer(renderer->video_decoder, 130, 1);
    if (buffer == NULL) {
        logger_log(renderer->logger, LOGGER_DEBUG, "Skipping video buffer due to busy decoder");
        return;
    }

    if (ilclient_remove_event(renderer->video_decoder, OMX_EventPortSettingsChanged, 131, 0, 0, 1) == 0) {
        if (ilclient_setup_tunnel(renderer->tunnels, 0, 0) != 0) {
            logger_log(renderer->logger, LOGGER_ERROR, "Could not setup renderer tunnel");
        }

        ilclient_change_component_state(renderer->video_renderer, OMX_StateExecuting);
    }

    assert(datalen < buffer->nAllocLen);
    memcpy(buffer->pBuffer, data, datalen);

    buffer->nOffset = 0;
    if (renderer->first_packet) {
       buffer->nFlags = OMX_BUFFERFLAG_STARTTIME;
       renderer->first_packet = 0;
    } else {
       buffer->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN;
    }

    if (OMX_EmptyThisBuffer(ILC_GET_HANDLE(renderer->video_decoder), buffer) != OMX_ErrorNone) {
       logger_log(renderer->logger, LOGGER_ERROR, "Video decoder refused processing buffer");
    }
}

void video_renderer_flush() {
    ilclient_flush_tunnels(renderer->tunnels, 0);
}

void video_renderer_destroy(video_renderer_t *renderer) {
    if (renderer) {
        video_renderer_flush();
        video_renderer_destroy_decoder(renderer);
        free(renderer);
    }
}
