//
// Created by Florian Draschbacher on 2019/04/22
//

#include "video_renderer.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "bcm_host.h"
#include "ilclient.h"

/* 
 * H264 renderer using OpenMAX for hardware accelerated decoding
 * on the Raspberry Pi. 
 * Based on the hello_video sample from the Raspberry Pi project.
*/

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

struct video_renderer_s {
    logger_t *logger;

    ILCLIENT_T *client;
    COMPONENT_T *video_decoder;
    COMPONENT_T *video_renderer;
    COMPONENT_T *video_scheduler;
    COMPONENT_T *clock;

    COMPONENT_T *components[5];
    TUNNEL_T tunnels[4];

    bool first_packet;
};

/* From: https://github.com/popcornmix/omxplayer/blob/master/omxplayer.cpp#L455
 * Licensed under the GPLv2 */
void video_renderer_init_background(){
	// we create a 1x1 black pixel image that is added to display just behind video
	DISPMANX_DISPLAY_HANDLE_T display;
	DISPMANX_UPDATE_HANDLE_T update;
	DISPMANX_RESOURCE_HANDLE_T resource;
	uint32_t vc_image_ptr;
	VC_IMAGE_TYPE_T type = VC_IMAGE_RGB565;
	uint16_t image = 0x0000; // black
	int layer = 0;

	VC_RECT_T dst_rect, src_rect;

	display = vc_dispmanx_display_open(0);

	resource = vc_dispmanx_resource_create( type, 1 /*width*/, 1 /*height*/, &vc_image_ptr );

	vc_dispmanx_rect_set( &dst_rect, 0, 0, 1, 1);

	vc_dispmanx_resource_write_data( resource, type, sizeof(image), &image, &dst_rect );

	vc_dispmanx_rect_set( &src_rect, 0, 0, 1<<16, 1<<16);
	vc_dispmanx_rect_set( &dst_rect, 0, 0, 0, 0);

	update = vc_dispmanx_update_start(0);

	vc_dispmanx_element_add(update, display, layer, &dst_rect, resource, &src_rect,
									DISPMANX_PROTECTION_NONE, NULL, NULL, DISPMANX_STEREOSCOPIC_MONO );

	vc_dispmanx_update_submit_sync(update);
}

void video_renderer_destroy_decoder(video_renderer_t *renderer) {
    ilclient_disable_tunnel(&renderer->tunnels[0]);
    ilclient_disable_tunnel(&renderer->tunnels[1]);
    ilclient_disable_tunnel(&renderer->tunnels[2]);
    ilclient_disable_port_buffers(renderer->video_decoder, 130, NULL, NULL, NULL);
    ilclient_teardown_tunnels(renderer->tunnels);

    ilclient_state_transition(renderer->components, OMX_StateIdle);
    ilclient_state_transition(renderer->components, OMX_StateLoaded);
    ilclient_cleanup_components(renderer->components);

    OMX_Deinit();
    ilclient_destroy(renderer->client);
}

int video_renderer_init_decoder(video_renderer_t *renderer) {
    memset(renderer->components, 0, sizeof(renderer->components));
    memset(renderer->tunnels, 0, sizeof(renderer->tunnels));    
    renderer->first_packet = true;

    bcm_host_init();

    video_renderer_init_background();

    if ((renderer->client = ilclient_init()) == NULL) {
      return -3;
    }

    if (OMX_Init() != OMX_ErrorNone) {
        ilclient_destroy(renderer->client);
        return -4;
    }

    // Create video_decode
    if (ilclient_create_component(renderer->client, &renderer->video_decoder, "video_decode", 
      ILCLIENT_DISABLE_ALL_PORTS | ILCLIENT_ENABLE_INPUT_BUFFERS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[0] = renderer->video_decoder;

    // Create video_renderer
    if (ilclient_create_component(renderer->client, &renderer->video_renderer, "video_render", 
            ILCLIENT_DISABLE_ALL_PORTS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[1] = renderer->video_renderer;

    // Create clock
    if (ilclient_create_component(renderer->client, &renderer->clock, "clock", 
            ILCLIENT_DISABLE_ALL_PORTS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[2] = renderer->clock;

    // Setup clock
    OMX_TIME_CONFIG_CLOCKSTATETYPE cstate;
    memset(&cstate, 0, sizeof(cstate));
    cstate.nSize = sizeof(cstate);
    cstate.nVersion.nVersion = OMX_VERSION;
    cstate.eState = OMX_TIME_ClockStateWaitingForStartTime;
    cstate.nWaitMask = 1;
    if (OMX_SetParameter(ILC_GET_HANDLE(renderer->clock), OMX_IndexConfigTimeClockState, &cstate) != OMX_ErrorNone) {
        video_renderer_destroy_decoder(renderer);
        return -13;
    }

    // Create video_scheduler
    if (ilclient_create_component(renderer->client, &renderer->video_scheduler, "video_scheduler", 
            ILCLIENT_DISABLE_ALL_PORTS) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -14;
    }
    renderer->components[3] = renderer->video_scheduler;

    // Create tunnels
    set_tunnel(&renderer->tunnels[0], renderer->video_decoder, 131, renderer->video_scheduler, 10);
    set_tunnel(&renderer->tunnels[1], renderer->video_scheduler, 11, renderer->video_renderer, 90);
    set_tunnel(&renderer->tunnels[2], renderer->clock, 80, renderer->video_scheduler, 12);

    // Setup renderer
    OMX_CONFIG_DISPLAYREGIONTYPE display_region;
    memset(&display_region, 0, sizeof(OMX_CONFIG_DISPLAYREGIONTYPE));
    display_region.nSize = sizeof(OMX_CONFIG_DISPLAYREGIONTYPE);
    display_region.nVersion.nVersion = OMX_VERSION;
    display_region.nPortIndex = 90;
    display_region.set = OMX_DISPLAY_SET_FULLSCREEN;
    display_region.fullscreen = OMX_TRUE;

    if (OMX_SetConfig(ilclient_get_handle(renderer->video_renderer), OMX_IndexConfigDisplayRegion, &display_region) != OMX_ErrorNone) {
        logger_log(renderer->logger, LOGGER_DEBUG, "Could not set renderer to fullscreen");
        video_renderer_destroy_decoder(renderer);
        return -13;
    }

    // Setup clock
    if (ilclient_setup_tunnel(&renderer->tunnels[2], 0, 0) != 0) {
        video_renderer_destroy_decoder(renderer);
        return -15;
    }
    ilclient_change_component_state(renderer->clock, OMX_StateExecuting);

    // Set decoder format
    ilclient_change_component_state(renderer->video_decoder, OMX_StateIdle);
    OMX_VIDEO_PARAM_PORTFORMATTYPE format;
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
    return 1;
}

video_renderer_t *video_renderer_init(logger_t *logger) {
    video_renderer_t *renderer;
    renderer = calloc(1, sizeof(video_renderer_t));
    if (!renderer) {
        return NULL;
    }
    renderer->logger = logger;

    if (video_renderer_init_decoder(renderer) != 1) {
        free(renderer);
        renderer = NULL;
    }

    return renderer;
}

void video_renderer_render_buffer(video_renderer_t *renderer, unsigned char* data, int datalen) {
    if (datalen == 0) return;

    logger_log(renderer->logger, LOGGER_DEBUG, "Got h264 data of %d bytes", datalen);

    if (ilclient_remove_event(renderer->video_decoder, OMX_EventPortSettingsChanged, 131, 0, 0, 1) == 0) {
        logger_log(renderer->logger, LOGGER_DEBUG, "Port settings changed!!");

        if (ilclient_setup_tunnel(&renderer->tunnels[0], 0, 0) != 0) {
            logger_log(renderer->logger, LOGGER_ERR, "Could not setup decoder tunnel");
        }

        ilclient_change_component_state(renderer->video_scheduler, OMX_StateExecuting);

        if (ilclient_setup_tunnel(&renderer->tunnels[1], 0, 1000) != 0) {
            logger_log(renderer->logger, LOGGER_ERR, "Could not setup scheduler tunnel");
        }

        ilclient_change_component_state(renderer->video_renderer, OMX_StateExecuting);
    }

    int offset = 0;
    while (offset < datalen) {
        OMX_BUFFERHEADERTYPE *buffer = ilclient_get_input_buffer(renderer->video_decoder, 130, 1);
        if (buffer == NULL) {
            sleep(10);
            continue;
        }

        int chunk_size = MIN(datalen - offset, buffer->nAllocLen);
        memcpy(buffer->pBuffer, data, chunk_size);
        offset += chunk_size;

        buffer->nFilledLen = chunk_size;
        buffer->nOffset = 0;
        if (renderer->first_packet) {
            buffer->nFlags = OMX_BUFFERFLAG_STARTTIME;
            renderer->first_packet = 0;
        } else {
            buffer->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN;
        }

        if (OMX_EmptyThisBuffer(ILC_GET_HANDLE(renderer->video_decoder), buffer) != OMX_ErrorNone) {
            logger_log(renderer->logger, LOGGER_ERR, "Video decoder refused processing buffer");
        }
    }
}

void video_renderer_flush(video_renderer_t *renderer) {
    ilclient_flush_tunnels(renderer->tunnels, 0);
}

void video_renderer_destroy(video_renderer_t *renderer) {
    if (renderer) {
        video_renderer_flush(renderer);
        video_renderer_destroy_decoder(renderer);
        free(renderer);
    }
}
