//
// Created by Administrator on 2019/1/29/029.
//

#include <jni.h>
#include <stddef.h>
#include "lib/raop.h"
#include "log.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include <malloc.h>
#include <cstring>

static JavaVM* g_JavaVM;

void OnRecvAudioData(void *observer, pcm_data_struct *data) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onRecvVideoDataM = jniEnv->GetMethodID(cls, "onRecvAudioData", "([SJ)V");
    jniEnv->DeleteLocalRef(cls);
    jshortArray sarr = jniEnv->NewShortArray(data->data_len);
    if (sarr == NULL) return;
    jniEnv->SetShortArrayRegion(sarr, (jint) 0, data->data_len, (jshort *) data->data);
    jniEnv->CallVoidMethod(obj, onRecvVideoDataM, sarr, data->pts);
    jniEnv->DeleteLocalRef(sarr);
    g_JavaVM->DetachCurrentThread();
}


void OnRecvVideoData(void *observer, h264_decode_struct *data) {
    jobject obj = (jobject) observer;
    JNIEnv* jniEnv = NULL;
    g_JavaVM->AttachCurrentThread(&jniEnv, NULL);
    jclass cls = jniEnv->GetObjectClass(obj);
    jmethodID onRecvVideoDataM = jniEnv->GetMethodID(cls, "onRecvVideoData", "([BIJJ)V");
    jniEnv->DeleteLocalRef(cls);
    jbyteArray barr = jniEnv->NewByteArray(data->data_len);
    if (barr == NULL) return;
    jniEnv->SetByteArrayRegion(barr, (jint) 0, data->data_len, (jbyte *) data->data);
    jniEnv->CallVoidMethod(obj, onRecvVideoDataM, barr, data->frame_type,
                                         data->pts, data->pts);
    jniEnv->DeleteLocalRef(barr);
    g_JavaVM->DetachCurrentThread();
}

extern "C" void
audio_process(void *cls, pcm_data_struct *data)
{
    OnRecvAudioData(cls, data);
}

extern "C" void
audio_set_volume(void *cls, void *opaque, float volume)
{

}

extern "C" void
video_process(void *cls, h264_decode_struct *data)
{
    OnRecvVideoData(cls, data);
}

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

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_JavaVM = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_fang_myapplication_RaopServer_start(JNIEnv* env, jobject object) {
    raop_t *raop;
    raop_callbacks_t raop_cbs;
    memset(&raop_cbs, 0, sizeof(raop_cbs));
    raop_cbs.cls = (void *) env->NewGlobalRef(object);;
    raop_cbs.audio_process = audio_process;
    raop_cbs.audio_set_volume = audio_set_volume;
    raop_cbs.video_process = video_process;
    raop = raop_init(10, &raop_cbs);
    if (raop == NULL) {
        LOGE("raop = NULL");
        return 0;
    } else {
        LOGD("raop init success");
    }

    raop_set_log_callback(raop, log_callback, NULL);
    raop_set_log_level(raop, RAOP_LOG_DEBUG);

    unsigned short port = 0;
    raop_start(raop, &port);
    raop_set_port(raop, port);
    LOGD("raop port = % d", raop_get_port(raop));
    return (jlong) (void *) raop;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_fang_myapplication_RaopServer_getPort(JNIEnv* env, jobject object, jlong opaque) {
    raop_t *raop = (raop_t *) (void *) opaque;
    return raop_get_port(raop);
}

extern "C" JNIEXPORT void JNICALL
Java_com_fang_myapplication_RaopServer_stop(JNIEnv* env, jobject object, jlong opaque) {
    raop_t *raop = (raop_t *) (void *) opaque;
    jobject obj = (jobject) raop_get_callback_cls(raop);
    raop_destroy(raop);
    env->DeleteGlobalRef(obj);

}