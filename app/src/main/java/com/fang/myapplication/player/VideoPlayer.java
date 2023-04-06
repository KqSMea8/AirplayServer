package com.fang.myapplication.player;

import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.Surface;

import com.fang.myapplication.model.NALPacket;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VideoPlayer extends Thread {

	private static final String TAG = "AIS-VideoPlayer";

	private String mMimeType = "video/avc";
//	private int mVideoWidth = 1280;
//	private int mVideoHeight = 720;
	 private int mVideoWidth = 1920;
	 private int mVideoHeight = 1080;
	private MediaCodec.BufferInfo mBufferInfo = new MediaCodec.BufferInfo();
	private MediaCodec mDecoder = null;
	private Surface mSurface = null;
	private boolean mIsEnd = false;
	private List<NALPacket> mListBuffer = Collections.synchronizedList(new ArrayList<NALPacket>());

	public VideoPlayer(Surface surface) {
		mSurface = surface;
	}


    private static boolean decoderSupportsAndroidRLowLatency(MediaCodecInfo decoderInfo, String mimeType) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                if (decoderInfo.getCapabilitiesForType(mimeType).isFeatureSupported(MediaCodecInfo.CodecCapabilities.FEATURE_LowLatency)) {
                    Log.d(TAG, "Low latency decoding mode supported (FEATURE_LowLatency)");
                    return true;
                }
            } catch (Exception e) {
                // Tolerate buggy codecs
                e.printStackTrace();
            }
        } else {
			Log.e(TAG, "ERROR: Low latency decoding mode NOT supported (FEATURE_LowLatency)");
		}

        return false;
    }

	public static boolean decoderSupportsAdaptivePlayback(MediaCodecInfo decoderInfo, String mimeType) {
		// Possibly enable adaptive playback on KitKat and above
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
			try {
				if (decoderInfo.getCapabilitiesForType(mimeType).
						isFeatureSupported(MediaCodecInfo.CodecCapabilities.FEATURE_AdaptivePlayback))
				{
					// This will make getCapabilities() return that adaptive playback is supported
					Log.i(TAG, "Adaptive playback supported (FEATURE_AdaptivePlayback)");
					return true;
				}
			} catch (Exception e) {
				// Tolerate buggy codecs
				e.printStackTrace();
			}
		}

		Log.w(TAG, "Adaptive playback NOT supported (FEATURE_AdaptivePlayback)");
		return false;
	}


	public void initDecoder() {
		try {
			MediaFormat videoFormat = MediaFormat.createVideoFormat(mMimeType, mVideoWidth, mVideoHeight);

			mDecoder = MediaCodec.createDecoderByType(mMimeType);

			MediaCodecInfo mDecoderInfo =  mDecoder.getCodecInfo();
			Log.i(TAG, "DECODER SELECTED = " + mDecoderInfo.getName());

			if ( decoderSupportsAndroidRLowLatency(mDecoderInfo, videoFormat.getString(MediaFormat.KEY_MIME)) )
			{
				videoFormat.setInteger("low-latency", 1);
				videoFormat.setInteger("vendor.rtc-ext-dec-low-latency.enable", 1);
			}

// 			if ( decoderSupportsAdaptivePlayback(mDecoderInfo, mMimeType) ) {
// //				videoFormat.setInteger(MediaFormat.KEY_MAX_WIDTH, 1280);
// //				videoFormat.setInteger(MediaFormat.KEY_MAX_HEIGHT, 720);
// 				videoFormat.setInteger(MediaFormat.KEY_MAX_WIDTH, 1920);
// 				videoFormat.setInteger(MediaFormat.KEY_MAX_HEIGHT, 1080);
// 			}

			// mDecoder = MediaCodec.createByCodecName("OMX.MS.AVC.Decoder");
			// mDecoder = MediaCodec.createByCodecName("OMX.google.h264.decoder");
			// mDecoder = MediaCodec.createByCodecName("OMX.MS.VP8.Decoder");

			// mDecoder = MediaCodec.createByCodecName("OMX.Exynos.avc.dec");
			mDecoder.configure(videoFormat, mSurface, null, 0);
			mDecoder.setVideoScalingMode(MediaCodec.VIDEO_SCALING_MODE_SCALE_TO_FIT);

			// Bundle lowLatency = new Bundle();
			// lowLatency.putInt(MediaCodec.PARAMETER_KEY_LOW_LATENCY, 1);
			// mDecoder.setParameters(lowLatency);

			mDecoder.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void addPacker(NALPacket nalPacket) {
		mListBuffer.add(nalPacket);
	}

	@Override
	public void run() {
		super.run();
		initDecoder();
		while (!mIsEnd) {
			if (mListBuffer.size() == 0) {
				try {
					sleep(1);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				continue;
			}
			doDecode(mListBuffer.remove(0));
		}
	}

	private void doDecode(NALPacket nalPacket) {
		final int TIMEOUT_USEC = 1000;
		ByteBuffer[] decoderInputBuffers = mDecoder.getInputBuffers();
		int inputBufIndex = -10000;
		try {
			inputBufIndex = mDecoder.dequeueInputBuffer(TIMEOUT_USEC);
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (inputBufIndex >= 0) {
			ByteBuffer inputBuf = decoderInputBuffers[inputBufIndex];
			inputBuf.put(nalPacket.nalData);
			mDecoder.queueInputBuffer(inputBufIndex, 0, nalPacket.nalData.length, nalPacket.pts, 0);
		} else {
			Log.d(TAG, "dequeueInputBuffer failed");
		}

		int outputBufferIndex = -10000;
		try {
			outputBufferIndex = mDecoder.dequeueOutputBuffer(mBufferInfo, TIMEOUT_USEC);
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (outputBufferIndex >= 0) {
			mDecoder.releaseOutputBuffer(outputBufferIndex, true);
//			try {
//				Thread.sleep(20);
//			} catch (InterruptedException ie) {
//				ie.printStackTrace();
//			}
		} else if (outputBufferIndex == MediaCodec.INFO_TRY_AGAIN_LATER) {
			try {
				Thread.sleep(1);
			} catch (InterruptedException ie) {
				ie.printStackTrace();
			}
		} else if (outputBufferIndex == MediaCodec.INFO_OUTPUT_BUFFERS_CHANGED) {
			// not important for us, since we're using Surface

		} else if (outputBufferIndex == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {

		} else {

		}

	}
}
