package com.fang.myapplication.player;

import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioTrack;

import com.fang.myapplication.model.PCMPacket;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AudioPlayer extends Thread {

    private AudioTrack mTrack;
    private int mChannel = AudioFormat.CHANNEL_OUT_STEREO;
    private int mSampleRate = 44100;
    private boolean isStopThread = false;
    private int mAudioFormat = AudioFormat.ENCODING_PCM_16BIT;
    private List<PCMPacket> mListBuffer = Collections.synchronizedList(new ArrayList<PCMPacket>());

    public AudioPlayer() {
        this.mTrack = new AudioTrack(AudioManager.STREAM_MUSIC, mSampleRate, mChannel, mAudioFormat,
                AudioTrack.getMinBufferSize(mSampleRate, mChannel, mAudioFormat), AudioTrack.MODE_STREAM);
        this.mTrack.play();
    }

    public void addPacker(PCMPacket pcmPacket) {
        mListBuffer.add(pcmPacket);
    }

    @Override
    public void run() {
        super.run();
        while (!isStopThread) {
            if (mListBuffer.size() == 0) {
                try {
                    Thread.sleep(2);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            } else {
                doPlay(mListBuffer.remove(0));
            }
        }
    }

    private void doPlay(PCMPacket pcmPacket) {
        if (mTrack != null) {
            mTrack.write(pcmPacket.data, 0, 960);
        }
    }


    public void stopPlay() {
        isStopThread = true;
        interrupt();
        if (mTrack != null) {
            mTrack.flush();
            mTrack.stop();
            mTrack.release();
            mTrack = null;
        }
    }

}
