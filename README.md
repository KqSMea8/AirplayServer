# Introduction

An open-source implementation of an AirPlay mirroring server for the Raspberry Pi.
The goal is to make it run smoothly even on a Raspberry Pi Zero.

# State

For now, only screen mirroring works. The GPU is used for decoding the h264
video stream. Unfortunately, the Pi has no hardware acceleration for audio
(AirPlay uses AAC), so a software decoder has to be integrated, which I 
haven't tackled yet.
It seems the Pi Zero is a bit too weak for running the current implementation
at 30fps, so improving the video speed has priority for now. 

By using OpenSSL for AES decryption, I was able to speed up the decryption of
video packets from up to 0.2 seconds to up to 0.007 seconds for large packets
(On the Pi Zero). Average is now more like 0.002 seconds.

# Todo

1. Use OpenSSL for 

2. Properly handle timestamps for video samples

3. Add software decoder for AAC audio