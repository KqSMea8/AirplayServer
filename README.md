# Introduction

An open-source implementation of an AirPlay mirroring server for the Raspberry Pi.
The goal is to make it run smoothly even on a Raspberry Pi Zero.

# State

For now, only screen mirroring works. The GPU is used for decoding the h264
video stream. Unfortunately, the Pi has no hardware acceleration for audio
(AirPlay uses AAC), so a software decoder has to be integrated, which I 
haven't done yet.
It seems the Pi Zero is a bit too weak for running the current implementation
at 30fps, so improving the video speed has priority for now. 

# Todo

1. Use OpenSSL instead of the various individual crypto pieces
From my tests, decrypting the video frames alone takes up to 0.2 seconds for some
larger packets. We're partly using code from tiny-AES, which has its focus on
code size, but not speed. According to figures from http://www.nm.ifi.lmu.de/pub/Fopras/paul17/PDF-Version/paul17.pdf,
OpenSSL is about 200x faster for decryption.

2. Properly handle timestamps for video samples

3. Add software decoder for AAC audio