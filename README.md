# Introduction

An open-source implementation of an AirPlay mirroring server for the Raspberry Pi.
The goal is to make it run smoothly even on a Raspberry Pi Zero.

# State

Screen mirroring and audio works. The GPU is used for decoding the h264
video stream. The Pi has no hardware acceleration for audio (AirPlay uses AAC), 
so the FDK-AAC decoder is used for that.
Unfortunately, it seems the Pi Zero is too slow for decoding audio at
a reasonable speed.

In order to get audio decoding fast enough for the Pi Zero, we likely have
to use a different AAC decoder library. 

By using OpenSSL for AES decryption, I was able to speed up the decryption of
video packets from up to 0.2 seconds to up to 0.007 seconds for large packets
(On the Pi Zero). Average is now more like 0.002 seconds.

There still are some playback issues. Have a look at the TODO list below.

Please note RPiPlay might not be suitable for remote video playback, as it
lacks a dedicated component for that: It seems like AirPlay on an AppleTV
switches to a standard AirPlay connection when video playback starts, thus
avoiding the re-encoding of the video.
For details, refer to the [inofficial AirPlay specification](https://nto.github.io/AirPlay.html#screenmirroring).

# Building

The following packages are required for building on Raspbian:

* **cmake** (for the build system)
* **libavahi-compat-libdnssd-dev** (for the bonjour registration)
* **libssl-dev** (for crypto primitives)
* **iclient** and Broadcom's OpenMAX stack as present in `/opt/vc` in Raspbian.

For building on a fresh Raspbian install, these steps should be run in the 
project's root folder:

```bash
sudo apt-get install cmake
sudo apt-get install libavahi-compat-libdnssd-dev
sudo apt-get install libssl-dev
mkdir build
cd build
cmake ..
make
```

# Usage

Start the airplay_server executable and an AirPlay mirror target device will appear in the network.
At the moment, these options are implemented:

**-n name**: Specify the network name of the AirPlay server

**-b**: Hide the black background behind the video

**-a (hdmi|analog|off)**: Set audio output device

**-v/-h**: Displays short help and version information

# Authors

The code in this repository accumulated from various sources over time. Here is my attempt at listing the various authors and the components they created:

* **dsafa22**: Created an [AirPlay 2 mirroring server](https://github.com/dsafa22/AirplayServer) for Android based on ShairPlay. This project is basically a port of dsafa22's code to the Raspberry Pi, utilizing OpenMAX and OpenSSL for better performance on the Pi. All code in `lib/` with a header crediting `Administrator` is dsafa22's work. License: unknown
* **Juho Vähä-Herttua** and contributors: Created an AirPlay audio server called [ShairPlay](https://github.com/juhovh/shairplay), including support for Fairplay based on PlayFair. Most of the code in `lib/` originally stems from this project. License: GNU LGPLv2.1+
* **EstebanKubata**: Created a FairPlay library called [PlayFair](https://github.com/EstebanKubata/playfair). Located in the `lib/playfair` folder. License: GNU GPL
* **Jonathan Beck, Nikias Bassen** and contributors: Created a library for plist handling called [libplist](https://github.com/libimobiledevice/libplist). Located in the `lib/plist` folder. License: GNU LGPLv2.1+

* **Joyent, Inc and contributors**: Created an http library called [http-parser](https://github.com/nodejs/http-parser). Located at `lib/http_parser.(c|h)`. License: MIT
* **Google, Inc and contributors**: Created an implementation of curve 25519 called [curve25519-donna](https://github.com/agl/curve25519-donna). Located in the `lib/curve25519` folder. License: 3-Clause BSD
* **Team XBMC**: Managed to show a black background for OpenMAX video rendering. This code is used in the video renderer. License: GNU GPL
* **Orson Peters and contributors**: An implementation of [Ed25519](https://github.com/orlp/ed25519) signatures. Located in `lib/ed25519`, License: ZLIB; Depends on LibTomCrypt, License: Public Domain

# Contributing

I'm not planning to regularly maintain this project. Instead, I'm hoping this project can be improved in a community effort. I'll fix and add as much as I need for personal use, and I count on you to do the same!

Your contributions are more than welcome!

# Todo

* Use OpenSSL for the elliptic curve crypto?
* Add help command and print version
* Bug: Sometimes cannot be stopped
* Bug: Frequent playback stalls
