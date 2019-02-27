# 简介

`Airplay2`是apple在`iOS11.3`中新加的特性，用作视频和音频的局域网投放

`AirplayServer`作为接收端，可以接收来自支持`Airplay2`设备的数据

`AirplayServer`可运行在`Android`设备，代码99%是C语言编写，方便移植

# 功能

1. mDNS发布服务
2. 握手协议
3. 接收镜像数据
4. MediaCodec硬解与展示
5. 接收音频数据
6. fdk-aac音频解码
7. AudioTrack播放PCM音乐

# 演示截图

下图是一次屏幕数据和音乐的投放演示，其中`iPhone`的系统是`iOS12`

![](https://ww1.sinaimg.cn/large/007rAy9hgy1g0l65hwvg7j30u01o0juj.jpg)