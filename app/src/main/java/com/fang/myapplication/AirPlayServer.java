package com.fang.myapplication;

import android.util.Log;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class AirPlayServer {

    public static String TAG = "AirPlayServer";

    private ServerSocket mServerSocket = null;
    private ServerThread mServerThread = null;

    public AirPlayServer() {

    }


    public void startServer() {
        try {
            mServerSocket = new ServerSocket(0);
        } catch (IOException e) {
            e.printStackTrace();
        }
        mServerThread = new ServerThread();
        mServerThread.start();
    }

    public void stopServer() {
        try {
            mServerSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public int getPort() {
        if (mServerSocket != null) {
            return mServerSocket.getLocalPort();
        }
        return 0;
    }


    class ServerThread extends Thread {

        @Override
        public void run() {
            try {
                Socket socket = mServerSocket.accept();
                Log.d(TAG, "receive accept");
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
