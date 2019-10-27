package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;

public class Entry {

    static final int PORT_NUMBER = 8080;

    public static void main( String[] args ) throws IOException {

        HttpsServer srvr = new HttpsServer("",PORT_NUMBER);
        srvr.start();



    }
}
