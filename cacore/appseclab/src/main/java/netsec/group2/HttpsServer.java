package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import javax.xml.ws.Response;
import java.io.IOException;


public class HttpsServer extends NanoHTTPD {

    public HttpsServer(String hostname, int port) {
        super(hostname, port);
    }

    @Override
    public Response serve(IHTTPSession session) {
        String path = session.getUri();
        if(path.equals("/getCertificate")) {
            return newFixedLengthResponse(Response.Status.OK, "text/plain", "Waf waf");
        } else if(path.equals("/revokeCertificate")) {

        }
        return newFixedLengthResponse(Response.Status.OK, "text/plain", "Even more waf");
    }

    @Override
    public void start() throws IOException {
        super.start();
    }

}
