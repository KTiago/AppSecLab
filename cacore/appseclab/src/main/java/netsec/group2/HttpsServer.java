package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.xml.ws.Response;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;


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

    public void makeHttps() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load( new FileInputStream( "certs/rootcertstore.jks" ),    "wafwaf".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks, "wafwaf".toCharArray());

        this.makeSecure(makeSSLSocketFactory(ks,keyManagerFactory),null);
    }
}
