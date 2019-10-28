package netsec.group2;

import fi.iki.elonen.NanoHTTPD;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class CACore {

    static final int PORT_NUMBER = 8080;

    public static void main( String[] args ) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException, InvalidKeySpecException {

        HttpsServer srvr = new HttpsServer("",PORT_NUMBER);
        srvr.makeHttps();
        srvr.start();

        Certs cert = new Certs();
        cert.createCertificate("waf@waf.com", "waffel");

        //Just run for a while
        try {
            Thread.sleep(600000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
