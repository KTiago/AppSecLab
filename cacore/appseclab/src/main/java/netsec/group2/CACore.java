package netsec.group2;

import fi.iki.elonen.NanoHTTPD;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class CACore {

    static final int PORT_NUMBER = 8080;
    static HttpsServer srvr = new HttpsServer("",PORT_NUMBER);
    public static void main(String[] args) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException, InvalidKeySpecException, InterruptedException {

        Thread t = new Thread(() -> {
                while(true){}
        });

        t.start();
        srvr.start();

        Runtime.getRuntime().addShutdownHook(new Thread(()->{
            t.stop();
            srvr.stop();
        }));
    }

    public static void shutdown() {
        srvr.stop();
    }
}
