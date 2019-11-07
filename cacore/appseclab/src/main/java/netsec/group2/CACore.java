package netsec.group2;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.*;

public class CACore {

    static final int PORT_NUMBER = 8080;
    static HttpsServer srvr = new HttpsServer("",PORT_NUMBER);
    private static Logger logger = Logger.getLogger("netsec.group2.cacore");

    public static void main(String[] args) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, SignatureException, InvalidKeyException, OperatorCreationException, InvalidKeySpecException, InterruptedException {
        Handler fh = new FileHandler("cacore.log");
        logger.addHandler(fh);
        logger.setLevel(Level.FINEST);
        logger.log(Level.FINEST, "Logfile created in cacore.log");

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
