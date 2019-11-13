package appseclab.group2;

import java.io.IOException;
import java.util.logging.Level;

public class CACore {

    static final int PORT_NUMBER = 8080;
    static HttpsServer srvr = new HttpsServer("", PORT_NUMBER);

    public static void main(String[] args) throws IOException {

        Thread t = new Thread(() -> {
                while(true){}
        });

        t.start();
        srvr.start();

        Runtime.getRuntime().addShutdownHook(new Thread(()->{
            CALogger.getInstance().logger.log(Level.INFO, "Shutting down");
            t.stop();
            srvr.stop();
        }));
    }

    public static void shutdown() {
        srvr.stop();
    }
}
