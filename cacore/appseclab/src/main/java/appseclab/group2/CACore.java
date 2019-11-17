package appseclab.group2;

import java.io.IOException;

public class CACore {

    static final int PORT_NUMBER = Integer.parseInt(System.getenv("port"));
    static HttpsServer srvr = new HttpsServer(System.getenv("hostname"), PORT_NUMBER);

    public static void main(String[] args) {

        Thread t = new Thread(() -> {
            while(true){
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        //Init Logger Singleton
        try {
            CALogger.initCALogger();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        //Init CertStructure Singleton
        try {
            CertStructure.initCertStructure();
        } catch (Exception e) {
            CALogger.getInstance().log("Exception during CertStructure initialization ", e);
            System.exit(-1);
        }

        try {
            srvr.start();
            t.start();
        } catch (IOException e) {
            CALogger.getInstance().log( "exception while starting the HTTPS server", e);
            System.exit(-1);
        }

        Runtime.getRuntime().addShutdownHook(new Thread(()->{
            CALogger.getInstance().log( "Shutting down");
            t.stop();
            srvr.stop();
        }));
    }

    public static void shutdown() {
        srvr.stop();
    }
}
