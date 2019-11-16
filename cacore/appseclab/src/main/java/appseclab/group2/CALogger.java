package appseclab.group2;

import java.io.IOException;
import java.util.logging.*;

public class CALogger {

    private final static Logger logger = Logger.getLogger("CALogger");

    private static CALogger instance = null;

    private CALogger() throws IOException {
        FileHandler fh;
        fh = new FileHandler("cacore.log", true);
        fh.setFormatter(new SimpleFormatter());
        fh.setLevel(Level.ALL);
        logger.addHandler(fh);

        if(System.getenv("debug").equals("true")) {
            ConsoleHandler ch;
            ch = new ConsoleHandler();
            ch.setFormatter(new SimpleFormatter());
            ch.setLevel(Level.ALL);
            logger.addHandler(ch);
        }

        logger.setUseParentHandlers(false);
        logger.setLevel(Level.ALL);
    }

    public static void initCALogger() throws IOException {
        if (instance == null) {
            instance = new CALogger();
        }
    }

    public static CALogger getInstance() {
        return instance;
    }

    public void log(String message) {
        logger.log(Level.INFO, message);
    }

    public void log(String message, Throwable e) {
        logger.log(Level.SEVERE, message, e);
    }
}
