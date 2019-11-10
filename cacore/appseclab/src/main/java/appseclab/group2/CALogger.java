package appseclab.group2;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class CALogger {

    public final static Logger logger = Logger.getLogger("CALogger");

    private static CALogger instance = null;

    private CALogger() {
        FileHandler fh;
        try {
            fh = new FileHandler("cacore.log", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setUseParentHandlers(false);
            logger.setLevel(Level.FINEST);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static CALogger getInstance() {
        if (instance == null) {
            instance = new CALogger();
        }

        return instance;
    }
}
