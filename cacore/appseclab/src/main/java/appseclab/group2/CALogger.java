package appseclab.group2;

import java.io.IOException;
import java.util.logging.*;

public class CALogger {

    public final static Logger logger = Logger.getLogger("CALogger");

    private static CALogger instance = null;

    private CALogger() {
        FileHandler fh;
        ConsoleHandler ch;
        try {
            fh = new FileHandler("cacore.log", true);
            fh.setFormatter(new SimpleFormatter());
            fh.setLevel(Level.ALL);

            ch = new ConsoleHandler();
            ch.setFormatter(new SimpleFormatter());
            ch.setLevel(Level.ALL);

            logger.addHandler(fh);
            logger.addHandler(ch);
            logger.setUseParentHandlers(false);
            logger.setLevel(Level.ALL);
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
