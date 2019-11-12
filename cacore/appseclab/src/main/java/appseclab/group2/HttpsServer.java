package appseclab.group2;

import com.google.gson.Gson;
import fi.iki.elonen.NanoHTTPD;

import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;



public class HttpsServer extends NanoHTTPD {

    public enum Status {
        VALID,
        INVALID
    }

    public class JSONAnswer {
        private Status status;
        private String data = "";

        public JSONAnswer(Status status, String data) {
            this.status = status;
            this.data = data;
        }

        public String getJson() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }

        public String getData() {
            return this.data;
        }
    }

    public static class JSONCertQuery {
        private String email = "";
        private String name = "";

        public JSONCertQuery(String email, String name) {
            this.email = email;
            this.name = name;
        }
    }

    public static class JSONRevokeQuery {
        private String serialNumber = "";

        public JSONRevokeQuery(String serialNumber) {
            this.serialNumber = serialNumber;
        }
    }

    public class JSONCertListAnswer {
        private Status status;
        private List<String> serials;

        public JSONCertListAnswer(Status status, List<String> serials) {
            this.status = status;
            this.serials = new ArrayList<>(serials);
        }

        public String getJson() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }

        public List<String> getList() {
            return new ArrayList<>(this.serials);
        }
    }

    public class JSONAdminInfos {
        private Status status;
        private String issuedCert;
        private String revokedCert;
        private String sn;

        public JSONAdminInfos(Status status, String issuedCert, String revokedCert, String sn) {
            this.status = status;
            this.issuedCert = issuedCert;
            this.revokedCert = revokedCert;
            this.sn = sn;
        }

        public String getJson() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }
    }

    public HttpsServer(String hostname, int port) {
        super(hostname, port);
    }

    @Override
    public Response serve(IHTTPSession session) {
        String path = session.getUri();

        //Define endpoints
        switch (path) {
            case "/getCert": {
                CALogger.getInstance().logger.log(Level.INFO, "getCert request received");
                File certFile = new File("certs/certGen");
                if (certFile.exists()) {
                    certFile.delete();
                }

                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /getCert");
                    CALogger.getInstance().logger.log(Level.INFO, "getCert request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Gson gson = new Gson();
                JSONCertQuery q = gson.fromJson(body.get("postData"), JSONCertQuery.class);
                String email = q.email;
                String name = q.name;

                CALogger.getInstance().logger.log(Level.INFO, "getCert parameters are email='" + email + "' name='" + name + "'");

                if (CertStructure.getInstance().isCertificateActive(email)) {
                    CALogger.getInstance().logger.log(Level.INFO, "Certificate already active for '" + email + "'");
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Certificate already active for that email");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                String encodedCert = java.util.Base64.getEncoder().withoutPadding().encodeToString(CertStructure.getInstance().createCert(email, name));

                JSONAnswer ans = new JSONAnswer(Status.VALID, encodedCert);
                CALogger.getInstance().logger.log(Level.INFO, "New certificate for '" + email + "' sent");
                return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
            }
            case "/revokeCert": {
                CALogger.getInstance().logger.log(Level.INFO, "revokeCert request received");
                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /revokeCert");
                    CALogger.getInstance().logger.log(Level.INFO, "revokeCert request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Gson gson = new Gson();
                String serialNumber = gson.fromJson(body.get("postData"), JSONRevokeQuery.class).serialNumber;

                CALogger.getInstance().logger.log(Level.INFO, "revokeCert parameter is serialNumber='" + serialNumber + "'");
                boolean success = CertStructure.getInstance().addRevokedCert(serialNumber);

                if (success) {
                    JSONAnswer ans = new JSONAnswer(Status.VALID, "");
                    CALogger.getInstance().logger.log(Level.INFO, "Certificate with serial number '" + serialNumber + "' as been revoked");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                } else {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Could not revoke certificate");
                    CALogger.getInstance().logger.log(Level.INFO, "Certificate can't be revoked");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }
            }
            case "/revokeList": {
                CALogger.getInstance().logger.log(Level.INFO, "revokeList request received");
                if (!Method.GET.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "GET Request needed for /revokeCert");
                    CALogger.getInstance().logger.log(Level.INFO, "revokeList request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                JSONCertListAnswer revokedCert = new JSONCertListAnswer(Status.VALID, CertStructure.getInstance().getRevokedList());
                CALogger.getInstance().logger.log(Level.INFO, "revokeList sent");
                return newFixedLengthResponse(Response.Status.OK, "application/json", revokedCert.getJson());
            }
            case "/getAdminInfos": {
                CALogger.getInstance().logger.log(Level.INFO, "getAdminInfos request received");
                String issuedCert = Integer.toString(CertStructure.getInstance().getIssuedCertNumber());
                String revokedCert = Integer.toString(CertStructure.getInstance().getRevokedCertNumber());
                String sn = CertStructure.getInstance().getSerialNumber();
                JSONAdminInfos adminInfos = new JSONAdminInfos(Status.VALID, issuedCert, revokedCert, sn);
                CALogger.getInstance().logger.log(Level.INFO, "admin infos sent");
                return newFixedLengthResponse(Response.Status.OK, "json/application", adminInfos.getJson());
            }
            default:
                JSONAnswer ans = new JSONAnswer(Status.INVALID, "Request not properly formed");
                CALogger.getInstance().logger.log(Level.INFO, "Invalid request received");
                return newFixedLengthResponse(Response.Status.OK, "json/application", ans.getJson());
        }
    }

    @Override
    public void start() throws IOException {
        try {
            this.makeHttps();
        } catch (Exception e) {
            e.printStackTrace();
        }
        super.start();
        CALogger.getInstance().logger.log(Level.INFO, "HTTPS Server started");
    }

    public void makeHttps() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load( new FileInputStream( "certs/root/rootstore.p12" ),    "wafwaf".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks, "wafwaf".toCharArray());

        this.makeSecure(makeSSLSocketFactory(ks,keyManagerFactory),null);
    }
}
