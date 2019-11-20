package appseclab.group2;

import com.google.gson.Gson;
import com.google.security.Security;
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

public class HttpsServer extends NanoHTTPD {

    public enum Status {
        VALID,
        INVALID
    }

    public static class JSONQuery {
        protected String pw = "";

        public JSONQuery(String pw) {
            this.pw = pw;
        }
    }

    public static class JSONCertQuery {
        private String email = "";
        private String name = "";
        private String pw = "";

        public JSONCertQuery(String email, String name, String pw) {
            this.email = email;
            this.name = name;
            this.pw = pw;
        }
    }

    public static class JSONRevokeQuery {
        private String serialNumber = "";
        private String pw = "";

        public JSONRevokeQuery(String serialNumber, String pw) {
            this.serialNumber = serialNumber;
            this.pw = pw;
        }
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

    public class JSONRevokeAnswer {
        private Status status;
        private String data = "";
        private String crl = "";

        public JSONRevokeAnswer(Status status, String data, String crl) {
            this.status = status;
            this.data = data;
            this.crl = crl;
        }

        public String getJson() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }

        public String getData() {
            return data;
        }

        public String getCRL() {
            return crl;
        }
    }

    public class JSONCertAnswer {
        private Status status;
        private String data = "";
        private String sn = "";

        public JSONCertAnswer(Status status, String data, String sn) {
            this.status = status;
            this.data = data;
            this.sn = sn;
        }

        public String getJson() {
            Gson gson = new Gson();
            return gson.toJson(this);
        }

        public String getData() {
            return data;
        }

        public String getSn() {
            return sn;
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

    private final String pw = System.getenv("sharedPw");

    public HttpsServer(String hostname, int port) {
        super(hostname, port);
    }

    @Override
    public Response serve(IHTTPSession session) {
        String path = session.getUri();
        Gson gson = new Gson();

        //Define endpoints
        switch (path) {
            case "/getCert": {
                CALogger.getInstance().log("getCert request received");
                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /getCert");
                    CALogger.getInstance().log("getCert request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    CALogger.getInstance().log("exception during parsing the body of getCert request", e);
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "error parsing body of /getCert request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                gson = new Gson();
                JSONCertQuery q = gson.fromJson(body.get("postData"), JSONCertQuery.class);
                String email = q.email;
                String name = q.name;

                CALogger.getInstance().log("getCert parameters are email='" + email + "' name='" + name + "'");

                if (!Security.safeEquals(pw, q.pw)) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Invalid identification");
                    CALogger.getInstance().log("wrong token in the request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                if (CertStructure.getInstance().isCertificateActive(email)) {
                    CALogger.getInstance().log("Certificate already active for '" + email + "'");
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Certificate already active for that email");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                CertTuple certTup = CertStructure.getInstance().createCert(email, name);
                byte[] cert = certTup.getCert();
                String sn = certTup.getSn();
                String encodedCert = java.util.Base64.getEncoder().withoutPadding().encodeToString(cert);
                JSONCertAnswer ans = new JSONCertAnswer(Status.VALID, encodedCert, sn);
                CALogger.getInstance().log("New certificate for '" + email + "' sent");
                return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
            }
            case "/revokeCert": {
                CALogger.getInstance().log("revokeCert request received");
                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /revokeCert");
                    CALogger.getInstance().log("revokeCert request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    CALogger.getInstance().log("exception during parsing the body of revokeCert request", e);
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "error parsing body of /revokeCert request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                gson = new Gson();
                JSONRevokeQuery q = gson.fromJson(body.get("postData"), JSONRevokeQuery.class);
                String serialNumber = q.serialNumber;

                CALogger.getInstance().log("revokeCert parameter is serialNumber='" + serialNumber + "'");

                if (!Security.safeEquals(pw, q.pw)) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Invalid identification");
                    CALogger.getInstance().log("wrong token in the request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                if (CertStructure.getInstance().addRevokedCert(serialNumber)) {
                    String crl = CertStructure.getInstance().getCRL();
                    JSONRevokeAnswer ans = new JSONRevokeAnswer(Status.VALID, "Certificate successfully revoked", crl);
                    CALogger.getInstance().log("Certificate with serial number '" + serialNumber + "' as been revoked");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                } else {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Could not revoke certificate");
                    CALogger.getInstance().log("Certificate can't be revoked");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }
            }
            case "/getAdminInfos": {
                CALogger.getInstance().log("getAdminInfos request received");
                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /getAdminInfos");
                    CALogger.getInstance().log("getAdminInfos request was not POST");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    CALogger.getInstance().log("exception during parsing the body of getAdminInfos request", e);
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "error parsing body of /getAdminInfos request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                gson = new Gson();
                JSONQuery q = gson.fromJson(body.get("postData"), JSONQuery.class);

                if (!Security.safeEquals(pw, q.pw)) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Invalid identification");
                    CALogger.getInstance().log("wrong token in the request");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                String issuedCert = Integer.toString(CertStructure.getInstance().getIssuedCertNumber());
                String revokedCert = Integer.toString(CertStructure.getInstance().getRevokedCertNumber());
                String sn = CertStructure.getInstance().getSerialNumber();
                JSONAdminInfos adminInfos = new JSONAdminInfos(Status.VALID, issuedCert, revokedCert, sn);
                CALogger.getInstance().log("admin infos sent");
                return newFixedLengthResponse(Response.Status.OK, "json/application", adminInfos.getJson());
            }
            default:
                JSONAnswer ans = new JSONAnswer(Status.INVALID, "Request not properly formed");
                CALogger.getInstance().log("Invalid request received");
                return newFixedLengthResponse(Response.Status.OK, "json/application", ans.getJson());
        }
    }

    @Override
    public void start() throws IOException {
        try {
            this.makeHttps();
        } catch (Exception e) {
            throw new IOException(e);
        }
        super.start();
        CALogger.getInstance().log("HTTPS Server started");
    }

    public void makeHttps() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load( new FileInputStream("certs/tls/tls.p12"), System.getenv("tlsPw").toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks, System.getenv("tlsPw").toCharArray());

        this.makeSecure(makeSSLSocketFactory(ks,keyManagerFactory),null);
    }
}
