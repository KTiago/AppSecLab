package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.*;

import com.google.gson.*;
import org.bouncycastle.util.encoders.Base64;


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
        private String email = "";

        public JSONRevokeQuery(String email) {
            this.email = email;
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
                File certFile = new File("certs/certGen");
                if (certFile.exists()) {
                    certFile.delete();
                }

                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /getCert");
                    return newFixedLengthResponse(Response.Status.BAD_REQUEST, "application/json", ans.getJson());
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


                if (CertStructure.getInstance().isActiveCert(email)) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Certificate already active for that email");
                    return newFixedLengthResponse(Response.Status.BAD_REQUEST, "application/json", ans.getJson());
                }

                Cert cert = new Cert();

                String encodedCert = Base64.toBase64String(cert.getCert(email, name));

                JSONAnswer ans = new JSONAnswer(Status.VALID, encodedCert);
                return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
            }
            case "/revokeCert": {
                if (!Method.POST.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "POST Request needed for /revokeCert");
                    return newFixedLengthResponse(Response.Status.BAD_REQUEST, "application/json", ans.getJson());
                }

                Map<String, String> body = new HashMap<>();
                try {
                    session.parseBody(body);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Gson gson = new Gson();
                String email = gson.fromJson(body.get("postData"), JSONRevokeQuery.class).email;

                boolean success = CertStructure.getInstance().setRevokedCert(email);

                if (success) {
                    JSONAnswer ans = new JSONAnswer(Status.VALID, "");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                } else {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "Could not revoke certificate");
                    return newFixedLengthResponse(Response.Status.BAD_REQUEST, "application/json", ans.getJson());
                }
            }
            case "/revokeList": {
                if (!Method.GET.equals(session.getMethod())) {
                    JSONAnswer ans = new JSONAnswer(Status.INVALID, "GET Request needed for /revokeCert");
                    return newFixedLengthResponse(Response.Status.OK, "application/json", ans.getJson());
                }

                JSONCertListAnswer revokedCert = new JSONCertListAnswer(Status.VALID, CertStructure.getInstance().getRevokedList());

                return newFixedLengthResponse(Response.Status.OK, "application/json", revokedCert.getJson());
            }
            case "/getAdminInfos": {
                String issuedCert = Integer.toString(CertStructure.getInstance().getIssuedCertNumber());
                String revokedCert = Integer.toString(CertStructure.getInstance().getRevokedCertNumber());
                String sn = CertStructure.getInstance().getSerialNumber();
                JSONAdminInfos adminInfos = new JSONAdminInfos(Status.VALID, issuedCert, revokedCert, sn);
                return newFixedLengthResponse(Response.Status.OK, "json/application", adminInfos.getJson());
            }
            default:
                JSONAnswer ans = new JSONAnswer(Status.INVALID, "Request not properly formed");
                return newFixedLengthResponse(Response.Status.BAD_REQUEST, "json/application", ans.getJson());
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
    }

    public void makeHttps() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load( new FileInputStream( "certs/root/rootstore.p12" ),    "wafwaf".toCharArray());
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ks, "wafwaf".toCharArray());

        this.makeSecure(makeSSLSocketFactory(ks,keyManagerFactory),null);
    }
}
