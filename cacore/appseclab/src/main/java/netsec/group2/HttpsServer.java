package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class HttpsServer extends NanoHTTPD {


    public HttpsServer(String hostname, int port) {
        super(hostname, port);
    }

    @Override
    public Response serve(IHTTPSession session) {
        String path = session.getUri();

        //Define endpoints
        if(path.equals("/getCert")) {

            File certFile = new File("certs/certGen");
            if(certFile.exists())
                certFile.delete();

            if(!Method.POST.equals(session.getMethod()))
                return newFixedLengthResponse(Response.Status.OK, "text/plain", "POST Request needed for /getCert");

            Map<String,String> body = new HashMap<>();
            try {
                session.parseBody(body);
            } catch (Exception e) {
                e.printStackTrace();
            }

            JsonReader reader = Json.createReader(new StringReader(body.get("postData")));
            JsonObject obj = reader.readObject();

            String email = obj.get("email").toString();
            email = email.substring(1,email.length()-1);
            String name = obj.get("name").toString();
            name = name.substring(1,name.length()-1);

            if(CertStructure.getInstance().isActiveCert(email))
                return newFixedLengthResponse(Response.Status.OK, "text/plain", "Certificate already active for that email");

            Cert cert = new Cert();

            return newChunkedResponse(Response.Status.OK, "application/x-pkcs12", cert.getCert(email,name));
        } else if(path.equals("/revokeCert")) {
            if(!Method.POST.equals(session.getMethod()))
                return newFixedLengthResponse(Response.Status.OK, "text/plain", "POST Request needed for /revokeCert");

            Map<String,String> body = new HashMap<>();
            try {
                session.parseBody(body);
            } catch (Exception e) {
                e.printStackTrace();
            }

            JsonReader reader = Json.createReader(new StringReader(body.get("postData")));
            JsonObject obj = reader.readObject();

            String email = obj.get("email").toString();
            email = email.substring(1,email.length()-1);

            boolean success = CertStructure.getInstance().setRevokedCert(email);

            if(success)
                return newFixedLengthResponse(Response.Status.OK, "text/plain", "Success");
            else
                return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Could not revoke certificate");
        } else if(path.equals("/revokeList")) {

            if(!Method.GET.equals(session.getMethod()))
                return newFixedLengthResponse(Response.Status.OK, "text/plain", "GET Request needed for /revokeCert");

            List<String> serialList = CertStructure.getInstance().getRevokedList();

            //There's no easy way to build a json object iteratively (in a loop)
            String arr = "{\"serials\":[";
            for(int i = 0; i < serialList.size(); ++i) {
                arr += "\"" + serialList.get(i) + "\"";
                if(i != serialList.size()-1)
                    arr += ",";
            }
            arr += "]}";

            JsonObject ret = Json.createReader(new StringReader(arr)).readObject();
            InputStream inputStream = null;
            try {
                inputStream = new ByteArrayInputStream(ret.toString().getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }

            if(inputStream == null)
                return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Failure");
            else
                return newChunkedResponse(Response.Status.OK, "application/json", inputStream);
        }

        return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Request not properly formed");
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
