package netsec.group2;

import fi.iki.elonen.NanoHTTPD;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.net.ssl.KeyManagerFactory;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
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

            Cert cert = new Cert();

            return newChunkedResponse(Response.Status.OK, "application/x-pkcs12", cert.getCert(email,name));
        } else if(path.equals("/revokeCert")) {

        } else if(path.equals("/revokeList")) {

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
