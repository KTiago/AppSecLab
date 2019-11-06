package netsec.group2;

import org.bouncycastle.operator.OperatorCreationException;

import javax.json.JsonObject;
import javax.net.ssl.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class UtilsForTests {

    public static void setUp() throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchProviderException, OperatorCreationException, KeyStoreException, InvalidKeySpecException, InterruptedException {
        CACore.main(null);

        //Delete all keystores
        File activeCertsFile = new File("activeCerts");
        if(activeCertsFile.exists())
            activeCertsFile.delete();

        File revokedCertsFile = new File("revokedCerts");
        if(revokedCertsFile.exists())
            revokedCertsFile.delete();

        File certsWithKeysFile = new File("certsWithKeys");
        if(certsWithKeysFile.exists())
            certsWithKeysFile.delete();

        CertStructure.getInstance().initialize();
    }

    public static InputStream sendPayload(String url, JsonObject req, String method) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        URL connect = new URL(url);
        HttpsURLConnection conn = (HttpsURLConnection)connect.openConnection();

        conn.setSSLSocketFactory(acceptAllCerts());
        conn.setHostnameVerifier((hostname, session) -> true);

        conn.setRequestMethod(method);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/jose+json");
        conn.setDoOutput(true);

        byte[] payload = req.toString().getBytes("UTF-8");

        if(payload != null)
            conn.setFixedLengthStreamingMode(payload.length);

        conn.connect();

        if(payload != null) {
            OutputStream out = conn.getOutputStream();
            out.write(payload);
        }

        return conn.getInputStream();
    }

    //Accept all certificates on the server for testing purposes
    private static SSLSocketFactory acceptAllCerts() throws IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException {

        SSLSocketFactory sslSocketFactory;

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                }
        }, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        sslSocketFactory = sc.getSocketFactory();

        return sslSocketFactory;
    }
}
