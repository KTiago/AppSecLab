package appseclab.group2;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;

public class UtilsForTests {
    public static String sendPayload(String url, String req, String method) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        URL connect = new URL(url);
        HttpsURLConnection conn = (HttpsURLConnection)connect.openConnection();

        conn.setSSLSocketFactory(acceptAllCerts());
        conn.setHostnameVerifier((hostname, session) -> true);

        conn.setRequestMethod(method);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        byte[] payload = null;
        if(!method.equals("GET"))
            payload = req.getBytes("UTF-8");

        if(payload != null)
            conn.setFixedLengthStreamingMode(payload.length);

        conn.connect();

        if(payload != null) {
            OutputStream out = conn.getOutputStream();
            out.write(payload);
        }

        InputStream in = conn.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length = 0;
        while ((length = in.read(buffer)) != -1) {
            baos.write(buffer, 0, length);
        }

        return baos.toString();
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
