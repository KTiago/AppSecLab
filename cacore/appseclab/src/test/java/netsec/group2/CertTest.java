package netsec.group2;


import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import static junit.framework.TestCase.assertTrue;

public class CertTest {

    @Before
    public void setup() throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchProviderException, OperatorCreationException, KeyStoreException, InvalidKeySpecException {
        CACore.main(null);
    }

    @Test
    public void getCert() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        URL url = new URL("https://localhost:"+CACore.PORT_NUMBER+"/getCert");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        conn.setSSLSocketFactory(acceptAllCerts());
        conn.setHostnameVerifier((hostname, session) -> true);

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/jose+json");
        conn.setDoOutput(true);

        String testEmail = "waf@wuf.com", testName = "Some Name";
        JsonObject req = Json.createObjectBuilder()
                .add("email",testEmail)
                .add("name",testName)
                .build();

        byte[] payload = req.toString().getBytes("UTF-8");

        if(payload != null)
            conn.setFixedLengthStreamingMode(payload.length);

        conn.connect();

        if(payload != null) {
            OutputStream out = conn.getOutputStream();
            out.write(payload);
        }

        File targetFile = new File("pkcstest");
        OutputStream outStream = new FileOutputStream(targetFile);

        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = conn.getInputStream().read(buffer)) != -1) {
            outStream.write(buffer, 0, bytesRead);
        }
        outStream.close();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        Certificate[] chain = keystore.getCertificateChain(testEmail);

        X509Certificate leafCert = (X509Certificate)chain[0];

        X500Name x500name = new JcaX509CertificateHolder(leafCert).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        RDN ou = x500name.getRDNs(BCStyle.OU)[0];

        assertTrue(IETFUtils.valueToString(cn.getFirst().getValue()).equals(testEmail));
        assertTrue(IETFUtils.valueToString(ou.getFirst().getValue()).equals(testName));

        //To verify if the signing was done with the root key, we have to load it
        final String ROOT_CA = "certs/root/rootstore.p12";
        final String ROOT_CA_PASSWORD = "wafwaf";
        final String ROOT_CA_ALIAS = "rootcert";

        KeyStore rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream("certs/root/rootstore.p12"), "wafwaf".toCharArray());

        Certificate rootCert = rootStore.getCertificate("rootcert");

        try {
            leafCert.verify(rootCert.getPublicKey());
        } catch (Exception e) {
            assertTrue(false);
        }
        assertTrue(true);

        File tmp = new File("pkcstest");
        assertTrue(tmp.delete());
    }

    //Accept all certificates on the server for testing purposes
    private SSLSocketFactory acceptAllCerts() throws IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException {

        SSLSocketFactory sslSocketFactory;

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        sslSocketFactory = sc.getSocketFactory();

        return sslSocketFactory;
    }

    TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
    };

}
