package netsec.group2;


import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static junit.framework.TestCase.assertTrue;

public class CertTest {

    @Before
    public void setup() throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchProviderException, OperatorCreationException, KeyStoreException, InvalidKeySpecException, InterruptedException {
        UtilsForTests.setUp();
    }

    @After
    public void tearDown() {
        CACore.shutdown();
        File tmp = new File("pkcstest");
        if(tmp.exists())
            tmp.delete();
    }

    @Test
    public void getCert() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        String testEmail = "waf@wuf.com", testName = "Some Name";
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        String ans = UtilsForTests.sendPayload("https://localhost:" + CACore.PORT_NUMBER + "/getCert", req, "POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] c = Base64.getDecoder().decode(in.getData());
        File targetFile = new File("pkcstest");
        OutputStream outStream = new FileOutputStream(targetFile);
        outStream.write(c);
        outStream.close();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        Certificate[] chain = keystore.getCertificateChain(testEmail);

        X509Certificate leafCert = (X509Certificate) chain[0];

        X500Name x500name = new JcaX509CertificateHolder(leafCert).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        RDN ou = x500name.getRDNs(BCStyle.OU)[0];

        assertTrue(IETFUtils.valueToString(cn.getFirst().getValue()).equals(testEmail));
        assertTrue(IETFUtils.valueToString(ou.getFirst().getValue()).equals(testName));

        //To verify if the signing was done with the root key, we have to load it
        KeyStore rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream("certs/root/rootstore.p12"), "wafwaf".toCharArray());

        Certificate rootCert = rootStore.getCertificate("rootcert");

        try {
            leafCert.verify(rootCert.getPublicKey());
        } catch (Exception e) {
            assertTrue(false);
        }
    }
}
