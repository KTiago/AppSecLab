package netsec.group2;

import com.google.gson.Gson;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class CertStructureTest {

    @Before
    public void setUp() throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, SignatureException, OperatorCreationException, NoSuchProviderException, InvalidKeySpecException, InterruptedException {
        UtilsForTests.setUp();
    }

    @After
    public void teardown() {
        CACore.shutdown();
    }

    @Test
    public void setActiveCertTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {

        String testEmail = "waf@wuf.com", testName = "Some Name";
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        assertTrue(CertStructure.getInstance().isActiveCert(testEmail));
    }

    @Test
    public void setRevokedCertsTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {


        String testEmail = "some@randomness.com", testName = "Cheers Mate";

        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        //Get a certificate
        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        assertTrue(CertStructure.getInstance().isActiveCert(testEmail));

        HttpsServer.JSONRevokeQuery q2 = new HttpsServer.JSONRevokeQuery(testEmail);
        String req2 = gson.toJson(q2, HttpsServer.JSONRevokeQuery.class);

        //Revoke the certificate
        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req2, "POST");

        assertFalse(CertStructure.getInstance().isActiveCert(testEmail));
        assertTrue(CertStructure.getInstance().isRevokedCert(testEmail));
    }

    @Test
    public void setKeyCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        String testEmail = "waffel@wuffel.com", testName = "Cheers Mate";
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        assertTrue(CertStructure.getInstance().isKeyCert(testEmail));
    }

    @Test
    public void getRevokedListTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        //Map to store the serial number
        Map<String,Boolean> serialMap = new HashMap<>();

        String testEmail1 = "waffel1@wuffel.com", testName1 = "Cheers Mate";
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail1, testName1);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req,"POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] c = Base64.getDecoder().decode(in.getData());

        File targetFile = new File("pkcstest");
        OutputStream outStream = new FileOutputStream(targetFile);
        outStream.write(c);
        outStream.close();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        java.security.cert.Certificate[] chain = keystore.getCertificateChain(testEmail1);
        if(targetFile.exists())
            targetFile.delete();

        X509Certificate cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put(cert.getSerialNumber().toString(), Boolean.TRUE);

        String testEmail2 = "waffel2@wuffel.com", testName2 = "Cheers Mate";
        gson = new Gson();
        HttpsServer.JSONCertQuery q2 = new HttpsServer.JSONCertQuery(testEmail2, testName2);
        String req2 = gson.toJson(q2, HttpsServer.JSONCertQuery.class);

        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req2, "POST");
        in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        c = Base64.getDecoder().decode(in.getData());
        //Get the serial
        targetFile = new File("pkcstest");
        outStream = new FileOutputStream(targetFile);
        outStream.write(c);
        outStream.close();

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        chain = keystore.getCertificateChain(testEmail2);
        if(targetFile.exists())
            targetFile.delete();

        cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put(cert.getSerialNumber().toString(), Boolean.TRUE);

        String testEmail3 = "waffel3@wuffel.com", testName3 = "Cheers Mate";
        gson = new Gson();
        HttpsServer.JSONCertQuery q3 = new HttpsServer.JSONCertQuery(testEmail3, testName3);
        String req3 = gson.toJson(q3, HttpsServer.JSONCertQuery.class);

        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req3, "POST");
        in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        c = Base64.getDecoder().decode(in.getData());
        //Get the serial
        targetFile = new File("pkcstest");
        outStream = new FileOutputStream(targetFile);
        outStream.write(c);
        outStream.close();

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        chain = keystore.getCertificateChain(testEmail3);
        if(targetFile.exists())
            targetFile.delete();

        cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put(cert.getSerialNumber().toString(), Boolean.TRUE);

        //Revoke 1st and 2nd certificate
        HttpsServer.JSONRevokeQuery q4 = new HttpsServer.JSONRevokeQuery(testEmail1);
        String req4 = gson.toJson(q4, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req4, "POST");

        HttpsServer.JSONRevokeQuery q5 = new HttpsServer.JSONRevokeQuery(testEmail2);
        String req5 = gson.toJson(q5, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req5, "POST");

        HttpsServer.JSONRevokeQuery q6 = new HttpsServer.JSONRevokeQuery(testEmail3);
        String req6 = gson.toJson(q6, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req6, "POST");

        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeList", null, "GET");
        HttpsServer.JSONCertListAnswer inL = gson.fromJson(ans, HttpsServer.JSONCertListAnswer.class);

        List<String> serials = inL.getList();
        assertTrue(serials.size() == serialMap.size());

        for (String s : serials) {
            assertTrue(serialMap.containsKey(s));
        }

        //We revoked 3 certificates
        assertTrue(serialMap.size() == 3);
    }
}
