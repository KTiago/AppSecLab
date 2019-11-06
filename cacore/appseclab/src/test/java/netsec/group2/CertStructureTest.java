package netsec.group2;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.json.*;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
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
        JsonObject req = Json.createObjectBuilder()
                .add("email",testEmail)
                .add("name",testName)
                .build();

        InputStream in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        //We don't care about the output, just consume the buffer
        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) {}

        assertTrue(CertStructure.getInstance().isActiveCert(testEmail));
    }

    @Test
    public void setRevokedCertsTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {


        String testEmail = "some@randomness.com", testName = "Cheers Mate";
        JsonObject req = Json.createObjectBuilder()
                .add("email",testEmail)
                .add("name",testName)
                .build();

        //Get a certificate
        InputStream in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) {}

        JsonObject req2 = Json.createObjectBuilder()
                .add("email",testEmail)
                .build();

        assertTrue(CertStructure.getInstance().isActiveCert(testEmail));

        //Revoke the certificate
        InputStream in2 = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req2, "POST");
        byte[] buffer2 = new byte[8192];
        while (in2.read(buffer2) != -1) {}

        assertFalse(CertStructure.getInstance().isActiveCert(testEmail));
        assertTrue(CertStructure.getInstance().isRevokedCert(testEmail));
    }

    @Test
    public void setKeyCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        String testEmail = "waffel@wuffel.com", testName = "Cheers Mate";
        JsonObject req = Json.createObjectBuilder()
                .add("email",testEmail)
                .add("name",testName)
                .build();

        InputStream in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        //We don't care about the output, just consume the buffer
        byte[] buffer = new byte[8192];
        while (in.read(buffer) != -1) {}

        assertTrue(CertStructure.getInstance().isKeyCert(testEmail));
    }

    @Test
    public void getRevokedListTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        //Map to store the serial number
        Map<String,Boolean> serialMap = new HashMap<>();

        String testEmail1 = "waffel1@wuffel.com", testName1 = "Cheers Mate";
        JsonObject req1 = Json.createObjectBuilder()
                .add("email",testEmail1)
                .add("name",testName1)
                .build();

        InputStream in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req1,"POST");

        //Get the serial
        File targetFile = new File("pkcstest");
        OutputStream outStream = new FileOutputStream(targetFile);

        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            outStream.write(buffer, 0, bytesRead);
        }
        outStream.close();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        java.security.cert.Certificate[] chain = keystore.getCertificateChain(testEmail1);
        if(targetFile.exists())
            targetFile.delete();

        X509Certificate cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put("\""+cert.getSerialNumber().toString()+"\"",Boolean.TRUE);

        String testEmail2 = "waffel2wuffel.com", testName2 = "Cheers Mate";
        JsonObject req2 = Json.createObjectBuilder()
                .add("email",testEmail2)
                .add("name",testName2)
                .build();

        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req2, "POST");

        //Get the serial
        targetFile = new File("pkcstest");
        outStream = new FileOutputStream(targetFile);

        while ((bytesRead = in.read(buffer)) != -1) {
            outStream.write(buffer, 0, bytesRead);
        }
        outStream.close();

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        chain = keystore.getCertificateChain(testEmail2);
        if(targetFile.exists())
            targetFile.delete();

        cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put("\""+cert.getSerialNumber().toString()+"\"",Boolean.TRUE);

        String testEmail3 = "waffel3@wuffel.com", testName3 = "Cheers Mate";
        JsonObject req3 = Json.createObjectBuilder()
                .add("email",testEmail3)
                .add("name",testName3)
                .build();

        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req3, "POST");

        //Get the serial
        targetFile = new File("pkcstest");
        outStream = new FileOutputStream(targetFile);

        while ((bytesRead = in.read(buffer)) != -1) {
            outStream.write(buffer, 0, bytesRead);
        }
        outStream.close();

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("pkcstest"), "".toCharArray());

        chain = keystore.getCertificateChain(testEmail3);
        if(targetFile.exists())
            targetFile.delete();

        cert = (X509Certificate)chain[0];

        //Add the serial number to the map, will be checked later
        serialMap.put("\""+cert.getSerialNumber().toString()+"\"",Boolean.TRUE);

        //Revoke 1st and 2nd certificate
        JsonObject req4 = Json.createObjectBuilder()
                .add("email",testEmail1)
                .build();

        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req4, "POST");


        //We don't care about the output, just consume the buffer
        while (in.read(buffer) != -1) {}

        JsonObject req5 = Json.createObjectBuilder()
                .add("email",testEmail2)
                .build();

        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req5, "POST");

        //We don't care about the output, just consume the buffer
        while (in.read(buffer) != -1) {}

        JsonObject req6 = Json.createObjectBuilder()
                .add("email",testEmail3)
                .build();

        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req6, "POST");

        //We don't care about the output, just consume the buffer
        while (in.read(buffer) != -1) {}


        in = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeList", null, "GET");

        //We don't care about the output, just consume the buffer
        JsonObject obj = Json.createReader(in).readObject();
        JsonArray arr = obj.getJsonArray("serials");

        for(JsonValue val: arr) {
            assertTrue(serialMap.containsKey(val.toString()));
        }

        //We revoked 3 certificates
        assertTrue(serialMap.size() == 3);
    }
}
