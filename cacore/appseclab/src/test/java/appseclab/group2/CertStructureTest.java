package appseclab.group2;

import com.google.gson.Gson;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.*;

import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

public class CertStructureTest {
    @Rule
    public final EnvironmentVariables environmentVariables
            = new EnvironmentVariables();

    @Before
    public void setUp() throws IOException, IllegalAccessException, NoSuchFieldException {

        Field instance = CertStructure.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);

        environmentVariables.set("sharedPw", "wafwaf");
        environmentVariables.set("intermediateCertStorePw", "wafwaf");
        environmentVariables.set("intermediateCertStoreLocation", "certs/test/intermediate.p12");
        environmentVariables.set("certsWithKeysPw", "wafwaf");
        environmentVariables.set("certsWithKeysFilename", "test_certsWithKeys");
        environmentVariables.set("revokedCertFilename", "test_revokedCert");
        environmentVariables.set("activeCertFilename", "test_activeCert");
        environmentVariables.set("tlsPw", "wafwaf");
        environmentVariables.set("hostname", "");

        //Delete all tests keyStores
        File activeCertsFile = new File(System.getenv("activeCertFilename"));
        if(activeCertsFile.exists()) {
            activeCertsFile.delete();
        }

        File revokedCertsFile = new File(System.getenv("revokedCertFilename"));
        if(revokedCertsFile.exists()) {
            revokedCertsFile.delete();
        }

        File certsWithKeysFile = new File(System.getenv("certsWithKeysFilename"));
        if(certsWithKeysFile.exists()) {
            certsWithKeysFile.delete();
        }
        CACore.main(null);
    }

    @After
    public void teardown() {
        CACore.shutdown();
        File f = new File("cacore.log");
        if (f.exists()) {
            f.delete();
        }

        //Delete all tests keyStores
        File activeCertsFile = new File(System.getenv("activeCertFilename"));
        if(activeCertsFile.exists()) {
            activeCertsFile.delete();
        }

        File revokedCertsFile = new File(System.getenv("revokedCertFilename"));
        if(revokedCertsFile.exists()) {
            revokedCertsFile.delete();
        }

        File certsWithKeysFile = new File(System.getenv("certsWithKeysFilename"));
        if(certsWithKeysFile.exists()) {
            certsWithKeysFile.delete();
        }
    }

    @Test
    public void createCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        String testEmail = "waf@wuf.com", testName = "Some Name", pw = System.getenv("sharedPw");
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName, pw);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        String ans = UtilsForTests.sendPayload("https://localhost:" + CACore.PORT_NUMBER + "/getCert", req, "POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] c = Base64.getDecoder().decode(in.getData());

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(c), "".toCharArray());

        X509Certificate leafCert = (X509Certificate) keystore.getCertificate(testEmail);

        X500Name x500name = new JcaX509CertificateHolder(leafCert).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        RDN ou = x500name.getRDNs(BCStyle.OU)[0];

        assertTrue(IETFUtils.valueToString(cn.getFirst().getValue()).equals(testEmail));
        assertTrue(IETFUtils.valueToString(ou.getFirst().getValue()).equals(testName));

        //To verify if the signing was done with the root key, we have to load it
        KeyStore rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream(System.getenv("intermediateCertStoreLocation")), System.getenv("intermediateCertStorePw").toCharArray());

        Certificate rootCert = rootStore.getCertificate("intermediate");

        try {
            leafCert.verify(rootCert.getPublicKey());
        } catch (Exception e) {
            assertTrue(false);
        }
    }

    @Test
    public void setActiveCertTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {

        String testEmail = "waf@wuf.com", testName = "Some Name", pw = System.getenv("sharedPw");
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName, pw);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");

        assertTrue(CertStructure.getInstance().isCertificateActive(testEmail));
    }

    @Test
    public void setRevokedCertsTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        String testEmail = "some@randomness.com", testName = "Cheers Mate", pw = System.getenv("sharedPw");

        Gson gson = new Gson();
        HttpsServer.JSONCertQuery certQuery = new HttpsServer.JSONCertQuery(testEmail, testName, pw);
        String certReq = gson.toJson(certQuery, HttpsServer.JSONCertQuery.class);

        //Get a certificate
        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", certReq, "POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] certByte = Base64.getDecoder().decode(in.getData());
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(certByte), "".toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(testEmail);
        String certSN = certificate.getSerialNumber().toString();

        assertTrue(CertStructure.getInstance().isCertificateActive(testEmail));

        HttpsServer.JSONRevokeQuery revokeQuery = new HttpsServer.JSONRevokeQuery(certSN, pw);
        String revokeReq = gson.toJson(revokeQuery, HttpsServer.JSONRevokeQuery.class);

        //Revoke the certificate
        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", revokeReq, "POST");

        assertFalse(CertStructure.getInstance().isCertificateActive(testEmail));
        assertTrue(CertStructure.getInstance().isCertificateRevoked(certSN));
    }

    @Test
    public void setKeyCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        String testEmail = "waffel@wuffel.com", testName = "Cheers Mate", pw = System.getenv("sharedPw");
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail, testName, pw);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] certByte = Base64.getDecoder().decode(in.getData());
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(certByte), "".toCharArray());
        X509Certificate certificate = (X509Certificate)ks.getCertificate(testEmail);
        String certSN = certificate.getSerialNumber().toString();

        KeyStore certsWithKeys = KeyStore.getInstance("PKCS12");
        File certsWithKeysFile = new File(System.getenv("certsWithKeysFilename"));
        certsWithKeys.load(new FileInputStream(certsWithKeysFile), System.getenv("certsWithKeysPw").toCharArray());
        assertTrue(certsWithKeys.containsAlias(certSN));
    }

    @Test
    public void getRevokedListTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        //Map to store the serial number
        Map<String,Boolean> serialMap = new HashMap<>();

        String testEmail1 = "waffel1@wuffel.com", testName1 = "Cheers Mate", pw = "wafwaf";
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(testEmail1, testName1, pw);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);

        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req,"POST");
        HttpsServer.JSONAnswer in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        byte[] c = Base64.getDecoder().decode(in.getData());

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(c), "".toCharArray());

        X509Certificate cert = (X509Certificate) keystore.getCertificate(testEmail1);

        //Add the serial number to the map, will be checked later
        String sn1 = cert.getSerialNumber().toString();
        serialMap.put(sn1, Boolean.TRUE);

        String testEmail2 = "waffel2@wuffel.com", testName2 = "Cheers Mate";
        gson = new Gson();
        HttpsServer.JSONCertQuery q2 = new HttpsServer.JSONCertQuery(testEmail2, testName2, pw);
        String req2 = gson.toJson(q2, HttpsServer.JSONCertQuery.class);

        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req2, "POST");
        in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        c = Base64.getDecoder().decode(in.getData());

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(c), "".toCharArray());

        cert = (X509Certificate) keystore.getCertificate(testEmail2);

        //Add the serial number to the map, will be checked later
        String sn2 = cert.getSerialNumber().toString();
        serialMap.put(sn2, Boolean.TRUE);

        String testEmail3 = "waffel3@wuffel.com", testName3 = "Cheers Mate";
        gson = new Gson();
        HttpsServer.JSONCertQuery q3 = new HttpsServer.JSONCertQuery(testEmail3, testName3, pw);
        String req3 = gson.toJson(q3, HttpsServer.JSONCertQuery.class);

        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req3, "POST");
        in = gson.fromJson(ans, HttpsServer.JSONAnswer.class);
        c = Base64.getDecoder().decode(in.getData());

        keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(c), "".toCharArray());

        cert = (X509Certificate) keystore.getCertificate(testEmail3);

        //Add the serial number to the map, will be checked later
        String sn3 = cert.getSerialNumber().toString();
        serialMap.put(sn3, Boolean.TRUE);

        //Revoke 1st, 2nd and 3rd certificate
        HttpsServer.JSONRevokeQuery q4 = new HttpsServer.JSONRevokeQuery(sn1, pw);
        String req4 = gson.toJson(q4, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req4, "POST");

        HttpsServer.JSONRevokeQuery q5 = new HttpsServer.JSONRevokeQuery(sn2, pw);
        String req5 = gson.toJson(q5, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req5, "POST");

        HttpsServer.JSONRevokeQuery q6 = new HttpsServer.JSONRevokeQuery(sn3, pw);
        String req6 = gson.toJson(q6, HttpsServer.JSONRevokeQuery.class);

        UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", req6, "POST");


        HttpsServer.JSONQuery q7 = new HttpsServer.JSONQuery(pw);
        String req7 = gson.toJson(q7, HttpsServer.JSONQuery.class);
        ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeList", req7, "POST");
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
