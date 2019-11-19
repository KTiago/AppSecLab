package appseclab.group2;

import com.google.gson.Gson;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.*;

import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import static junit.framework.TestCase.*;

public class CertStructureTest {
    private String pw;
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
        environmentVariables.set("crlFilename", "test_revokedList.crl");
        environmentVariables.set("tlsPw", "wafwaf");
        environmentVariables.set("hostname", "");
        environmentVariables.set("port", "8080");
        environmentVariables.set("debug", "true");
        pw = System.getenv("sharedPw");

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

        File crlFile = new File(System.getenv("crlFilename"));
        if(crlFile.exists()) {
            crlFile.delete();
        }
    }

    private String sendRevoke(String sn) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        Gson gson = new Gson();
        HttpsServer.JSONRevokeQuery revokeQuery = new HttpsServer.JSONRevokeQuery(sn, pw);
        String revokeReq = gson.toJson(revokeQuery, HttpsServer.JSONRevokeQuery.class);

        //Revoke the certificate
        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/revokeCert", revokeReq, "POST");
        HttpsServer.JSONRevokeAnswer in = gson.fromJson(ans, HttpsServer.JSONRevokeAnswer.class);
        return in.getCRL();
    }

    private CertTuple sendGetCert(String email, String name) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        Gson gson = new Gson();
        HttpsServer.JSONCertQuery q = new HttpsServer.JSONCertQuery(email, name, pw);
        String req = gson.toJson(q, HttpsServer.JSONCertQuery.class);
        String ans = UtilsForTests.sendPayload("https://localhost:"+CACore.PORT_NUMBER+"/getCert", req, "POST");
        HttpsServer.JSONCertAnswer in = gson.fromJson(ans, HttpsServer.JSONCertAnswer.class);
        byte[] c = Base64.getDecoder().decode(in.getData());

        //Add the serial number to the map, will be checked later
        String sn = in.getSn();
        return new CertTuple(c, sn);
    }

    private byte[] derCRLToPem(String crl) {
        String[] split = crl.split("\n");

        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < split.length-1; ++i) {
            sb.append(split[i]);
        }

        String crl1Der = sb.toString();
        return java.util.Base64.getDecoder().decode(crl1Der.getBytes());
    }

    @Test
    public void createCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        String testEmail = "waf@wuf.com", testName = "Some Name";
        CertTuple ct = sendGetCert(testEmail, testName);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new ByteArrayInputStream(ct.getCert()), "".toCharArray());

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
        String testEmail = "waf@wuf.com", testName = "Some Name";
        sendGetCert(testEmail, testName);

        assertTrue(CertStructure.getInstance().isCertificateActive(testEmail));
    }

    @Test
    public void setRevokedCertsTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException {
        String testEmail = "some@randomness.com", testName = "Cheers Mate";

        CertTuple ct = sendGetCert(testEmail, testName);

        assertTrue(CertStructure.getInstance().isCertificateActive(testEmail));

        sendRevoke(ct.getSn());

        assertFalse(CertStructure.getInstance().isCertificateActive(testEmail));
        assertTrue(CertStructure.getInstance().isCertificateRevoked(ct.getSn()));
    }

    @Test
    public void setKeyCertTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        String testEmail = "waffel@wuffel.com", testName = "Cheers Mate";

        CertTuple ct = sendGetCert(testEmail, testName);

        KeyStore certsWithKeys = KeyStore.getInstance("PKCS12");
        File certsWithKeysFile = new File(System.getenv("certsWithKeysFilename"));
        certsWithKeys.load(new FileInputStream(certsWithKeysFile), System.getenv("certsWithKeysPw").toCharArray());
        assertTrue(certsWithKeys.containsAlias(ct.getSn()));
    }

    @Test
    public void CRLTest() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        String testEmail1 = "waffel1@wuffel.com", testName1 = "Cheers Mate";
        CertTuple ct1 = sendGetCert(testEmail1, testName1);
        Set<String> crlTest1 = new HashSet<>();
        crlTest1.add(ct1.getSn());

        String testEmail2 = "waffel2@wuffel.com", testName2 = "Cheers Mate";
        CertTuple ct2 = sendGetCert(testEmail2, testName2);
        Set<String> crlTest2 = new HashSet<>();
        crlTest2.add(ct1.getSn());
        crlTest2.add(ct2.getSn());

        String testEmail3 = "waffel3@wuffel.com", testName3 = "Cheers Mate";
        CertTuple ct3 = sendGetCert(testEmail3, testName3);
        Set<String> crlTest3 = new HashSet<>();
        crlTest3.add(ct1.getSn());
        crlTest3.add(ct2.getSn());
        crlTest3.add(ct3.getSn());

        String crl1 = sendRevoke(ct1.getSn());
        String crl2 = sendRevoke(ct2.getSn());
        String crl3 = sendRevoke(ct3.getSn());

        //Check crl1:
        X509CRLHolder crl = new X509CRLHolder(derCRLToPem(crl1));
        Collection<X509CRLEntryHolder> t = crl.getRevokedCertificates();
        assertEquals(1, t.size());
        for (X509CRLEntryHolder elem : t) {
            assertTrue(crlTest1.contains(elem.getSerialNumber().toString()));
            System.out.println(elem.getSerialNumber());
        }

        //Check crl2:
        crl = new X509CRLHolder(derCRLToPem(crl2));
        t = crl.getRevokedCertificates();
        assertEquals(2, t.size());
        for (X509CRLEntryHolder elem : t) {
            assertTrue(crlTest2.contains(elem.getSerialNumber().toString()));
            System.out.println(elem.getSerialNumber());
        }

        //Check crl3:
        crl = new X509CRLHolder(derCRLToPem(crl3));
        t = crl.getRevokedCertificates();
        assertEquals(3, t.size());
        for (X509CRLEntryHolder elem : t) {
            assertTrue(crlTest3.contains(elem.getSerialNumber().toString()));
            System.out.println(elem.getSerialNumber());
        }
    }
}
