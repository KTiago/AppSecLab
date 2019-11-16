package appseclab.group2;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;

//Implemented as singleton
public class CertStructure {
    private final String INTERMEDIATE_CA_LOCATION = System.getenv("intermediateCertStoreLocation");
    private final String INTERMEDIATE_CA_PASSWORD = System.getenv("intermediateCertStorePw");
    private final String INTERMEDIATE_CA_ALIAS = "intermediate";
    private final String SIG_ALG = "SHA256WITHRSA";
    private final String certsWithKeysFilename = System.getenv("certsWithKeysFilename");
    private final String certsWithKeysPw = System.getenv("certsWithKeysPw");
    private final String activeCertFilename = System.getenv("activeCertFilename");
    private final String revokedCertFilename = System.getenv("revokedCertFilename");
    private final String crlFilename = System.getenv("crlFilename");

    private final int KEY_SIZE = 2048;
    private final int VALIDITY = 365;

    private X509Certificate caCert;
    private PrivateKey caPrivKey;

    private KeyStore activeCerts;
    private KeyStore revokedCerts;

    //This will be regularly backed up
    private KeyStore certsWithKeys;
    private X509CRLHolder crlHolder;

    private String currentSerialNumber = null;
    private int revokedCertNumber = 0;
    private int issuedCertNumber = 0;

    private static CertStructure instance;

    private String initSerialNumber() throws KeyStoreException {
        String sn = null;
        Enumeration<String> emails = activeCerts.aliases();
        List<BigInteger> serialNumbers = new ArrayList<>();
        while (emails.hasMoreElements()) {
            X509Certificate tmp = (X509Certificate) activeCerts.getCertificate(emails.nextElement());
            serialNumbers.add(tmp.getSerialNumber());
        }

        Enumeration<String> serials = revokedCerts.aliases();
        while (serials.hasMoreElements()) {
            serialNumbers.add(new BigInteger(serials.nextElement()));
        }

        if (serialNumbers.isEmpty()) {
            sn = "N/A";
        } else {
            Collections.sort(serialNumbers);
            sn = serialNumbers.get(serialNumbers.size()-1).toString();
        }
        return sn;
    }

    private CertStructure() throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Get the root certificate ready along with its private key
        KeyStore rootStore = null;
        rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream(INTERMEDIATE_CA_LOCATION), INTERMEDIATE_CA_PASSWORD.toCharArray());

        caPrivKey = (PrivateKey)rootStore.getKey(INTERMEDIATE_CA_ALIAS, INTERMEDIATE_CA_PASSWORD.toCharArray());
        caCert = (X509Certificate) rootStore.getCertificate(INTERMEDIATE_CA_ALIAS);
        rootStore.getCertificate(INTERMEDIATE_CA_ALIAS);

        //Get the keyStore ready
        activeCerts = KeyStore.getInstance("PKCS12");
        revokedCerts = KeyStore.getInstance("PKCS12");
        certsWithKeys = KeyStore.getInstance("PKCS12");

        //Check if keystores already exist or have to be created
        File activeCertsFile = new File(activeCertFilename);
        File revokedCertsFile = new File(revokedCertFilename);
        File certsWithKeysFile = new File(certsWithKeysFilename);

        if(activeCertsFile.exists()) {
            activeCerts.load(new FileInputStream(activeCertsFile), "".toCharArray());
        } else {
            activeCerts.load(null, null);
        }

        if(revokedCertsFile.exists()) {
            revokedCerts.load(new FileInputStream(revokedCertsFile), "".toCharArray());
        } else {
            revokedCerts.load(null, null);
        }

        if(certsWithKeysFile.exists()) {
            certsWithKeys.load(new FileInputStream(certsWithKeysFile), certsWithKeysPw.toCharArray());
        } else {
            certsWithKeys.load(null, null);
        }

        //CRL
        File crlFile = new File(crlFilename);
        if(crlFile.exists()) {
            crlHolder = new X509CRLHolder(new FileInputStream(crlFile));
        } else {
            ZoneOffset zoneOffSet = ZoneId.of("Europe/Zurich").getRules().getOffset(LocalDateTime.now());
            Date now = Date.from(LocalDateTime.now().toInstant(zoneOffSet));
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(JcaX500NameUtil.getSubject(caCert), now);

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIG_ALG);
            signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ContentSigner signer = signerBuilder.build(caPrivKey);
            crlHolder = crlBuilder.build(signer);
            crlHolder.getEncoded();
            OutputStream outStream = new FileOutputStream(crlFilename);
            outStream.write(crlHolder.getEncoded());
            outStream.close();
        }

        //Init current infos
        issuedCertNumber = activeCerts.size() + revokedCerts.size();
        revokedCertNumber = revokedCerts.size();

        currentSerialNumber = initSerialNumber();
    }

    private void updateCRL(BigInteger sn) {
        ZoneOffset zoneOffSet = ZoneId.of("Europe/Zurich").getRules().getOffset(LocalDateTime.now());
        Date now = Date.from(LocalDateTime.now().toInstant(zoneOffSet));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlHolder);
        crlBuilder.addCRLEntry(sn, now, CRLReason.unspecified);
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIG_ALG);
        signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
        ContentSigner signer = null;
        try {
            signer = signerBuilder.build(caPrivKey);
            crlHolder = crlBuilder.build(signer);
            OutputStream outStream = new FileOutputStream(crlFilename);
            outStream.write(crlHolder.getEncoded());
            outStream.close();
        } catch (OperatorCreationException | IOException e) {
            CALogger.getInstance().log("exception during the CRL update", e);
        }
    }

    public String getCRL() {
        try {
            StringWriter sw = new StringWriter();
            JcaPEMWriter pemW = new JcaPEMWriter(sw);
            JcaX509CRLConverter converter = new JcaX509CRLConverter();
            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            X509CRL crl = converter.getCRL(crlHolder);
            pemW.writeObject(crl);
            pemW.close();
            return sw.toString();
        } catch (IOException | CRLException e) {
            CALogger.getInstance().log("exception while getting the CRL's bytes", e);
            return "";
        }
    }

    public static void initCertStructure() throws UnrecoverableEntryException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
        if (instance == null) {
            instance = new CertStructure();
        }
    }

    public static CertStructure getInstance () {
        return instance;
    }

    private void addActiveCert(X509Certificate crt) {
        try {
            activeCerts.setCertificateEntry(getEmailFromCert(crt), crt);
            activeCerts.store(new FileOutputStream(activeCertFilename), "".toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            CALogger.getInstance().log("exception while adding a new certificate to the activeCert KeyStore", e);
        }
    }

    private String getEmailFromSN(String serialNumber) {
        Enumeration<String> emails;
        try {
            emails = activeCerts.aliases();
            while (emails.hasMoreElements()) {
                String email = emails.nextElement();
                X509Certificate tmp = (X509Certificate) activeCerts.getCertificate(email);
                if (serialNumber.equals(tmp.getSerialNumber().toString())) {
                    return email;
                }
            }
        } catch (KeyStoreException e) {
            CALogger.getInstance().log("exception when fetching the email from the serial number", e);
        }

        return null;
    }

    public boolean addRevokedCert(String serialNumber) {
        //Check if email is valid first
        try {
            String email = getEmailFromSN(serialNumber);
            if(email == null) {
                return false;
            }

            revokedCerts.setCertificateEntry(serialNumber, activeCerts.getCertificate(email));
            revokedCerts.store(new FileOutputStream(revokedCertFilename), "".toCharArray());
            activeCerts.deleteEntry(email);
            activeCerts.store(new FileOutputStream(activeCertFilename), "".toCharArray());
            revokedCertNumber++;
            updateCRL(new BigInteger(serialNumber));
            return true;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            CALogger.getInstance().log("exception while adding a new certificate to the revokedCert KeyStore", e);
        }
        return false;
    }

    private void addKeyCert(X509Certificate[] chain, PrivateKey key) {
        try {
            certsWithKeys.setKeyEntry(chain[0].getSerialNumber().toString(), key, "".toCharArray(),chain);
            certsWithKeys.store(new FileOutputStream(certsWithKeysFilename), certsWithKeysPw.toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            CALogger.getInstance().log("exception while adding a certificate to the certWithKeys KeyStore", e);
        }
    }

    public boolean isCertificateActive(String email) {
        try {
            return activeCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            CALogger.getInstance().log("exception during active certificate verification", e);
        }

        return false;
    }

    public boolean isCertificateRevoked(String serialNumber) {
        try {
            return revokedCerts.containsAlias(serialNumber);
        } catch (KeyStoreException e) {
            CALogger.getInstance().log("exception during revoke certificate verification", e);
        }

        //If the above check threw an exception, it shouldn't be treated as valid
        return true;
    }

    public int getIssuedCertNumber() {
        return issuedCertNumber;
    }

    public int getRevokedCertNumber() {
        return revokedCertNumber;
    }

    public String getSerialNumber() {
        return currentSerialNumber;
    }

    private String getEmailFromCert(X509Certificate crt) {
        RDN cn = null;
        try {
            X500Name x500name = new JcaX509CertificateHolder(crt).getSubject();
            cn = x500name.getRDNs(BCStyle.CN)[0];
            return IETFUtils.valueToString(cn.getFirst().getValue());
        } catch (CertificateEncodingException e) {
            CALogger.getInstance().log("exception while fetching email from the certificate", e);
        }
        return null;
    }

    public CertTuple createCert(String email, String name) {
        //KeyPair for newly created certificate
        KeyPair keyPair;
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE, new SecureRandom());
            keyPair = keyGen.generateKeyPair();

            X500NameBuilder nameBuilder = new X500NameBuilder();
            nameBuilder.addRDN(BCStyle.CN, email);
            nameBuilder.addRDN(BCStyle.OU, name);

            ZoneOffset zoneOffSet = ZoneId.of("Europe/Zurich").getRules().getOffset(LocalDateTime.now());

            BigInteger sn = getNewSerialNumber();
            X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
                    JcaX500NameUtil.getSubject(caCert),
                    sn,
                    Date.from(LocalDateTime.now().toInstant(zoneOffSet)),
                    Date.from(LocalDateTime.now().plusDays(VALIDITY).toInstant(zoneOffSet)),
                    nameBuilder.build(),
                    keyPair.getPublic()
            );

            v3CertBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            v3CertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            v3CertBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection}));

            X509CertificateHolder certHolder = null;
            X509Certificate newCert = null;

            certHolder = v3CertBuilder.build(new JcaContentSignerBuilder(SIG_ALG).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivKey));
            newCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);

            KeyStore keystore = null;
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null, null);

            X509Certificate[] chain = new X509Certificate[2];
            chain[0] = newCert;
            chain[1] = caCert;

            keystore.setKeyEntry(email, keyPair.getPrivate(), "".toCharArray(), chain);
            keystore.store(new FileOutputStream("certs/certGen"), "".toCharArray());

            //Add to local structures as well
            CertStructure.getInstance().addActiveCert(chain[0]);
            CertStructure.getInstance().addKeyCert(chain, keyPair.getPrivate());
            issuedCertNumber++;

            File cert =  new File("certs/certGen");
            CALogger.getInstance().log("Certificate created for '" + name + "' with email '" + email + "'");

            CertTuple res = new CertTuple(Files.readAllBytes(cert.toPath()), sn.toString());
            if (cert.exists()) {
                cert.delete();
            }
            return res;
        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | OperatorCreationException | IOException e) {
            CALogger.getInstance().log("exception during certificate creation", e);
        }

        return null;
    }

    private BigInteger getNewSerialNumber() {
        BigInteger sn = BigInteger.valueOf(System.currentTimeMillis());
        if(!currentSerialNumber.equals("N/A")) {
            while(sn.compareTo(new BigInteger(currentSerialNumber)) <= 0) {
                sn = BigInteger.valueOf(System.currentTimeMillis());
            }
        }

        currentSerialNumber = sn.toString();
        return sn;
    }
}