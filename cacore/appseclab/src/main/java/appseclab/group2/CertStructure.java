package appseclab.group2;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    private final int KEY_SIZE = 2048;
    private final int VALIDITY = 365;

    private X509Certificate caCert;
    private PrivateKey caPrivKey;

    private KeyStore activeCerts;
    private KeyStore revokedCerts;

    //This will be regularly backed up
    private KeyStore certsWithKeys;

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

    private CertStructure() throws KeyStoreException, IOException, UnrecoverableEntryException, NoSuchAlgorithmException, CertificateException {
        //Get the root certificate ready along with its private key
        KeyStore rootStore = null;
        rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream(INTERMEDIATE_CA_LOCATION), INTERMEDIATE_CA_PASSWORD.toCharArray());

        caPrivKey = (PrivateKey)rootStore.getKey(INTERMEDIATE_CA_ALIAS, INTERMEDIATE_CA_PASSWORD.toCharArray());
        caCert = (X509Certificate) rootStore.getCertificate(INTERMEDIATE_CA_ALIAS);

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

        //Init current infos
        issuedCertNumber = activeCerts.size() + revokedCerts.size();
        revokedCertNumber = revokedCerts.size();

        currentSerialNumber = initSerialNumber();
    }

    public byte[] getCRL() {
        ZoneOffset zoneOffSet = ZoneId.of("Europe/Zurich").getRules().getOffset(LocalDateTime.now());
        Date date = Date.from(LocalDateTime.now().toInstant(zoneOffSet));
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(JcaX500NameUtil.getIssuer(caCert), date);
        Enumeration<String> serials = null;
        try {
            serials = revokedCerts.aliases();
            while(serials.hasMoreElements()) {
                crlBuilder.addCRLEntry(new BigInteger(serials.nextElement()), date, CRLReason.unspecified);
            }
            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIG_ALG);
            signerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ContentSigner signer = signerBuilder.build(caPrivKey);
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            JcaX509CRLConverter converter = new JcaX509CRLConverter();

            converter.setProvider(BouncyCastleProvider.PROVIDER_NAME);

            return converter.getCRL(crlHolder).getEncoded();
        } catch (KeyStoreException | OperatorCreationException | CRLException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void initCertStructure() throws UnrecoverableEntryException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
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
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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
            e.printStackTrace();
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
            return true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void addKeyCert(X509Certificate[] chain, PrivateKey key) {
        try {
            certsWithKeys.setKeyEntry(chain[0].getSerialNumber().toString(), key, "".toCharArray(),chain);
            certsWithKeys.store(new FileOutputStream(certsWithKeysFilename), certsWithKeysPw.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public List<String> getRevokedList() {
        List<String> serials = new ArrayList<>();
        Enumeration<String> aliases = null;
        try {
            aliases = revokedCerts.aliases();

            while (aliases.hasMoreElements()) {
                serials.add(aliases.nextElement());
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return serials;
    }

    public boolean isCertificateActive(String email) {
        try {
            return activeCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean isCertificateRevoked(String serialNumber) {
        try {
            return revokedCerts.containsAlias(serialNumber);
        } catch (KeyStoreException e) {
            e.printStackTrace();
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
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public CertTuple createCert(String email, String name) {
        //KeyPair for newly created certificate
        KeyPair keyPair;
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

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

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509CertificateHolder certHolder = null;
        X509Certificate newCert = null;
        try {
            certHolder = v3CertBuilder.build(new JcaContentSignerBuilder(SIG_ALG).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivKey));
            newCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        KeyStore keystore = null;
        try {
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

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            File cert =  new File("certs/certGen");
            CALogger.getInstance().log("Certificate created for '" + name + "' with email '" + email + "'");
            return new CertTuple(Files.readAllBytes(cert.toPath()), sn.toString());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
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