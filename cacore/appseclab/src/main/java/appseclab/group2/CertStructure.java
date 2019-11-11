package appseclab.group2;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;

//Implemented as singleton
public class CertStructure {
    final String ROOT_CA = "certs/root/rootstore.p12";
    final String ROOT_CA_PASSWORD = "wafwaf";
    final String ROOT_CA_ALIAS = "rootcert";
    final String SIG_ALG = "SHA256WITHRSA";

    final int KEY_SIZE = 2048;
    final int VALIDITY = 365;

    private X509Certificate caCert;
    private PrivateKey caPrivKey;

    private KeyStore activeCerts;
    private KeyStore revokedCerts;

    //This will be regularly backed up
    private KeyStore certsWithKeys;

    private String currentSerialNumber = null;
    private int revokedCertNumber = 0;
    private int issuedCertNumber = 0;

    //private static Logger logger = Logger.getLogger("appseclab.group2.CertStructure");

    private static CertStructure instance;
    private CertStructure() {
        initialize();
    }

    //Needs to be public for tests
    public void initialize() {
        //Get the root certificate ready along with its private key
        KeyStore rootStore = null;
        try {
            rootStore = KeyStore.getInstance("PKCS12");
            rootStore.load(new FileInputStream(ROOT_CA), ROOT_CA_PASSWORD.toCharArray());

            caPrivKey = (PrivateKey)rootStore.getKey(ROOT_CA_ALIAS, ROOT_CA_PASSWORD.toCharArray());
            caCert = (X509Certificate) rootStore.getCertificate(ROOT_CA_ALIAS);
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Get the keyStore ready
        try {
            activeCerts = KeyStore.getInstance("PKCS12");
            revokedCerts = KeyStore.getInstance("PKCS12");
            certsWithKeys = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        //Check if keystores already exist or have to be created
        File activeCertsFile = new File("activeCerts");
        File revokedCertsFile = new File("revokedCerts");
        File certsWithKeysFile = new File("certsWithKeys");
        try {
            if(activeCertsFile.exists())
                activeCerts.load(new FileInputStream(activeCertsFile), "".toCharArray());
            else
                activeCerts.load(null,null);

            if(revokedCertsFile.exists())
                revokedCerts.load(new FileInputStream(revokedCertsFile), "".toCharArray());
            else
                revokedCerts.load(null,null);

            if(certsWithKeysFile.exists())
                certsWithKeys.load(new FileInputStream(certsWithKeysFile), "".toCharArray());
            else
                certsWithKeys.load(null,null);

            //Init current infos
            Enumeration<String> aliases = certsWithKeys.aliases();
            issuedCertNumber = certsWithKeys.size();
            revokedCertNumber = revokedCerts.size();

            String alias = "";
            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
            }

            if (alias.equals("")) {
                currentSerialNumber = "N/A";
            } else {
                X509Certificate tmp = (X509Certificate) certsWithKeys.getCertificate(alias);
                currentSerialNumber = tmp.getSerialNumber().toString();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public static CertStructure getInstance () {
        if (CertStructure.instance == null) {
            CertStructure.instance = new CertStructure();
        }
        return CertStructure.instance;
    }

    public void setActiveCert(X509Certificate crt) {
        try {
            activeCerts.setCertificateEntry(getCnFromCert(crt), crt);
            activeCerts.store(new FileOutputStream("activeCerts"),"".toCharArray());
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

    //not atomic, but I guess we don't need to think about concurrency
    public boolean setRevokedCert(String email) {
        //Check if email is valid first
        try {
            if(!activeCerts.containsAlias(email)) {
                return false;
            }

            revokedCerts.setCertificateEntry(email,activeCerts.getCertificate(email));
            revokedCerts.store(new FileOutputStream("revokedCerts"),"".toCharArray());
            activeCerts.deleteEntry(email);
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

    public void setKeyCert(X509Certificate[] chain, PrivateKey key) {

        try {
            certsWithKeys.setKeyEntry(getCnFromCert(chain[0]),key,"".toCharArray(),chain);
            certsWithKeys.store(new FileOutputStream("certsWithKeys"), "".toCharArray());
            currentSerialNumber = chain[0].getSerialNumber().toString();
            issuedCertNumber++;
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
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        if(aliases == null) return null;

        try {
            while (aliases.hasMoreElements()) {
                X509Certificate tmp = (X509Certificate) revokedCerts.getCertificate(aliases.nextElement());
                serials.add(tmp.getSerialNumber().toString());
            }
        } catch (KeyStoreException e) {
                e.printStackTrace();
        }

        return serials;
    }

    public boolean isActiveCert(String email) {
        try {
            return activeCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean isRevokedCert(String email) {
        try {
            return revokedCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        //If the above check threw an exception, it shouldn't be tretaed as valid
        return true;
    }

    public boolean isKeyCert(String email) {
        try {
            return certsWithKeys.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
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

    private String getCnFromCert(X509Certificate crt) {
        RDN cn = null;
        try {
            X500Name x500name = new JcaX509CertificateHolder(crt).getSubject();
            cn = x500name.getRDNs(BCStyle.CN)[0];
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }

    public byte[] getCert(String email, String name) {
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

        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
                JcaX500NameUtil.getIssuer(caCert),
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)),
                Date.from(LocalDateTime.now().plusDays(VALIDITY).toInstant(ZoneOffset.UTC)),
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

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = newCert;

            keystore.setKeyEntry(email, keyPair.getPrivate(), "".toCharArray(), chain);
            keystore.store(new FileOutputStream("certs/certGen"), "".toCharArray());

            //Add to local structures as well
            CertStructure.getInstance().setActiveCert(chain[0]);
            CertStructure.getInstance().setKeyCert(chain,keyPair.getPrivate());

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
            CALogger.getInstance().logger.log(Level.INFO, "Certificate created for '" + name + "' with email '" + email + "'");
            return Files.readAllBytes(cert.toPath());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}