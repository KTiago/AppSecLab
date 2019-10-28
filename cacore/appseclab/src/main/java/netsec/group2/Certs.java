package netsec.group2;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class Certs {

    final String ROOT_CA = "certs/rootcertstore.jks";
    final String ROOT_CA_PASSWORD = "wafwaf";
    final String ROOT_CA_ALIAS = "rootcert";
    final String SIG_ALG = "SHA256WITHRSA";

    private X509Certificate caCert;
    private PrivateKey caPrivKey;

    public Certs() throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException {

        //Get the root certificate ready along with its private key
        KeyStore rootStore = KeyStore.getInstance("PKCS12");
        rootStore.load(new FileInputStream(ROOT_CA), ROOT_CA_PASSWORD.toCharArray());

        Key key = rootStore.getKey(ROOT_CA_ALIAS, ROOT_CA_PASSWORD.toCharArray());

        //Kind of a weird way to extract the private key but meh
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) key;
        RSAPrivateCrtKeyParameters caPrivateKey = new RSAPrivateCrtKeyParameters(privKey.getModulus(), privKey.getPublicExponent(), privKey.getPrivateExponent(),
                privKey.getPrimeP(), privKey.getPrimeQ(), privKey.getPrimeExponentP(), privKey.getPrimeExponentQ(), privKey.getCrtCoefficient());
        caPrivKey = KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateCrtKeySpec(caPrivateKey.getModulus(), caPrivateKey.getPublicExponent(),
                        caPrivateKey.getExponent(), caPrivateKey.getP(), caPrivateKey.getQ(),
                        caPrivateKey.getDP(), caPrivateKey.getDQ(), caPrivateKey.getQInv()));

        caCert = (X509Certificate) rootStore.getCertificate(ROOT_CA_ALIAS);
    }

    public void createCertificate(String email, String name) throws NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, KeyStoreException, NoSuchProviderException, OperatorCreationException, UnrecoverableKeyException {

        //KeyPair for newly created certificate
        KeyPair keyPair;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        keyPair = keyGen.generateKeyPair();

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, email);
        nameBuilder.addRDN(BCStyle.OU, name);

        X509v3CertificateBuilder v3CertBuilder = new JcaX509v3CertificateBuilder(
                JcaX500NameUtil.getIssuer(caCert),
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)),
                Date.from(LocalDateTime.now().plusDays(365).toInstant(ZoneOffset.UTC)),
                nameBuilder.build(),
                keyPair.getPublic()
        );

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        X509CertificateHolder certHolder = v3CertBuilder.build(new JcaContentSignerBuilder(SIG_ALG).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivKey));
        X509Certificate newCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(null, null);

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = newCert;
        //chain[1] = caCert;

        keystore.setKeyEntry("newCert", keyPair.getPrivate(), "wafwaf".toCharArray(), chain);
        keystore.store(new FileOutputStream("certs/certGen"), "wafwaf".toCharArray());
    }
}