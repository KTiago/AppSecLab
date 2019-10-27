package netsec.group2;


import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;

public class Certs {

    final String ROOT_CA = "";
    final String ROOT_CA_PASSWORD = "";
    final String ROOT_CA_ALIAS = "rootca";

    private X509Certificate caCert;
    private KeyPair rootCaKeyPair;

    public Certs() throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {

        //Get the root certificate ready along with its private key
    }

    //Some encoding
    public byte[] createCertificate(String email, String name) throws NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, SignatureException, KeyStoreException, NoSuchProviderException {

        //Here we will need TBSCertificate (to-be-signed certificates) and create new client certificates
        return null;
    }
}