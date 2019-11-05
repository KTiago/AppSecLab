package netsec.group2;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

//Implemented as singleton
public class CertStructure {

    private KeyStore activeCerts;
    private KeyStore revokedCerts;

    //This will be regularly backed up
    private KeyStore certsWithKeys;

    private static CertStructure instance;
    private CertStructure() {

        //Probably easiest if we make everything PKCS12
        try {
            activeCerts = KeyStore.getInstance("PKCS12");
            revokedCerts = KeyStore.getInstance("PKCS12");
            certsWithKeys = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public static CertStructure getInstance () {
        if (CertStructure.instance == null) {
            CertStructure.instance = new CertStructure ();
        }
        return CertStructure.instance;
    }

    public void setKeyCert(X509Certificate crt, PrivateKey key) {

        //certsWithKeys.setKeyEntry(getCnFromCert(crt),key,"".toCharArray(),chain)
    }

    public void setActiveCert(X509Certificate crt) {
        try {
            activeCerts.setCertificateEntry(getCnFromCert(crt), crt);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public List<String> getRevokedList() {

        List<String> serials = new LinkedList<>();
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

    //not atomic, but I guess we don't need to think about concurrency
    public void revokeCert(String email) {
        //Check if email is valid first
        try {
            if(!activeCerts.containsAlias(email)) return;
            revokedCerts.setCertificateEntry(email,activeCerts.getCertificate(email));
            activeCerts.deleteEntry(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    public boolean isValid(String email) {
        try {
            return activeCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean isRevoked(String email) {
        try {
            return revokedCerts.containsAlias(email);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        //If the above check threw an exception, it shouldn't be tretaed as valid
        return true;
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
}