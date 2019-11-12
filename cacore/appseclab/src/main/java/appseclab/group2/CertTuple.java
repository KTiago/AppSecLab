package appseclab.group2;

public class CertTuple {
    private byte[] cert;
    private String sn;

    public CertTuple(byte[] cert, String sn) {
        this.cert = cert;
        this.sn = sn;
    }

    public byte[] getCert() {
        return cert;
    }

    public String getSn() {
        return sn;
    }
}
