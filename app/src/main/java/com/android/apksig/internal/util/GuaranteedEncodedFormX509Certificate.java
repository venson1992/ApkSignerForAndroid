package com.android.apksig.internal.util;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class GuaranteedEncodedFormX509Certificate extends DelegatingX509Certificate {
    private static final long serialVersionUID = 1;
    private final byte[] mEncodedForm;
    private int mHash = -1;

    public GuaranteedEncodedFormX509Certificate(X509Certificate wrapped, byte[] encodedForm) {
        super(wrapped);
        this.mEncodedForm = encodedForm != null ? (byte[]) encodedForm.clone() : null;
    }

    @Override // java.security.cert.Certificate, com.android.apksig.internal.util.DelegatingX509Certificate
    public byte[] getEncoded() throws CertificateEncodingException {
        if (this.mEncodedForm != null) {
            return (byte[]) this.mEncodedForm.clone();
        }
        return null;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof X509Certificate)) {
            return false;
        }
        try {
            return Arrays.equals(getEncoded(), ((X509Certificate) o).getEncoded());
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    public int hashCode() {
        if (this.mHash == -1) {
            try {
                this.mHash = Arrays.hashCode(getEncoded());
            } catch (CertificateEncodingException e) {
                this.mHash = 0;
            }
        }
        return this.mHash;
    }
}
