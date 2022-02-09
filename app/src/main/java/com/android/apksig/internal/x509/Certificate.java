package com.android.apksig.internal.x509;

import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import com.android.apksig.internal.pkcs7.IssuerAndSerialNumber;
import com.android.apksig.internal.pkcs7.SignerIdentifier;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.X509CertificateUtils;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.security.auth.x500.X500Principal;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class Certificate {
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.SEQUENCE)
    public TBSCertificate certificate;
    @Asn1Field(index = 2, type = Asn1Type.BIT_STRING)
    public ByteBuffer signature;
    @Asn1Field(index = 1, type = Asn1Type.SEQUENCE)
    public AlgorithmIdentifier signatureAlgorithm;

    public static X509Certificate findCertificate(Collection<X509Certificate> certs, SignerIdentifier id) {
        for (X509Certificate cert : certs) {
            if (isMatchingCerticicate(cert, id)) {
                return cert;
            }
        }
        return null;
    }

    private static boolean isMatchingCerticicate(X509Certificate cert, SignerIdentifier id) {
        if (id.issuerAndSerialNumber == null) {
            return false;
        }
        IssuerAndSerialNumber issuerAndSerialNumber = id.issuerAndSerialNumber;
        X500Principal idIssuer = new X500Principal(ByteBufferUtils.toByteArray(issuerAndSerialNumber.issuer.getEncoded()));
        if (!issuerAndSerialNumber.certificateSerialNumber.equals(cert.getSerialNumber()) || !idIssuer.equals(cert.getIssuerX500Principal())) {
            return false;
        }
        return true;
    }

    public static List<X509Certificate> parseCertificates(List<Asn1OpaqueObject> encodedCertificates) throws CertificateException {
        if (encodedCertificates.isEmpty()) {
            return Collections.emptyList();
        }
        List<X509Certificate> result = new ArrayList<>(encodedCertificates.size());
        for (int i = 0; i < encodedCertificates.size(); i++) {
            byte[] encodedForm = ByteBufferUtils.toByteArray(encodedCertificates.get(i).getEncoded());
            try {
                result.add(new GuaranteedEncodedFormX509Certificate(X509CertificateUtils.generateCertificate(encodedForm), encodedForm));
            } catch (CertificateException e) {
                throw new CertificateException("Failed to parse certificate #" + (i + 1), e);
            }
        }
        return result;
    }
}
