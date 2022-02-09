package com.android.apksig.internal.pkcs7;

import com.android.apksig.internal.apk.v1.DigestAlgorithm;
import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1DerEncoder;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.oid.OidConstants;
import com.android.apksig.internal.util.Pair;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;

@Asn1Class(type = Asn1Type.SEQUENCE)
public class AlgorithmIdentifier {
    @Asn1Field(index = BerEncoding.TAG_CLASS_UNIVERSAL, type = Asn1Type.OBJECT_IDENTIFIER)
    public String algorithm;
    @Asn1Field(index = 1, optional = true, type = Asn1Type.ANY)
    public Asn1OpaqueObject parameters;

    public AlgorithmIdentifier() {
    }

    public AlgorithmIdentifier(String algorithmOid, Asn1OpaqueObject parameters2) {
        this.algorithm = algorithmOid;
        this.parameters = parameters2;
    }

    public static AlgorithmIdentifier getSignerInfoDigestAlgorithmOid(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA1:
                return new AlgorithmIdentifier(OidConstants.OID_DIGEST_SHA1, Asn1DerEncoder.ASN1_DER_NULL);
            case SHA256:
                return new AlgorithmIdentifier(OidConstants.OID_DIGEST_SHA256, Asn1DerEncoder.ASN1_DER_NULL);
            default:
                throw new IllegalArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
        }
    }

    public static Pair<String, AlgorithmIdentifier> getSignerInfoSignatureAlgorithm(PublicKey publicKey, DigestAlgorithm digestAlgorithm) throws InvalidKeyException {
        String jcaDigestPrefixForSigAlg;
        AlgorithmIdentifier sigAlgId;
        String keyAlgorithm = publicKey.getAlgorithm();
        switch (digestAlgorithm) {
            case SHA1:
                jcaDigestPrefixForSigAlg = "SHA1";
                break;
            case SHA256:
                jcaDigestPrefixForSigAlg = "SHA256";
                break;
            default:
                throw new IllegalArgumentException("Unexpected digest algorithm: " + digestAlgorithm);
        }
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            return Pair.of(jcaDigestPrefixForSigAlg + "withRSA", new AlgorithmIdentifier(OidConstants.OID_SIG_RSA, Asn1DerEncoder.ASN1_DER_NULL));
        }
        if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            switch (digestAlgorithm) {
                case SHA1:
                    sigAlgId = new AlgorithmIdentifier(OidConstants.OID_SIG_DSA, Asn1DerEncoder.ASN1_DER_NULL);
                    break;
                case SHA256:
                    sigAlgId = new AlgorithmIdentifier(OidConstants.OID_SIG_SHA256_WITH_DSA, Asn1DerEncoder.ASN1_DER_NULL);
                    break;
                default:
                    throw new IllegalArgumentException("Unexpected digest algorithm: " + digestAlgorithm);
            }
            return Pair.of(jcaDigestPrefixForSigAlg + "withDSA", sigAlgId);
        } else if ("EC".equalsIgnoreCase(keyAlgorithm)) {
            return Pair.of(jcaDigestPrefixForSigAlg + "withECDSA", new AlgorithmIdentifier(OidConstants.OID_SIG_EC_PUBLIC_KEY, Asn1DerEncoder.ASN1_DER_NULL));
        } else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    public static String getJcaSignatureAlgorithm(String digestAlgorithmOid, String signatureAlgorithmOid) throws SignatureException {
        String suffix;
        String result = OidConstants.OID_TO_JCA_SIGNATURE_ALG.get(signatureAlgorithmOid);
        if (result != null) {
            return result;
        }
        if (OidConstants.OID_SIG_RSA.equals(signatureAlgorithmOid)) {
            suffix = "RSA";
        } else if (OidConstants.OID_SIG_DSA.equals(signatureAlgorithmOid)) {
            suffix = "DSA";
        } else if (OidConstants.OID_SIG_EC_PUBLIC_KEY.equals(signatureAlgorithmOid)) {
            suffix = "ECDSA";
        } else {
            throw new SignatureException("Unsupported JCA Signature algorithm . Digest algorithm: " + digestAlgorithmOid + ", signature algorithm: " + signatureAlgorithmOid);
        }
        String jcaDigestAlg = getJcaDigestAlgorithm(digestAlgorithmOid);
        if (jcaDigestAlg.startsWith("SHA-")) {
            jcaDigestAlg = "SHA" + jcaDigestAlg.substring("SHA-".length());
        }
        return jcaDigestAlg + "with" + suffix;
    }

    public static String getJcaDigestAlgorithm(String oid) throws SignatureException {
        String result = OidConstants.OID_TO_JCA_DIGEST_ALG.get(oid);
        if (result != null) {
            return result;
        }
        throw new SignatureException("Unsupported digest algorithm: " + oid);
    }
}
