package org.conscrypt;

import com.android.apksig.internal.oid.OidConstants;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

public final class CertificatePriorityComparator implements Comparator<X509Certificate> {
    private static final Map<String, Integer> ALGORITHM_OID_PRIORITY_MAP = new HashMap();
    private static final Integer PRIORITY_MD5 = 6;
    private static final Integer PRIORITY_SHA1 = 5;
    private static final Integer PRIORITY_SHA224 = 4;
    private static final Integer PRIORITY_SHA256 = 3;
    private static final Integer PRIORITY_SHA384 = 2;
    private static final Integer PRIORITY_SHA512 = 1;
    private static final Integer PRIORITY_UNKNOWN = -1;

    static {
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA512_WITH_RSA, PRIORITY_SHA512);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA384_WITH_RSA, PRIORITY_SHA384);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA256_WITH_RSA, PRIORITY_SHA256);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA224_WITH_RSA, PRIORITY_SHA224);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA1_WITH_RSA, PRIORITY_SHA1);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_MD5_WITH_RSA, PRIORITY_MD5);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA512_WITH_ECDSA, PRIORITY_SHA512);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA384_WITH_ECDSA, PRIORITY_SHA384);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA256_WITH_ECDSA, PRIORITY_SHA256);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA224_WITH_ECDSA, PRIORITY_SHA224);
        ALGORITHM_OID_PRIORITY_MAP.put(OidConstants.OID_SIG_SHA1_WITH_ECDSA, PRIORITY_SHA1);
    }

    public int compare(X509Certificate lhs, X509Certificate rhs) {
        int i;
        boolean lhsSelfSigned = lhs.getSubjectDN().equals(lhs.getIssuerDN());
        boolean rhsSelfSigned = rhs.getSubjectDN().equals(rhs.getIssuerDN());
        if (lhsSelfSigned != rhsSelfSigned) {
            if (rhsSelfSigned) {
                i = 1;
            } else {
                i = -1;
            }
            return i;
        }
        int result = compareStrength(rhs, lhs);
        if (result != 0) {
            return result;
        }
        int result2 = rhs.getNotAfter().compareTo(lhs.getNotAfter());
        if (result2 != 0) {
            return result2;
        }
        return rhs.getNotBefore().compareTo(lhs.getNotBefore());
    }

    private int compareStrength(X509Certificate lhs, X509Certificate rhs) {
        PublicKey lhsPublicKey = lhs.getPublicKey();
        PublicKey rhsPublicKey = rhs.getPublicKey();
        int result = compareKeyAlgorithm(lhsPublicKey, rhsPublicKey);
        if (result != 0) {
            return result;
        }
        int result2 = compareKeySize(lhsPublicKey, rhsPublicKey);
        return result2 != 0 ? result2 : compareSignatureAlgorithm(lhs, rhs);
    }

    private int compareKeyAlgorithm(PublicKey lhs, PublicKey rhs) {
        String lhsAlgorithm = lhs.getAlgorithm();
        if (lhsAlgorithm.equalsIgnoreCase(rhs.getAlgorithm())) {
            return 0;
        }
        if ("EC".equalsIgnoreCase(lhsAlgorithm)) {
            return 1;
        }
        return -1;
    }

    private int compareKeySize(PublicKey lhs, PublicKey rhs) {
        if (lhs.getAlgorithm().equalsIgnoreCase(rhs.getAlgorithm())) {
            return getKeySize(lhs) - getKeySize(rhs);
        }
        throw new IllegalArgumentException("Keys are not of the same type");
    }

    private int getKeySize(PublicKey pkey) {
        if (pkey instanceof ECPublicKey) {
            return ((ECPublicKey) pkey).getParams().getCurve().getField().getFieldSize();
        }
        if (pkey instanceof RSAPublicKey) {
            return ((RSAPublicKey) pkey).getModulus().bitLength();
        }
        throw new IllegalArgumentException("Unsupported public key type: " + pkey.getClass().getName());
    }

    private int compareSignatureAlgorithm(X509Certificate lhs, X509Certificate rhs) {
        Integer lhsPriority = ALGORITHM_OID_PRIORITY_MAP.get(lhs.getSigAlgOID());
        Integer rhsPriority = ALGORITHM_OID_PRIORITY_MAP.get(rhs.getSigAlgOID());
        if (lhsPriority == null) {
            lhsPriority = PRIORITY_UNKNOWN;
        }
        if (rhsPriority == null) {
            rhsPriority = PRIORITY_UNKNOWN;
        }
        return rhsPriority.intValue() - lhsPriority.intValue();
    }
}
