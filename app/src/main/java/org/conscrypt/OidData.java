package org.conscrypt;

import com.android.apksig.internal.oid.OidConstants;
import java.util.HashMap;
import java.util.Map;

/* access modifiers changed from: package-private */
public final class OidData {
    private static final Map<String, String> OID_TO_NAME_MAP = new HashMap();

    private OidData() {
    }

    static {
        OID_TO_NAME_MAP.put("1.2.840.113549.1.1.2", "MD2withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_MD5_WITH_RSA, "MD5withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA1_WITH_RSA, "SHA1withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA1_WITH_DSA, "SHA1withDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA1_WITH_ECDSA, "SHA1withECDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA224_WITH_RSA, "SHA224withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA256_WITH_RSA, "SHA256withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA384_WITH_RSA, "SHA384withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA512_WITH_RSA, "SHA512withRSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA224_WITH_DSA, "SHA224withDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA256_WITH_DSA, "SHA256withDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA224_WITH_ECDSA, "SHA224withECDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA256_WITH_ECDSA, "SHA256withECDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA384_WITH_ECDSA, "SHA384withECDSA");
        OID_TO_NAME_MAP.put(OidConstants.OID_SIG_SHA512_WITH_ECDSA, "SHA512withECDSA");
    }

    public static String oidToAlgorithmName(String oid) {
        return OID_TO_NAME_MAP.get(oid);
    }
}
