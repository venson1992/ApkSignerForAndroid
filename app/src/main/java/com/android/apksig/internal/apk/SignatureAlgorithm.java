package com.android.apksig.internal.apk;

import com.android.apksig.internal.apk.AndroidBinXmlParser;
import com.android.apksig.internal.util.Pair;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public enum SignatureAlgorithm {
    RSA_PSS_WITH_SHA256(257, ContentDigestAlgorithm.CHUNKED_SHA256, "RSA", Pair.of("SHA256withRSA/PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)), 24, 23),
    RSA_PSS_WITH_SHA512(AndroidBinXmlParser.Chunk.RES_XML_TYPE_START_ELEMENT, ContentDigestAlgorithm.CHUNKED_SHA512, "RSA", Pair.of("SHA512withRSA/PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)), 24, 23),
    RSA_PKCS1_V1_5_WITH_SHA256(AndroidBinXmlParser.Chunk.RES_XML_TYPE_END_ELEMENT, ContentDigestAlgorithm.CHUNKED_SHA256, "RSA", Pair.of("SHA256withRSA", null), 24, 1),
    RSA_PKCS1_V1_5_WITH_SHA512(260, ContentDigestAlgorithm.CHUNKED_SHA512, "RSA", Pair.of("SHA512withRSA", null), 24, 1),
    ECDSA_WITH_SHA256(513, ContentDigestAlgorithm.CHUNKED_SHA256, "EC", Pair.of("SHA256withECDSA", null), 24, 11),
    ECDSA_WITH_SHA512(514, ContentDigestAlgorithm.CHUNKED_SHA512, "EC", Pair.of("SHA512withECDSA", null), 24, 11),
    DSA_WITH_SHA256(769, ContentDigestAlgorithm.CHUNKED_SHA256, "DSA", Pair.of("SHA256withDSA", null), 24, 1),
    VERITY_RSA_PKCS1_V1_5_WITH_SHA256(1057, ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "RSA", Pair.of("SHA256withRSA", null), 28, 1),
    VERITY_ECDSA_WITH_SHA256(1059, ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "EC", Pair.of("SHA256withECDSA", null), 28, 11),
    VERITY_DSA_WITH_SHA256(1061, ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, "DSA", Pair.of("SHA256withDSA", null), 28, 1);
    
    private final ContentDigestAlgorithm mContentDigestAlgorithm;
    private final int mId;
    private final String mJcaKeyAlgorithm;
    private final int mJcaSigAlgMinSdkVersion;
    private final Pair<String, ? extends AlgorithmParameterSpec> mJcaSignatureAlgAndParams;
    private final int mMinSdkVersion;

    private SignatureAlgorithm(int id, ContentDigestAlgorithm contentDigestAlgorithm, String jcaKeyAlgorithm, Pair pair, int minSdkVersion, int jcaSigAlgMinSdkVersion) {
        this.mId = id;
        this.mContentDigestAlgorithm = contentDigestAlgorithm;
        this.mJcaKeyAlgorithm = jcaKeyAlgorithm;
        this.mJcaSignatureAlgAndParams = pair;
        this.mMinSdkVersion = minSdkVersion;
        this.mJcaSigAlgMinSdkVersion = jcaSigAlgMinSdkVersion;
    }

    public int getId() {
        return this.mId;
    }

    public ContentDigestAlgorithm getContentDigestAlgorithm() {
        return this.mContentDigestAlgorithm;
    }

    public String getJcaKeyAlgorithm() {
        return this.mJcaKeyAlgorithm;
    }

    public Pair<String, ? extends AlgorithmParameterSpec> getJcaSignatureAlgorithmAndParams() {
        return this.mJcaSignatureAlgAndParams;
    }

    public int getMinSdkVersion() {
        return this.mMinSdkVersion;
    }

    public int getJcaSigAlgMinSdkVersion() {
        return this.mJcaSigAlgMinSdkVersion;
    }

    public static SignatureAlgorithm findById(int id) {
        SignatureAlgorithm[] values = values();
        for (SignatureAlgorithm alg : values) {
            if (alg.getId() == id) {
                return alg;
            }
        }
        return null;
    }
}
