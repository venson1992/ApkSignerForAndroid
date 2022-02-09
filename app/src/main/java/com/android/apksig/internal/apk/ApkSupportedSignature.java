package com.android.apksig.internal.apk;

public class ApkSupportedSignature {
    public final SignatureAlgorithm algorithm;
    public final byte[] signature;

    public ApkSupportedSignature(SignatureAlgorithm algorithm2, byte[] signature2) {
        this.algorithm = algorithm2;
        this.signature = signature2;
    }
}
