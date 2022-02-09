package com.android.apksig.internal.apk;

import java.nio.ByteBuffer;

public class SignatureInfo {
    public final long apkSigningBlockOffset;
    public final long centralDirOffset;
    public final ByteBuffer eocd;
    public final long eocdOffset;
    public final ByteBuffer signatureBlock;

    public SignatureInfo(ByteBuffer signatureBlock2, long apkSigningBlockOffset2, long centralDirOffset2, long eocdOffset2, ByteBuffer eocd2) {
        this.signatureBlock = signatureBlock2;
        this.apkSigningBlockOffset = apkSigningBlockOffset2;
        this.centralDirOffset = centralDirOffset2;
        this.eocdOffset = eocdOffset2;
        this.eocd = eocd2;
    }
}
