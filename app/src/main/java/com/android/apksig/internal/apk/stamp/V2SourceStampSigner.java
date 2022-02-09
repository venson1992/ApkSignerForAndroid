package com.android.apksig.internal.apk.stamp;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.util.Pair;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class V2SourceStampSigner {
    public static final int V2_SOURCE_STAMP_BLOCK_ID = 1845461005;

    private V2SourceStampSigner() {
    }

    /* JADX WARN: Type inference failed for: r4v2, types: [void, java.util.function.Function] */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static com.android.apksig.internal.util.Pair<byte[], java.lang.Integer> generateSourceStampBlock(com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig r10, java.util.Map<java.lang.Integer, java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]>> r11) throws java.security.SignatureException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException {
        /*
        // Method dump skipped, instructions count: 144
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.V2SourceStampSigner.generateSourceStampBlock(com.android.apksig.internal.apk.ApkSigningBlockUtils$SignerConfig, java.util.Map):com.android.apksig.internal.util.Pair");
    }

    /*  JADX ERROR: JadxRuntimeException in pass: BlockSplitter
        jadx.core.utils.exceptions.JadxRuntimeException: Missing block: 74
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.getBlock(BlockSplitter.java:307)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.setupConnections(BlockSplitter.java:236)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.splitBasicBlocks(BlockSplitter.java:129)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.visit(BlockSplitter.java:52)
        */
    private static void getSignedDigestsFor(int r8, java.util.Map<java.lang.Integer, java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]>> r9, com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig r10, java.util.List<com.android.apksig.internal.util.Pair<java.lang.Integer, byte[]>> r11) throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.SignatureException {
        /*
        // Method dump skipped, instructions count: 109
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.V2SourceStampSigner.getSignedDigestsFor(int, java.util.Map, com.android.apksig.internal.apk.ApkSigningBlockUtils$SignerConfig, java.util.List):void");
    }

    private static byte[] encodeStampAttributes(Map<Integer, byte[]> stampAttributes) {
        int payloadSize = 0;
        for (byte[] attributeValue : stampAttributes.values()) {
            payloadSize += attributeValue.length + 8;
        }
        ByteBuffer result = ByteBuffer.allocate(payloadSize + 4);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(payloadSize);
        for (Map.Entry<Integer, byte[]> stampAttribute : stampAttributes.entrySet()) {
            result.putInt(stampAttribute.getValue().length + 4);
            result.putInt(stampAttribute.getKey().intValue());
            result.put(stampAttribute.getValue());
        }
        return result.array();
    }

    private static Map<Integer, byte[]> generateStampAttributes(SigningCertificateLineage lineage) {
        HashMap<Integer, byte[]> stampAttributes = new HashMap<>();
        if (lineage != null) {
            stampAttributes.put(Integer.valueOf((int) SourceStampConstants.PROOF_OF_ROTATION_ATTR_ID), lineage.encodeSigningCertificateLineage());
        }
        return stampAttributes;
    }

    /* access modifiers changed from: private */
    public static final class SourceStampBlock {
        public List<Pair<Integer, byte[]>> signedDigests;
        public List<Pair<Integer, byte[]>> signedStampAttributes;
        public byte[] stampAttributes;
        public byte[] stampCertificate;

        private SourceStampBlock() {
        }
    }
}
