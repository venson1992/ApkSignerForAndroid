package com.android.apksig.internal.apk.stamp;

import com.android.apksig.internal.util.Pair;
import java.util.List;

public abstract class V1SourceStampSigner {
    public static final int V1_SOURCE_STAMP_BLOCK_ID = 722016414;

    private V1SourceStampSigner() {
    }

    /*  JADX ERROR: JadxRuntimeException in pass: BlockSplitter
        jadx.core.utils.exceptions.JadxRuntimeException: Missing block: 70
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.getBlock(BlockSplitter.java:307)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.setupConnections(BlockSplitter.java:236)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.splitBasicBlocks(BlockSplitter.java:129)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.visit(BlockSplitter.java:52)
        */
    public static com.android.apksig.internal.util.Pair<byte[], java.lang.Integer> generateSourceStampBlock(com.android.apksig.internal.apk.ApkSigningBlockUtils.SignerConfig r10, java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]> r11) throws java.security.SignatureException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException {
        /*
        // Method dump skipped, instructions count: 157
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.V1SourceStampSigner.generateSourceStampBlock(com.android.apksig.internal.apk.ApkSigningBlockUtils$SignerConfig, java.util.Map):com.android.apksig.internal.util.Pair");
    }

    private static final class SourceStampBlock {
        public List<Pair<Integer, byte[]>> signedDigests;
        public byte[] stampCertificate;

        private SourceStampBlock() {
        }
    }
}
