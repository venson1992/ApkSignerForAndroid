package com.android.apksig.internal.apk.stamp;

import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.util.DataSource;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Map;

public abstract class V1SourceStampVerifier {
    private V1SourceStampVerifier() {
    }

    public static ApkSigningBlockUtils.Result verify(DataSource apk, ApkUtils.ZipSections zipSections, byte[] sourceStampCertificateDigest, Map<ContentDigestAlgorithm, byte[]> apkContentDigests, int minSdkVersion, int maxSdkVersion) throws IOException, NoSuchAlgorithmException, ApkSigningBlockUtils.SignatureNotFoundException {
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(0);
        verify(ApkSigningBlockUtils.findSignature(apk, zipSections, 722016414, result).signatureBlock, sourceStampCertificateDigest, apkContentDigests, minSdkVersion, maxSdkVersion, result);
        return result;
    }

    private static void verify(ByteBuffer sourceStampBlock, byte[] sourceStampCertificateDigest, Map<ContentDigestAlgorithm, byte[]> apkContentDigests, int minSdkVersion, int maxSdkVersion, ApkSigningBlockUtils.Result result) throws NoSuchAlgorithmException {
        boolean z;
        ApkSigningBlockUtils.Result.SignerInfo signerInfo = new ApkSigningBlockUtils.Result.SignerInfo();
        result.signers.add(signerInfo);
        try {
            SourceStampVerifier.verifyV1SourceStamp(ApkSigningBlockUtils.getLengthPrefixedSlice(sourceStampBlock), CertificateFactory.getInstance("X.509"), signerInfo, ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(getApkDigests(apkContentDigests)), sourceStampCertificateDigest, minSdkVersion, maxSdkVersion);
            if (result.containsErrors() || result.containsWarnings()) {
                z = false;
            } else {
                z = true;
            }
            result.verified = z;
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to obtain X.509 CertificateFactory", e);
        } catch (ApkFormatException | BufferUnderflowException e2) {
            signerInfo.addWarning(ApkVerifier.Issue.SOURCE_STAMP_MALFORMED_SIGNATURE, new Object[0]);
        }
    }

    /*  JADX ERROR: JadxRuntimeException in pass: BlockSplitter
        jadx.core.utils.exceptions.JadxRuntimeException: Missing block: 53
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.getBlock(BlockSplitter.java:307)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.setupConnections(BlockSplitter.java:236)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.splitBasicBlocks(BlockSplitter.java:129)
        	at jadx.core.dex.visitors.blocksmaker.BlockSplitter.visit(BlockSplitter.java:52)
        */
    private static java.util.List<com.android.apksig.internal.util.Pair<java.lang.Integer, byte[]>> getApkDigests(java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]> r5) {
        /*
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            java.util.Set r2 = r5.entrySet()
            java.util.Iterator r3 = r2.iterator()
        L_0x000d:
            boolean r2 = r3.hasNext()
            if (r2 == 0) goto L_0x0035
            java.lang.Object r0 = r3.next()
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0
            java.lang.Object r2 = r0.getKey()
            com.android.apksig.internal.apk.ContentDigestAlgorithm r2 = (com.android.apksig.internal.apk.ContentDigestAlgorithm) r2
            int r2 = r2.getId()
            java.lang.Integer r4 = java.lang.Integer.valueOf(r2)
            java.lang.Object r2 = r0.getValue()
            byte[] r2 = (byte[]) r2
            com.android.apksig.internal.util.Pair r2 = com.android.apksig.internal.util.Pair.of(r4, r2)
            r1.add(r2)
            goto L_0x000d
        L_?:
            r2 = move-result
            java.util.Comparator r2 = java.util.Comparator.comparing(r2)
            java.util.Collections.sort(r1, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.V1SourceStampVerifier.getApkDigests(java.util.Map):java.util.List");
    }
}
