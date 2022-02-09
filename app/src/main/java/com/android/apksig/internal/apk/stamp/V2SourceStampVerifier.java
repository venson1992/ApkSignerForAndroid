package com.android.apksig.internal.apk.stamp;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.apk.ApkSigResult;
import com.android.apksig.internal.apk.ApkSignerInfo;
import com.android.apksig.internal.apk.ApkSigningBlockUtilsLite;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureNotFoundException;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipSections;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;

public abstract class V2SourceStampVerifier {
    private V2SourceStampVerifier() {
    }

    public static ApkSigResult verify(DataSource apk, ZipSections zipSections, byte[] sourceStampCertificateDigest, Map<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests, int minSdkVersion, int maxSdkVersion) throws IOException, NoSuchAlgorithmException, SignatureNotFoundException {
        ApkSigResult result = new ApkSigResult(0);
        verify(ApkSigningBlockUtilsLite.findSignature(apk, zipSections, 1845461005).signatureBlock, sourceStampCertificateDigest, signatureSchemeApkContentDigests, minSdkVersion, maxSdkVersion, result);
        return result;
    }

    private static void verify(ByteBuffer sourceStampBlock, byte[] sourceStampCertificateDigest, Map<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests, int minSdkVersion, int maxSdkVersion, ApkSigResult result) throws NoSuchAlgorithmException {
        boolean z;
        ApkSignerInfo signerInfo = new ApkSignerInfo();
        result.mSigners.add(signerInfo);
        try {
            SourceStampVerifier.verifyV2SourceStamp(ApkSigningBlockUtilsLite.getLengthPrefixedSlice(sourceStampBlock), CertificateFactory.getInstance("X.509"), signerInfo, getSignatureSchemeDigests(signatureSchemeApkContentDigests), sourceStampCertificateDigest, minSdkVersion, maxSdkVersion);
            if (result.containsErrors() || result.containsWarnings()) {
                z = false;
            } else {
                z = true;
            }
            result.verified = z;
        } catch (CertificateException e) {
            throw new IllegalStateException("Failed to obtain X.509 CertificateFactory", e);
        } catch (ApkFormatException | BufferUnderflowException e2) {
            signerInfo.addWarning(20, new Object[0]);
        }
    }

    private static Map<Integer, byte[]> getSignatureSchemeDigests(Map<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests) {
        Map<Integer, byte[]> digests = new HashMap<>();
        for (Map.Entry<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigest : signatureSchemeApkContentDigests.entrySet()) {
            digests.put(signatureSchemeApkContentDigest.getKey(), ApkSigningBlockUtilsLite.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(getApkDigests(signatureSchemeApkContentDigest.getValue())));
        }
        return digests;
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
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.V2SourceStampVerifier.getApkDigests(java.util.Map):java.util.List");
    }
}
