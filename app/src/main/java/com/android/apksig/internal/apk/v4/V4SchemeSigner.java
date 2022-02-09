package com.android.apksig.internal.apk.v4;

import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v2.V2SchemeVerifier;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SchemeVerifier;
import com.android.apksig.internal.apk.v4.V4Signature;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public abstract class V4SchemeSigner {
    private V4SchemeSigner() {
    }

    public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey, int minSdkVersion, boolean apkSigningBlockPaddingSupported) throws InvalidKeyException {
        List<SignatureAlgorithm> algorithms = V3SchemeSigner.getSuggestedSignatureAlgorithms(signingKey, minSdkVersion, apkSigningBlockPaddingSupported);
        Iterator<SignatureAlgorithm> iter = algorithms.listIterator();
        while (iter.hasNext()) {
            if (!isSupported(iter.next().getContentDigestAlgorithm(), false)) {
                iter.remove();
            }
        }
        return algorithms;
    }

    public static void generateV4Signature(DataSource apkContent, ApkSigningBlockUtils.SignerConfig signerConfig, File outputFile) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        Pair<V4Signature, byte[]> pair = generateV4Signature(apkContent, signerConfig);
        try {
            OutputStream output = new FileOutputStream(outputFile);
            try {
                pair.getFirst().writeTo(output);
                V4Signature.writeBytes(output, pair.getSecond());
                output.close();
                return;
            } catch (Throwable th) {
                th.addSuppressed(th);
            }
            throw th;
        } catch (IOException e) {
            outputFile.delete();
            throw e;
        }
    }

    public static Pair<V4Signature, byte[]> generateV4Signature(DataSource apkContent, ApkSigningBlockUtils.SignerConfig signerConfig) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        long fileSize = apkContent.size();
        byte[] apkDigest = getApkDigest(apkContent);
        ApkSigningBlockUtils.VerityTreeAndDigest verityContentDigestInfo = ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent);
        ContentDigestAlgorithm verityContentDigestAlgorithm = verityContentDigestInfo.contentDigestAlgorithm;
        byte[] rootHash = verityContentDigestInfo.rootHash;
        byte[] tree = verityContentDigestInfo.tree;
        Pair<Integer, Byte> hashingAlgorithmBlockSizePair = convertToV4HashingInfo(verityContentDigestAlgorithm);
        try {
            return Pair.of(generateSignature(signerConfig, new V4Signature.HashingInfo(hashingAlgorithmBlockSizePair.getFirst().intValue(), hashingAlgorithmBlockSizePair.getSecond().byteValue(), null, rootHash), apkDigest, null, fileSize), tree);
        } catch (InvalidKeyException | SignatureException | CertificateEncodingException e) {
            throw new InvalidKeyException("Signer failed", e);
        }
    }

    private static V4Signature generateSignature(ApkSigningBlockUtils.SignerConfig signerConfig, V4Signature.HashingInfo hashingInfo, byte[] apkDigest, byte[] additionaData, long fileSize) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateEncodingException {
        if (signerConfig.certificates.isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        } else if (signerConfig.certificates.size() != 1) {
            throw new CertificateEncodingException("Should only have one certificate");
        } else {
            PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();
            byte[] encodedCertificate = ApkSigningBlockUtils.encodeCertificates(signerConfig.certificates).get(0);
            List<Pair<Integer, byte[]>> signatures = ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, V4Signature.getSigningData(fileSize, hashingInfo, new V4Signature.SigningInfo(apkDigest, encodedCertificate, additionaData, publicKey.getEncoded(), -1, null)));
            if (signatures.size() != 1) {
                throw new SignatureException("Should only be one signature generated");
            }
            return new V4Signature(2, hashingInfo.toByteArray(), new V4Signature.SigningInfo(apkDigest, encodedCertificate, additionaData, publicKey.getEncoded(), signatures.get(0).getFirst().intValue(), signatures.get(0).getSecond()).toByteArray());
        }
    }

    private static byte[] getApkDigest(DataSource apk) throws IOException {
        try {
            ApkUtils.ZipSections zipSections = ApkUtils.findZipSections(apk);
            try {
                return getBestV3Digest(apk, zipSections);
            } catch (SignatureException e) {
                try {
                    return getBestV2Digest(apk, zipSections);
                } catch (SignatureException e2) {
                    throw new IOException("Failed to obtain v2/v3 digest, v3 exception: " + e + ", v2 exception: " + e2);
                }
            }
        } catch (ZipFormatException e3) {
            throw new IOException("Malformed APK: not a ZIP archive", e3);
        }
    }

    private static byte[] getBestV3Digest(DataSource apk, ApkUtils.ZipSections zipSections) throws SignatureException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(3);
        try {
            V3SchemeVerifier.parseSigners(ApkSigningBlockUtils.findSignature(apk, zipSections, -262969152, result).signatureBlock, contentDigestsToVerify, result);
            if (result.signers.size() != 1) {
                throw new SignatureException("Should only have one signer, errors: " + result.getErrors());
            }
            ApkSigningBlockUtils.Result.SignerInfo signer = result.signers.get(0);
            if (!signer.containsErrors()) {
                return pickBestDigest(result.signers.get(0).contentDigests);
            }
            throw new SignatureException("Parsing failed: " + signer.getErrors());
        } catch (Exception e) {
            throw new SignatureException("Failed to extract and parse v3 block", e);
        }
    }

    private static byte[] getBestV2Digest(DataSource apk, ApkUtils.ZipSections zipSections) throws SignatureException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        Set<Integer> foundApkSigSchemeIds = new HashSet<>(1);
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(2);
        try {
            V2SchemeVerifier.parseSigners(ApkSigningBlockUtils.findSignature(apk, zipSections, 1896449818, result).signatureBlock, contentDigestsToVerify, Collections.emptyMap(), foundApkSigSchemeIds, Integer.MAX_VALUE, Integer.MAX_VALUE, result);
            if (result.signers.size() != 1) {
                throw new SignatureException("Should only have one signer, errors: " + result.getErrors());
            }
            ApkSigningBlockUtils.Result.SignerInfo signer = result.signers.get(0);
            if (!signer.containsErrors()) {
                return pickBestDigest(signer.contentDigests);
            }
            throw new SignatureException("Parsing failed: " + signer.getErrors());
        } catch (Exception e) {
            throw new SignatureException("Failed to extract and parse v2 block", e);
        }
    }

    private static byte[] pickBestDigest(List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests) throws SignatureException {
        int algorithmOrder;
        if (contentDigests == null || contentDigests.isEmpty()) {
            throw new SignatureException("Should have at least one digest");
        }
        int bestAlgorithmOrder = -1;
        byte[] bestDigest = null;
        for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest : contentDigests) {
            ContentDigestAlgorithm contentDigestAlgorithm = SignatureAlgorithm.findById(contentDigest.getSignatureAlgorithmId()).getContentDigestAlgorithm();
            if (isSupported(contentDigestAlgorithm, true) && bestAlgorithmOrder < (algorithmOrder = digestAlgorithmSortingOrder(contentDigestAlgorithm))) {
                bestAlgorithmOrder = algorithmOrder;
                bestDigest = contentDigest.getValue();
            }
        }
        if (bestDigest != null) {
            return bestDigest;
        }
        throw new SignatureException("Failed to find a supported digest in the source APK");
    }

    public static int digestAlgorithmSortingOrder(ContentDigestAlgorithm contentDigestAlgorithm) {
        switch (contentDigestAlgorithm) {
            case CHUNKED_SHA256:
                return 0;
            case VERITY_CHUNKED_SHA256:
                return 1;
            case CHUNKED_SHA512:
                return 2;
            default:
                return -1;
        }
    }

    private static boolean isSupported(ContentDigestAlgorithm contentDigestAlgorithm, boolean forV3Digest) {
        if (contentDigestAlgorithm == null) {
            return false;
        }
        if (contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA256 || contentDigestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA512 || (forV3Digest && contentDigestAlgorithm == ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)) {
            return true;
        }
        return false;
    }

    private static Pair<Integer, Byte> convertToV4HashingInfo(ContentDigestAlgorithm algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case VERITY_CHUNKED_SHA256:
                return Pair.of(1, Byte.valueOf((byte) V4Signature.LOG2_BLOCK_SIZE_4096_BYTES));
            default:
                throw new NoSuchAlgorithmException("Invalid hash algorithm, only SHA2-256 over 4 KB chunks supported.");
        }
    }
}
