package com.android.apksig.internal.apk.v3;

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.SignatureInfo;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.X509CertificateUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

public abstract class V3SchemeVerifier {
    private V3SchemeVerifier() {
    }

    public static ApkSigningBlockUtils.Result verify(RunnablesExecutor executor, DataSource apk, ApkUtils.ZipSections zipSections, int minSdkVersion, int maxSdkVersion) throws IOException, NoSuchAlgorithmException, ApkSigningBlockUtils.SignatureNotFoundException {
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(3);
        SignatureInfo signatureInfo = ApkSigningBlockUtils.findSignature(apk, zipSections, -262969152, result);
        DataSource beforeApkSigningBlock = apk.slice(0, signatureInfo.apkSigningBlockOffset);
        DataSource centralDir = apk.slice(signatureInfo.centralDirOffset, signatureInfo.eocdOffset - signatureInfo.centralDirOffset);
        ByteBuffer eocd = signatureInfo.eocd;
        if (minSdkVersion < 28) {
            minSdkVersion = 28;
        }
        verify(executor, beforeApkSigningBlock, signatureInfo.signatureBlock, centralDir, eocd, minSdkVersion, maxSdkVersion, result);
        return result;
    }

    private static void verify(RunnablesExecutor executor, DataSource beforeApkSigningBlock, ByteBuffer apkSignatureSchemeV3Block, DataSource centralDir, ByteBuffer eocd, int minSdkVersion, int maxSdkVersion, ApkSigningBlockUtils.Result result) throws IOException, NoSuchAlgorithmException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        parseSigners(apkSignatureSchemeV3Block, contentDigestsToVerify, result);
        if (!result.containsErrors()) {
            ApkSigningBlockUtils.verifyIntegrity(executor, beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, result);
            SortedMap<Integer, ApkSigningBlockUtils.Result.SignerInfo> sortedSigners = new TreeMap<>();
            for (ApkSigningBlockUtils.Result.SignerInfo signer : result.signers) {
                sortedSigners.put(Integer.valueOf(signer.minSdkVersion), signer);
            }
            int firstMin = 0;
            int lastMax = 0;
            int lastLineageSize = 0;
            List<SigningCertificateLineage> lineages = new ArrayList<>(result.signers.size());
            Iterator<ApkSigningBlockUtils.Result.SignerInfo> it = sortedSigners.values().iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                ApkSigningBlockUtils.Result.SignerInfo signer2 = it.next();
                int currentMin = signer2.minSdkVersion;
                int currentMax = signer2.maxSdkVersion;
                if (firstMin != 0) {
                    if (currentMin != lastMax + 1) {
                        result.addError(ApkVerifier.Issue.V3_INCONSISTENT_SDK_VERSIONS, new Object[0]);
                        break;
                    }
                } else {
                    firstMin = currentMin;
                }
                lastMax = currentMax;
                if (signer2.signingCertificateLineage != null) {
                    int currLineageSize = signer2.signingCertificateLineage.size();
                    if (currLineageSize < lastLineageSize) {
                        result.addError(ApkVerifier.Issue.V3_INCONSISTENT_LINEAGES, new Object[0]);
                        break;
                    } else {
                        lastLineageSize = currLineageSize;
                        lineages.add(signer2.signingCertificateLineage);
                    }
                }
            }
            if (firstMin > minSdkVersion || lastMax < maxSdkVersion) {
                result.addError(ApkVerifier.Issue.V3_MISSING_SDK_VERSIONS, Integer.valueOf(firstMin), Integer.valueOf(lastMax));
            }
            try {
                result.signingCertificateLineage = SigningCertificateLineage.consolidateLineages(lineages);
            } catch (IllegalArgumentException e) {
                result.addError(ApkVerifier.Issue.V3_INCONSISTENT_LINEAGES, new Object[0]);
            }
            if (!result.containsErrors()) {
                result.verified = true;
            }
        }
    }

    public static void parseSigners(ByteBuffer apkSignatureSchemeV3Block, Set<ContentDigestAlgorithm> contentDigestsToVerify, ApkSigningBlockUtils.Result result) throws NoSuchAlgorithmException {
        try {
            ByteBuffer signers = ApkSigningBlockUtils.getLengthPrefixedSlice(apkSignatureSchemeV3Block);
            if (!signers.hasRemaining()) {
                result.addError(ApkVerifier.Issue.V3_SIG_NO_SIGNERS, new Object[0]);
                return;
            }
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                int signerCount = 0;
                while (signers.hasRemaining()) {
                    signerCount++;
                    ApkSigningBlockUtils.Result.SignerInfo signerInfo = new ApkSigningBlockUtils.Result.SignerInfo();
                    signerInfo.index = signerCount;
                    result.signers.add(signerInfo);
                    try {
                        parseSigner(ApkSigningBlockUtils.getLengthPrefixedSlice(signers), certFactory, signerInfo, contentDigestsToVerify);
                    } catch (ApkFormatException | BufferUnderflowException e) {
                        signerInfo.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNER, new Object[0]);
                        return;
                    }
                }
            } catch (CertificateException e2) {
                throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e2);
            }
        } catch (ApkFormatException e3) {
            result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNERS, new Object[0]);
        }
    }

    private static void parseSigner(ByteBuffer signerBlock, CertificateFactory certFactory, ApkSigningBlockUtils.Result.SignerInfo result, Set<ContentDigestAlgorithm> contentDigestsToVerify) throws ApkFormatException, NoSuchAlgorithmException {
        byte[] certificatePublicKeyBytes;
        ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] signedDataBytes = new byte[signedData.remaining()];
        signedData.get(signedDataBytes);
        signedData.flip();
        result.signedData = signedDataBytes;
        int parsedMinSdkVersion = signerBlock.getInt();
        int parsedMaxSdkVersion = signerBlock.getInt();
        result.minSdkVersion = parsedMinSdkVersion;
        result.maxSdkVersion = parsedMaxSdkVersion;
        if (parsedMinSdkVersion < 0 || parsedMinSdkVersion > parsedMaxSdkVersion) {
            result.addError(ApkVerifier.Issue.V3_SIG_INVALID_SDK_VERSIONS, Integer.valueOf(parsedMinSdkVersion), Integer.valueOf(parsedMaxSdkVersion));
        }
        ByteBuffer signatures = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] publicKeyBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signerBlock);
        int signatureCount = 0;
        List<ApkSigningBlockUtils.SupportedSignature> supportedSignatures = new ArrayList<>(1);
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = ApkSigningBlockUtils.getLengthPrefixedSlice(signatures);
                int sigAlgorithmId = signature.getInt();
                byte[] sigBytes = ApkSigningBlockUtils.readLengthPrefixedByteArray(signature);
                result.signatures.add(new ApkSigningBlockUtils.Result.SignerInfo.Signature(sigAlgorithmId, sigBytes));
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                if (signatureAlgorithm == null) {
                    result.addWarning(ApkVerifier.Issue.V3_SIG_UNKNOWN_SIG_ALGORITHM, Integer.valueOf(sigAlgorithmId));
                } else {
                    supportedSignatures.add(new ApkSigningBlockUtils.SupportedSignature(signatureAlgorithm, sigBytes));
                }
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_SIGNATURE, Integer.valueOf(signatureCount));
                return;
            }
        }
        if (result.signatures.isEmpty()) {
            result.addError(ApkVerifier.Issue.V3_SIG_NO_SIGNATURES, new Object[0]);
            return;
        }
        try {
            for (ApkSigningBlockUtils.SupportedSignature signature2 : ApkSigningBlockUtils.getSignaturesToVerify(supportedSignatures, result.minSdkVersion, result.maxSdkVersion)) {
                SignatureAlgorithm signatureAlgorithm2 = signature2.algorithm;
                String jcaSignatureAlgorithm = signatureAlgorithm2.getJcaSignatureAlgorithmAndParams().getFirst();
                AlgorithmParameterSpec jcaSignatureAlgorithmParams = (AlgorithmParameterSpec) signatureAlgorithm2.getJcaSignatureAlgorithmAndParams().getSecond();
                try {
                    PublicKey publicKey = KeyFactory.getInstance(signatureAlgorithm2.getJcaKeyAlgorithm()).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                    try {
                        Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                        sig.initVerify(publicKey);
                        if (jcaSignatureAlgorithmParams != null) {
                            sig.setParameter(jcaSignatureAlgorithmParams);
                        }
                        signedData.position(0);
                        sig.update(signedData);
                        byte[] sigBytes2 = signature2.signature;
                        if (!sig.verify(sigBytes2)) {
                            result.addError(ApkVerifier.Issue.V3_SIG_DID_NOT_VERIFY, signatureAlgorithm2);
                            return;
                        }
                        result.verifiedSignatures.put(signatureAlgorithm2, sigBytes2);
                        contentDigestsToVerify.add(signatureAlgorithm2.getContentDigestAlgorithm());
                    } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException e2) {
                        result.addError(ApkVerifier.Issue.V3_SIG_VERIFY_EXCEPTION, signatureAlgorithm2, e2);
                        return;
                    }
                } catch (Exception e3) {
                    result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_PUBLIC_KEY, e3);
                    return;
                }
            }
            signedData.position(0);
            ByteBuffer digests = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ByteBuffer certificates = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            int signedMinSdkVersion = signedData.getInt();
            if (signedMinSdkVersion != parsedMinSdkVersion) {
                result.addError(ApkVerifier.Issue.V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD, Integer.valueOf(parsedMinSdkVersion), Integer.valueOf(signedMinSdkVersion));
            }
            int signedMaxSdkVersion = signedData.getInt();
            if (signedMaxSdkVersion != parsedMaxSdkVersion) {
                result.addError(ApkVerifier.Issue.V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD, Integer.valueOf(parsedMaxSdkVersion), Integer.valueOf(signedMaxSdkVersion));
            }
            ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            int certificateIndex = -1;
            while (certificates.hasRemaining()) {
                certificateIndex++;
                byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(certificates);
                try {
                    result.certs.add(new GuaranteedEncodedFormX509Certificate(X509CertificateUtils.generateCertificate(encodedCert, certFactory), encodedCert));
                } catch (CertificateException e4) {
                    result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_CERTIFICATE, Integer.valueOf(certificateIndex), Integer.valueOf(certificateIndex + 1), e4);
                    return;
                }
            }
            if (result.certs.isEmpty()) {
                result.addError(ApkVerifier.Issue.V3_SIG_NO_CERTIFICATES, new Object[0]);
                return;
            }
            X509Certificate mainCertificate = (X509Certificate) result.certs.get(0);
            try {
                certificatePublicKeyBytes = ApkSigningBlockUtils.encodePublicKey(mainCertificate.getPublicKey());
            } catch (InvalidKeyException e5) {
                System.out.println("Caught an exception encoding the public key: " + e5);
                e5.printStackTrace();
                certificatePublicKeyBytes = mainCertificate.getPublicKey().getEncoded();
            }
            if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
                result.addError(ApkVerifier.Issue.V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD, ApkSigningBlockUtils.toHex(certificatePublicKeyBytes), ApkSigningBlockUtils.toHex(publicKeyBytes));
                return;
            }
            int digestCount = 0;
            while (digests.hasRemaining()) {
                digestCount++;
                try {
                    ByteBuffer digest = ApkSigningBlockUtils.getLengthPrefixedSlice(digests);
                    result.contentDigests.add(new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(digest.getInt(), ApkSigningBlockUtils.readLengthPrefixedByteArray(digest)));
                } catch (ApkFormatException | BufferUnderflowException e6) {
                    result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_DIGEST, Integer.valueOf(digestCount));
                    return;
                }
            }
            List<Integer> sigAlgsFromSignaturesRecord = new ArrayList<>(result.signatures.size());
            for (ApkSigningBlockUtils.Result.SignerInfo.Signature signature3 : result.signatures) {
                sigAlgsFromSignaturesRecord.add(Integer.valueOf(signature3.getAlgorithmId()));
            }
            List<Integer> sigAlgsFromDigestsRecord = new ArrayList<>(result.contentDigests.size());
            for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest digest2 : result.contentDigests) {
                sigAlgsFromDigestsRecord.add(Integer.valueOf(digest2.getSignatureAlgorithmId()));
            }
            if (!sigAlgsFromSignaturesRecord.equals(sigAlgsFromDigestsRecord)) {
                result.addError(ApkVerifier.Issue.V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS, sigAlgsFromSignaturesRecord, sigAlgsFromDigestsRecord);
                return;
            }
            int additionalAttributeCount = 0;
            while (additionalAttributes.hasRemaining()) {
                additionalAttributeCount++;
                try {
                    ByteBuffer attribute = ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                    int id = attribute.getInt();
                    byte[] value = ByteBufferUtils.toByteArray(attribute);
                    result.additionalAttributes.add(new ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                    if (id == 1000370060) {
                        try {
                            result.signingCertificateLineage = SigningCertificateLineage.readFromV3AttributeValue(value);
                            if (result.signingCertificateLineage.size() != result.signingCertificateLineage.getSubLineage((X509Certificate) result.certs.get(0)).size()) {
                                result.addError(ApkVerifier.Issue.V3_SIG_POR_CERT_MISMATCH, new Object[0]);
                            }
                        } catch (SecurityException e7) {
                            result.addError(ApkVerifier.Issue.V3_SIG_POR_DID_NOT_VERIFY, new Object[0]);
                        } catch (IllegalArgumentException e8) {
                            result.addError(ApkVerifier.Issue.V3_SIG_POR_CERT_MISMATCH, new Object[0]);
                        } catch (Exception e9) {
                            result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_LINEAGE, new Object[0]);
                        }
                    } else {
                        result.addWarning(ApkVerifier.Issue.V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, Integer.valueOf(id));
                    }
                } catch (ApkFormatException | BufferUnderflowException e10) {
                    result.addError(ApkVerifier.Issue.V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, Integer.valueOf(additionalAttributeCount));
                    return;
                }
            }
        } catch (ApkSigningBlockUtils.NoSupportedSignaturesException e11) {
            result.addError(ApkVerifier.Issue.V3_SIG_NO_SUPPORTED_SIGNATURES, new Object[0]);
        }
    }
}
