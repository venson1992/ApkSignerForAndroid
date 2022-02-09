package com.android.apksig.internal.apk.v2;

import com.android.apksig.ApkVerifier;
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
import java.nio.ByteOrder;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class V2SchemeVerifier {
    private V2SchemeVerifier() {
    }

    public static ApkSigningBlockUtils.Result verify(RunnablesExecutor executor, DataSource apk, ApkUtils.ZipSections zipSections, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundSigSchemeIds, int minSdkVersion, int maxSdkVersion) throws IOException, ApkFormatException, NoSuchAlgorithmException, ApkSigningBlockUtils.SignatureNotFoundException {
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(2);
        SignatureInfo signatureInfo = ApkSigningBlockUtils.findSignature(apk, zipSections, 1896449818, result);
        verify(executor, apk.slice(0, signatureInfo.apkSigningBlockOffset), signatureInfo.signatureBlock, apk.slice(signatureInfo.centralDirOffset, signatureInfo.eocdOffset - signatureInfo.centralDirOffset), signatureInfo.eocd, supportedApkSigSchemeNames, foundSigSchemeIds, minSdkVersion, maxSdkVersion, result);
        return result;
    }

    private static void verify(RunnablesExecutor executor, DataSource beforeApkSigningBlock, ByteBuffer apkSignatureSchemeV2Block, DataSource centralDir, ByteBuffer eocd, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundSigSchemeIds, int minSdkVersion, int maxSdkVersion, ApkSigningBlockUtils.Result result) throws IOException, NoSuchAlgorithmException {
        Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
        parseSigners(apkSignatureSchemeV2Block, contentDigestsToVerify, supportedApkSigSchemeNames, foundSigSchemeIds, minSdkVersion, maxSdkVersion, result);
        if (!result.containsErrors()) {
            ApkSigningBlockUtils.verifyIntegrity(executor, beforeApkSigningBlock, centralDir, eocd, contentDigestsToVerify, result);
            if (!result.containsErrors()) {
                result.verified = true;
            }
        }
    }

    public static void parseSigners(ByteBuffer apkSignatureSchemeV2Block, Set<ContentDigestAlgorithm> contentDigestsToVerify, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds, int minSdkVersion, int maxSdkVersion, ApkSigningBlockUtils.Result result) throws NoSuchAlgorithmException {
        try {
            ByteBuffer signers = ApkSigningBlockUtils.getLengthPrefixedSlice(apkSignatureSchemeV2Block);
            if (!signers.hasRemaining()) {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNERS, new Object[0]);
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
                        parseSigner(ApkSigningBlockUtils.getLengthPrefixedSlice(signers), certFactory, signerInfo, contentDigestsToVerify, supportedApkSigSchemeNames, foundApkSigSchemeIds, minSdkVersion, maxSdkVersion);
                    } catch (ApkFormatException | BufferUnderflowException e) {
                        signerInfo.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNER, new Object[0]);
                        return;
                    }
                }
            } catch (CertificateException e2) {
                throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e2);
            }
        } catch (ApkFormatException e3) {
            result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNERS, new Object[0]);
        }
    }

    private static void parseSigner(ByteBuffer signerBlock, CertificateFactory certFactory, ApkSigningBlockUtils.Result.SignerInfo result, Set<ContentDigestAlgorithm> contentDigestsToVerify, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds, int minSdkVersion, int maxSdkVersion) throws ApkFormatException, NoSuchAlgorithmException {
        byte[] certificatePublicKeyBytes;
        ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(signerBlock);
        byte[] signedDataBytes = new byte[signedData.remaining()];
        signedData.get(signedDataBytes);
        signedData.flip();
        result.signedData = signedDataBytes;
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
                    result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_SIG_ALGORITHM, Integer.valueOf(sigAlgorithmId));
                } else {
                    supportedSignatures.add(new ApkSigningBlockUtils.SupportedSignature(signatureAlgorithm, sigBytes));
                }
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_SIGNATURE, Integer.valueOf(signatureCount));
                return;
            }
        }
        if (result.signatures.isEmpty()) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_SIGNATURES, new Object[0]);
            return;
        }
        try {
            for (ApkSigningBlockUtils.SupportedSignature signature2 : ApkSigningBlockUtils.getSignaturesToVerify(supportedSignatures, minSdkVersion, maxSdkVersion)) {
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
                            result.addError(ApkVerifier.Issue.V2_SIG_DID_NOT_VERIFY, signatureAlgorithm2);
                            return;
                        }
                        result.verifiedSignatures.put(signatureAlgorithm2, sigBytes2);
                        contentDigestsToVerify.add(signatureAlgorithm2.getContentDigestAlgorithm());
                    } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException e2) {
                        result.addError(ApkVerifier.Issue.V2_SIG_VERIFY_EXCEPTION, signatureAlgorithm2, e2);
                        return;
                    }
                } catch (Exception e3) {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_PUBLIC_KEY, e3);
                    return;
                }
            }
            signedData.position(0);
            ByteBuffer digests = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ByteBuffer certificates = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
            int certificateIndex = -1;
            while (certificates.hasRemaining()) {
                certificateIndex++;
                byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(certificates);
                try {
                    result.certs.add(new GuaranteedEncodedFormX509Certificate(X509CertificateUtils.generateCertificate(encodedCert, certFactory), encodedCert));
                } catch (CertificateException e4) {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_CERTIFICATE, Integer.valueOf(certificateIndex), Integer.valueOf(certificateIndex + 1), e4);
                    return;
                }
            }
            if (result.certs.isEmpty()) {
                result.addError(ApkVerifier.Issue.V2_SIG_NO_CERTIFICATES, new Object[0]);
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
                result.addError(ApkVerifier.Issue.V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD, ApkSigningBlockUtils.toHex(certificatePublicKeyBytes), ApkSigningBlockUtils.toHex(publicKeyBytes));
                return;
            }
            int digestCount = 0;
            while (digests.hasRemaining()) {
                digestCount++;
                try {
                    ByteBuffer digest = ApkSigningBlockUtils.getLengthPrefixedSlice(digests);
                    result.contentDigests.add(new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(digest.getInt(), ApkSigningBlockUtils.readLengthPrefixedByteArray(digest)));
                } catch (ApkFormatException | BufferUnderflowException e6) {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_DIGEST, Integer.valueOf(digestCount));
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
                result.addError(ApkVerifier.Issue.V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS, sigAlgsFromSignaturesRecord, sigAlgsFromDigestsRecord);
                return;
            }
            int additionalAttributeCount = 0;
            Set<Integer> supportedApkSigSchemeIds = supportedApkSigSchemeNames.keySet();
            Set<Integer> supportedExpectedApkSigSchemeIds = new HashSet<>(1);
            while (additionalAttributes.hasRemaining()) {
                additionalAttributeCount++;
                try {
                    ByteBuffer attribute = ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
                    int id = attribute.getInt();
                    byte[] value = ByteBufferUtils.toByteArray(attribute);
                    result.additionalAttributes.add(new ApkSigningBlockUtils.Result.SignerInfo.AdditionalAttribute(id, value));
                    switch (id) {
                        case V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID:
                            int foundId = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN).getInt();
                            if (supportedApkSigSchemeIds.contains(Integer.valueOf(foundId))) {
                                supportedExpectedApkSigSchemeIds.add(Integer.valueOf(foundId));
                                break;
                            } else {
                                result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID, Integer.valueOf(result.index), Integer.valueOf(foundId));
                                break;
                            }
                        default:
                            result.addWarning(ApkVerifier.Issue.V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE, Integer.valueOf(id));
                            break;
                    }
                } catch (ApkFormatException | BufferUnderflowException e7) {
                    result.addError(ApkVerifier.Issue.V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE, Integer.valueOf(additionalAttributeCount));
                    return;
                }
            }
            for (Integer num : supportedExpectedApkSigSchemeIds) {
                int id2 = num.intValue();
                if (!foundApkSigSchemeIds.contains(Integer.valueOf(id2))) {
                    result.addError(ApkVerifier.Issue.V2_SIG_MISSING_APK_SIG_REFERENCED, Integer.valueOf(result.index), supportedApkSigSchemeNames.get(Integer.valueOf(id2)));
                }
            }
        } catch (ApkSigningBlockUtils.NoSupportedSignaturesException e8) {
            result.addError(ApkVerifier.Issue.V2_SIG_NO_SUPPORTED_SIGNATURES, e8);
        }
    }
}
