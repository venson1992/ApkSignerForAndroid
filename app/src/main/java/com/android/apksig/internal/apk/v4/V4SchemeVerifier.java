package com.android.apksig.internal.apk.v4;

import com.android.apksig.ApkVerifier;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v4.V4Signature;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.X509CertificateUtils;
import com.android.apksig.util.DataSource;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public abstract class V4SchemeVerifier {
    private V4SchemeVerifier() {
    }

    public static ApkSigningBlockUtils.Result verify(DataSource apk, File v4SignatureFile) throws IOException, NoSuchAlgorithmException {
        InputStream input = new FileInputStream(v4SignatureFile);
        try {
            V4Signature signature = V4Signature.readFrom(input);
            byte[] tree = V4Signature.readBytes(input);
            input.close();
            ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(4);
            if (signature == null) {
                result.addError(ApkVerifier.Issue.V4_SIG_NO_SIGNATURES, "Signature file does not contain a v4 signature.");
            } else {
                if (signature.version != 2) {
                    result.addWarning(ApkVerifier.Issue.V4_SIG_VERSION_NOT_CURRENT, Integer.valueOf(signature.version), 2);
                }
                V4Signature.HashingInfo hashingInfo = V4Signature.HashingInfo.fromByteArray(signature.hashingInfo);
                V4Signature.SigningInfo signingInfo = V4Signature.SigningInfo.fromByteArray(signature.signingInfo);
                ApkSigningBlockUtils.Result.SignerInfo signerInfo = parseAndVerifySignatureBlock(signingInfo, V4Signature.getSigningData(apk.size(), hashingInfo, signingInfo));
                result.signers.add(signerInfo);
                if (!result.containsErrors()) {
                    verifyRootHashAndTree(apk, signerInfo, hashingInfo.rawRootHash, tree);
                    if (!result.containsErrors()) {
                        result.verified = true;
                    }
                }
            }
            return result;
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    }

    private static ApkSigningBlockUtils.Result.SignerInfo parseAndVerifySignatureBlock(V4Signature.SigningInfo signingInfo, byte[] signedData) throws NoSuchAlgorithmException {
        byte[] certificatePublicKeyBytes;
        ApkSigningBlockUtils.Result.SignerInfo result = new ApkSigningBlockUtils.Result.SignerInfo();
        result.index = 0;
        int sigAlgorithmId = signingInfo.signatureAlgorithmId;
        byte[] sigBytes = signingInfo.signature;
        result.signatures.add(new ApkSigningBlockUtils.Result.SignerInfo.Signature(sigAlgorithmId, sigBytes));
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
        if (signatureAlgorithm == null) {
            result.addError(ApkVerifier.Issue.V4_SIG_UNKNOWN_SIG_ALGORITHM, Integer.valueOf(sigAlgorithmId));
        } else {
            String jcaSignatureAlgorithm = signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getFirst();
            AlgorithmParameterSpec jcaSignatureAlgorithmParams = (AlgorithmParameterSpec) signatureAlgorithm.getJcaSignatureAlgorithmAndParams().getSecond();
            String keyAlgorithm = signatureAlgorithm.getJcaKeyAlgorithm();
            byte[] publicKeyBytes = signingInfo.publicKey;
            try {
                PublicKey publicKey = KeyFactory.getInstance(keyAlgorithm).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                try {
                    Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                    sig.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null) {
                        sig.setParameter(jcaSignatureAlgorithmParams);
                    }
                    sig.update(signedData);
                    if (!sig.verify(sigBytes)) {
                        result.addError(ApkVerifier.Issue.V4_SIG_DID_NOT_VERIFY, signatureAlgorithm);
                    } else {
                        result.verifiedSignatures.put(signatureAlgorithm, sigBytes);
                        if (signingInfo.certificate == null) {
                            result.addError(ApkVerifier.Issue.V4_SIG_NO_CERTIFICATE, new Object[0]);
                        } else {
                            try {
                                GuaranteedEncodedFormX509Certificate guaranteedEncodedFormX509Certificate = new GuaranteedEncodedFormX509Certificate(X509CertificateUtils.generateCertificate(signingInfo.certificate), signingInfo.certificate);
                                result.certs.add(guaranteedEncodedFormX509Certificate);
                                try {
                                    certificatePublicKeyBytes = ApkSigningBlockUtils.encodePublicKey(guaranteedEncodedFormX509Certificate.getPublicKey());
                                } catch (InvalidKeyException e) {
                                    System.out.println("Caught an exception encoding the public key: " + e);
                                    e.printStackTrace();
                                    certificatePublicKeyBytes = guaranteedEncodedFormX509Certificate.getPublicKey().getEncoded();
                                }
                                if (!Arrays.equals(publicKeyBytes, certificatePublicKeyBytes)) {
                                    result.addError(ApkVerifier.Issue.V4_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD, ApkSigningBlockUtils.toHex(certificatePublicKeyBytes), ApkSigningBlockUtils.toHex(publicKeyBytes));
                                } else {
                                    result.contentDigests.add(new ApkSigningBlockUtils.Result.SignerInfo.ContentDigest(0, signingInfo.apkDigest));
                                }
                            } catch (CertificateException e2) {
                                result.addError(ApkVerifier.Issue.V4_SIG_MALFORMED_CERTIFICATE, e2);
                            }
                        }
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException | SignatureException e3) {
                    result.addError(ApkVerifier.Issue.V4_SIG_VERIFY_EXCEPTION, signatureAlgorithm, e3);
                }
            } catch (Exception e4) {
                result.addError(ApkVerifier.Issue.V4_SIG_MALFORMED_PUBLIC_KEY, e4);
            }
        }
        return result;
    }

    private static void verifyRootHashAndTree(DataSource apkContent, ApkSigningBlockUtils.Result.SignerInfo signerInfo, byte[] expectedDigest, byte[] expectedTree) throws IOException, NoSuchAlgorithmException {
        ApkSigningBlockUtils.VerityTreeAndDigest actualContentDigestInfo = ApkSigningBlockUtils.computeChunkVerityTreeAndDigest(apkContent);
        ContentDigestAlgorithm algorithm = actualContentDigestInfo.contentDigestAlgorithm;
        byte[] actualDigest = actualContentDigestInfo.rootHash;
        byte[] actualTree = actualContentDigestInfo.tree;
        if (!Arrays.equals(expectedDigest, actualDigest)) {
            signerInfo.addError(ApkVerifier.Issue.V4_SIG_APK_ROOT_DID_NOT_VERIFY, algorithm, ApkSigningBlockUtils.toHex(expectedDigest), ApkSigningBlockUtils.toHex(actualDigest));
        } else if (expectedTree == null || Arrays.equals(expectedTree, actualTree)) {
            signerInfo.verifiedContentDigests.put(algorithm, actualDigest);
        } else {
            signerInfo.addError(ApkVerifier.Issue.V4_SIG_APK_TREE_DID_NOT_VERIFY, algorithm, ApkSigningBlockUtils.toHex(expectedDigest), ApkSigningBlockUtils.toHex(actualDigest));
        }
    }
}
