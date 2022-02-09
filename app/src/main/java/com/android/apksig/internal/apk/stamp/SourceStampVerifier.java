package com.android.apksig.internal.apk.stamp;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.apk.ApkSignerInfo;
import com.android.apksig.internal.apk.ApkSigningBlockUtilsLite;
import com.android.apksig.internal.apk.ApkSupportedSignature;
import com.android.apksig.internal.apk.NoApkSupportedSignaturesException;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.stamp.SourceStampCertificateLineage;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import java.io.ByteArrayInputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* access modifiers changed from: package-private */
public class SourceStampVerifier {
    private SourceStampVerifier() {
    }

    public static void verifyV1SourceStamp(ByteBuffer sourceStampBlockData, CertificateFactory certFactory, ApkSignerInfo result, byte[] apkDigest, byte[] sourceStampCertificateDigest, int minSdkVersion, int maxSdkVersion) throws ApkFormatException, NoSuchAlgorithmException {
        X509Certificate sourceStampCertificate = verifySourceStampCertificate(sourceStampBlockData, certFactory, sourceStampCertificateDigest, result);
        if (!result.containsWarnings() && !result.containsErrors()) {
            verifySourceStampSignature(apkDigest, minSdkVersion, maxSdkVersion, sourceStampCertificate, ApkSigningBlockUtilsLite.getLengthPrefixedSlice(sourceStampBlockData), result);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:11:0x004a  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static void verifyV2SourceStamp(java.nio.ByteBuffer r18, java.security.cert.CertificateFactory r19, com.android.apksig.internal.apk.ApkSignerInfo r20, java.util.Map<java.lang.Integer, byte[]> r21, byte[] r22, int r23, int r24) throws com.android.apksig.apk.ApkFormatException, java.security.NoSuchAlgorithmException {
        /*
        // Method dump skipped, instructions count: 197
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.stamp.SourceStampVerifier.verifyV2SourceStamp(java.nio.ByteBuffer, java.security.cert.CertificateFactory, com.android.apksig.internal.apk.ApkSignerInfo, java.util.Map, byte[], int, int):void");
    }

    private static X509Certificate verifySourceStampCertificate(ByteBuffer sourceStampBlockData, CertificateFactory certFactory, byte[] sourceStampCertificateDigest, ApkSignerInfo result) throws NoSuchAlgorithmException, ApkFormatException {
        byte[] sourceStampEncodedCertificate = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(sourceStampBlockData);
        try {
            X509Certificate sourceStampCertificate = new GuaranteedEncodedFormX509Certificate((X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(sourceStampEncodedCertificate)), sourceStampEncodedCertificate);
            result.certs.add(sourceStampCertificate);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(sourceStampEncodedCertificate);
            byte[] sourceStampBlockCertificateDigest = messageDigest.digest();
            if (Arrays.equals(sourceStampCertificateDigest, sourceStampBlockCertificateDigest)) {
                return sourceStampCertificate;
            }
            result.addWarning(27, ApkSigningBlockUtilsLite.toHex(sourceStampBlockCertificateDigest), ApkSigningBlockUtilsLite.toHex(sourceStampCertificateDigest));
            return null;
        } catch (CertificateException e) {
            result.addWarning(18, e);
            return null;
        }
    }

    private static void verifySourceStampSignature(byte[] data, int minSdkVersion, int maxSdkVersion, X509Certificate sourceStampCertificate, ByteBuffer signatures, ApkSignerInfo result) {
        int signatureCount = 0;
        List<ApkSupportedSignature> supportedSignatures = new ArrayList<>(1);
        while (signatures.hasRemaining()) {
            signatureCount++;
            try {
                ByteBuffer signature = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signatures);
                int sigAlgorithmId = signature.getInt();
                byte[] sigBytes = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(signature);
                SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(sigAlgorithmId);
                if (signatureAlgorithm == null) {
                    result.addWarning(19, Integer.valueOf(sigAlgorithmId));
                } else {
                    supportedSignatures.add(new ApkSupportedSignature(signatureAlgorithm, sigBytes));
                }
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addWarning(20, Integer.valueOf(signatureCount));
                return;
            }
        }
        if (supportedSignatures.isEmpty()) {
            result.addWarning(17, new Object[0]);
            return;
        }
        try {
            for (ApkSupportedSignature signature2 : ApkSigningBlockUtilsLite.getSignaturesToVerify(supportedSignatures, minSdkVersion, maxSdkVersion, true)) {
                SignatureAlgorithm signatureAlgorithm2 = signature2.algorithm;
                String jcaSignatureAlgorithm = signatureAlgorithm2.getJcaSignatureAlgorithmAndParams().getFirst();
                AlgorithmParameterSpec jcaSignatureAlgorithmParams = (AlgorithmParameterSpec) signatureAlgorithm2.getJcaSignatureAlgorithmAndParams().getSecond();
                PublicKey publicKey = sourceStampCertificate.getPublicKey();
                try {
                    Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                    sig.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null) {
                        sig.setParameter(jcaSignatureAlgorithmParams);
                    }
                    sig.update(data);
                    if (!sig.verify(signature2.signature)) {
                        result.addWarning(21, signatureAlgorithm2);
                        return;
                    }
                } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e2) {
                    result.addWarning(22, signatureAlgorithm2, e2);
                    return;
                }
            }
        } catch (NoApkSupportedSignaturesException e3) {
            StringBuilder signatureAlgorithms = new StringBuilder();
            for (ApkSupportedSignature supportedSignature : supportedSignatures) {
                if (signatureAlgorithms.length() > 0) {
                    signatureAlgorithms.append(", ");
                }
                signatureAlgorithms.append(supportedSignature.algorithm);
            }
            result.addWarning(26, signatureAlgorithms.toString(), e3);
        }
    }

    private static void parseStampAttributes(ByteBuffer stampAttributeData, X509Certificate sourceStampCertificate, ApkSignerInfo result) throws ApkFormatException {
        ByteBuffer stampAttributes = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(stampAttributeData);
        int stampAttributeCount = 0;
        while (stampAttributes.hasRemaining()) {
            stampAttributeCount++;
            try {
                ByteBuffer attribute = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(stampAttributes);
                int id = attribute.getInt();
                byte[] value = ByteBufferUtils.toByteArray(attribute);
                if (id == -1654455305) {
                    readStampCertificateLineage(value, sourceStampCertificate, result);
                } else {
                    result.addWarning(32, Integer.valueOf(id));
                }
            } catch (ApkFormatException | BufferUnderflowException e) {
                result.addWarning(31, Integer.valueOf(stampAttributeCount));
                return;
            }
        }
    }

    private static void readStampCertificateLineage(byte[] lineageBytes, X509Certificate sourceStampCertificate, ApkSignerInfo result) {
        try {
            List<SourceStampCertificateLineage.SigningCertificateNode> nodes = SourceStampCertificateLineage.readSigningCertificateLineage(ByteBuffer.wrap(lineageBytes).order(ByteOrder.LITTLE_ENDIAN));
            for (int i = 0; i < nodes.size(); i++) {
                result.certificateLineage.add(nodes.get(i).signingCert);
            }
            if (!sourceStampCertificate.equals(result.certificateLineage.get(result.certificateLineage.size() - 1))) {
                result.addWarning(34, new Object[0]);
            }
        } catch (SecurityException e) {
            result.addWarning(35, new Object[0]);
        } catch (IllegalArgumentException e2) {
            result.addWarning(34, new Object[0]);
        } catch (Exception e3) {
            result.addWarning(33, new Object[0]);
        }
    }
}
