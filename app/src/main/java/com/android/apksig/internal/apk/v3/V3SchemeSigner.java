package com.android.apksig.internal.apk.v3;

import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public abstract class V3SchemeSigner {
    public static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = -262969152;
    public static final int PROOF_OF_ROTATION_ATTR_ID = 1000370060;

    private V3SchemeSigner() {
    }

    public static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey, int minSdkVersion, boolean verityEnabled) throws InvalidKeyException {
        String keyAlgorithm = signingKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            if (((RSAKey) signingKey).getModulus().bitLength() > 3072) {
                return Collections.singletonList(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512);
            }
            List<SignatureAlgorithm> algorithms = new ArrayList<>();
            algorithms.add(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256);
            if (!verityEnabled) {
                return algorithms;
            }
            algorithms.add(SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256);
            return algorithms;
        } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            List<SignatureAlgorithm> algorithms2 = new ArrayList<>();
            algorithms2.add(SignatureAlgorithm.DSA_WITH_SHA256);
            if (!verityEnabled) {
                return algorithms2;
            }
            algorithms2.add(SignatureAlgorithm.VERITY_DSA_WITH_SHA256);
            return algorithms2;
        } else if (!"EC".equalsIgnoreCase(keyAlgorithm)) {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        } else if (((ECKey) signingKey).getParams().getOrder().bitLength() > 256) {
            return Collections.singletonList(SignatureAlgorithm.ECDSA_WITH_SHA512);
        } else {
            List<SignatureAlgorithm> algorithms3 = new ArrayList<>();
            algorithms3.add(SignatureAlgorithm.ECDSA_WITH_SHA256);
            if (!verityEnabled) {
                return algorithms3;
            }
            algorithms3.add(SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256);
            return algorithms3;
        }
    }

    public static ApkSigningBlockUtils.SigningSchemeBlockAndDigests generateApkSignatureSchemeV3Block(RunnablesExecutor executor, DataSource beforeCentralDir, DataSource centralDir, DataSource eocd, List<ApkSigningBlockUtils.SignerConfig> signerConfigs) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Pair<List<ApkSigningBlockUtils.SignerConfig>, Map<ContentDigestAlgorithm, byte[]>> digestInfo = ApkSigningBlockUtils.computeContentDigests(executor, beforeCentralDir, centralDir, eocd, signerConfigs);
        return new ApkSigningBlockUtils.SigningSchemeBlockAndDigests(generateApkSignatureSchemeV3Block(digestInfo.getFirst(), digestInfo.getSecond()), digestInfo.getSecond());
    }

    public static byte[] generateV3SignerAttribute(SigningCertificateLineage signingCertificateLineage) {
        byte[] encodedLineage = signingCertificateLineage.encodeSigningCertificateLineage();
        ByteBuffer result = ByteBuffer.allocate(encodedLineage.length + 8);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(encodedLineage.length + 4);
        result.putInt(1000370060);
        result.put(encodedLineage);
        return result.array();
    }

    private static Pair<byte[], Integer> generateApkSignatureSchemeV3Block(List<ApkSigningBlockUtils.SignerConfig> signerConfigs, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        List<byte[]> signerBlocks = new ArrayList<>(signerConfigs.size());
        int signerNumber = 0;
        for (ApkSigningBlockUtils.SignerConfig signerConfig : signerConfigs) {
            signerNumber++;
            try {
                signerBlocks.add(generateSignerBlock(signerConfig, contentDigests));
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException("Signer #" + signerNumber + " failed", e);
            } catch (SignatureException e2) {
                throw new SignatureException("Signer #" + signerNumber + " failed", e2);
            }
        }
        return Pair.of(ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(new byte[][]{ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signerBlocks)}), -262969152);
    }

    private static byte[] generateSignerBlock(ApkSigningBlockUtils.SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (signerConfig.certificates.isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }
        byte[] encodedPublicKey = ApkSigningBlockUtils.encodePublicKey(signerConfig.certificates.get(0).getPublicKey());
        V3SignatureSchemeBlock.SignedData signedData = new V3SignatureSchemeBlock.SignedData();
        try {
            signedData.certificates = ApkSigningBlockUtils.encodeCertificates(signerConfig.certificates);
            List<Pair<Integer, byte[]>> digests = new ArrayList<>(signerConfig.signatureAlgorithms.size());
            for (SignatureAlgorithm signatureAlgorithm : signerConfig.signatureAlgorithms) {
                ContentDigestAlgorithm contentDigestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
                byte[] contentDigest = contentDigests.get(contentDigestAlgorithm);
                if (contentDigest == null) {
                    throw new RuntimeException(contentDigestAlgorithm + " content digest for " + signatureAlgorithm + " not computed");
                }
                digests.add(Pair.of(Integer.valueOf(signatureAlgorithm.getId()), contentDigest));
            }
            signedData.digests = digests;
            signedData.minSdkVersion = signerConfig.minSdkVersion;
            signedData.maxSdkVersion = signerConfig.maxSdkVersion;
            signedData.additionalAttributes = generateAdditionalAttributes(signerConfig);
            V3SignatureSchemeBlock.Signer signer = new V3SignatureSchemeBlock.Signer();
            signer.signedData = encodeSignedData(signedData);
            signer.minSdkVersion = signerConfig.minSdkVersion;
            signer.maxSdkVersion = signerConfig.maxSdkVersion;
            signer.publicKey = encodedPublicKey;
            signer.signatures = ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, signer.signedData);
            return encodeSigner(signer);
        } catch (CertificateEncodingException e) {
            throw new SignatureException("Failed to encode certificates", e);
        }
    }

    private static byte[] encodeSigner(V3SignatureSchemeBlock.Signer signer) {
        byte[] signedData = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signer.signedData);
        byte[] signatures = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signer.signatures));
        byte[] publicKey = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signer.publicKey);
        ByteBuffer result = ByteBuffer.allocate(signedData.length + 4 + 4 + signatures.length + publicKey.length);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.put(signedData);
        result.putInt(signer.minSdkVersion);
        result.putInt(signer.maxSdkVersion);
        result.put(signatures);
        result.put(publicKey);
        return result.array();
    }

    private static byte[] encodeSignedData(V3SignatureSchemeBlock.SignedData signedData) {
        byte[] digests = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.digests));
        byte[] certs = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signedData.certificates));
        byte[] attributes = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(signedData.additionalAttributes);
        ByteBuffer result = ByteBuffer.allocate(digests.length + certs.length + 4 + 4 + attributes.length);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.put(digests);
        result.put(certs);
        result.putInt(signedData.minSdkVersion);
        result.putInt(signedData.maxSdkVersion);
        result.put(attributes);
        return result.array();
    }

    private static byte[] generateAdditionalAttributes(ApkSigningBlockUtils.SignerConfig signerConfig) {
        if (signerConfig.mSigningCertificateLineage == null) {
            return new byte[0];
        }
        return generateV3SignerAttribute(signerConfig.mSigningCertificateLineage);
    }

    private static final class V3SignatureSchemeBlock {

        /* access modifiers changed from: private */
        public static final class Signer {
            public int maxSdkVersion;
            public int minSdkVersion;
            public byte[] publicKey;
            public List<Pair<Integer, byte[]>> signatures;
            public byte[] signedData;

            private Signer() {
            }
        }

        private V3SignatureSchemeBlock() {
        }

        /* access modifiers changed from: private */
        public static final class SignedData {
            public byte[] additionalAttributes;
            public List<byte[]> certificates;
            public List<Pair<Integer, byte[]>> digests;
            public int maxSdkVersion;
            public int minSdkVersion;

            private SignedData() {
            }
        }
    }
}
