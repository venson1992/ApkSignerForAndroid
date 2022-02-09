package com.android.apksig.internal.apk.v2;

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

public abstract class V2SchemeSigner {
    public static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 1896449818;

    private V2SchemeSigner() {
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

    public static ApkSigningBlockUtils.SigningSchemeBlockAndDigests generateApkSignatureSchemeV2Block(RunnablesExecutor executor, DataSource beforeCentralDir, DataSource centralDir, DataSource eocd, List<ApkSigningBlockUtils.SignerConfig> signerConfigs, boolean v3SigningEnabled) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        Pair<List<ApkSigningBlockUtils.SignerConfig>, Map<ContentDigestAlgorithm, byte[]>> digestInfo = ApkSigningBlockUtils.computeContentDigests(executor, beforeCentralDir, centralDir, eocd, signerConfigs);
        return new ApkSigningBlockUtils.SigningSchemeBlockAndDigests(generateApkSignatureSchemeV2Block(digestInfo.getFirst(), digestInfo.getSecond(), v3SigningEnabled), digestInfo.getSecond());
    }

    private static Pair<byte[], Integer> generateApkSignatureSchemeV2Block(List<ApkSigningBlockUtils.SignerConfig> signerConfigs, Map<ContentDigestAlgorithm, byte[]> contentDigests, boolean v3SigningEnabled) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        List<byte[]> signerBlocks = new ArrayList<>(signerConfigs.size());
        int signerNumber = 0;
        for (ApkSigningBlockUtils.SignerConfig signerConfig : signerConfigs) {
            signerNumber++;
            try {
                signerBlocks.add(generateSignerBlock(signerConfig, contentDigests, v3SigningEnabled));
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException("Signer #" + signerNumber + " failed", e);
            } catch (SignatureException e2) {
                throw new SignatureException("Signer #" + signerNumber + " failed", e2);
            }
        }
        return Pair.of(ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(new byte[][]{ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signerBlocks)}), 1896449818);
    }

    private static byte[] generateSignerBlock(ApkSigningBlockUtils.SignerConfig signerConfig, Map<ContentDigestAlgorithm, byte[]> contentDigests, boolean v3SigningEnabled) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (signerConfig.certificates.isEmpty()) {
            throw new SignatureException("No certificates configured for signer");
        }
        byte[] encodedPublicKey = ApkSigningBlockUtils.encodePublicKey(signerConfig.certificates.get(0).getPublicKey());
        V2SignatureSchemeBlock.SignedData signedData = new V2SignatureSchemeBlock.SignedData();
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
            signedData.additionalAttributes = generateAdditionalAttributes(v3SigningEnabled);
            V2SignatureSchemeBlock.Signer signer = new V2SignatureSchemeBlock.Signer();
            signer.signedData = ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(new byte[][]{ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.digests), ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(signedData.certificates), signedData.additionalAttributes, new byte[0]});
            signer.publicKey = encodedPublicKey;
            signer.signatures = new ArrayList();
            signer.signatures = ApkSigningBlockUtils.generateSignaturesOverData(signerConfig, signer.signedData);
            return ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(new byte[][]{signer.signedData, ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signer.signatures), signer.publicKey});
        } catch (CertificateEncodingException e) {
            throw new SignatureException("Failed to encode certificates", e);
        }
    }

    private static byte[] generateAdditionalAttributes(boolean v3SigningEnabled) {
        if (!v3SigningEnabled) {
            return new byte[0];
        }
        ByteBuffer result = ByteBuffer.allocate(12);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(8);
        result.putInt(V2SchemeConstants.STRIPPING_PROTECTION_ATTR_ID);
        result.putInt(3);
        return result.array();
    }

    private static final class V2SignatureSchemeBlock {

        /* access modifiers changed from: private */
        public static final class Signer {
            public byte[] publicKey;
            public List<Pair<Integer, byte[]>> signatures;
            public byte[] signedData;

            private Signer() {
            }
        }

        private V2SignatureSchemeBlock() {
        }

        /* access modifiers changed from: private */
        public static final class SignedData {
            public byte[] additionalAttributes;
            public List<byte[]> certificates;
            public List<Pair<Integer, byte[]>> digests;

            private SignedData() {
            }
        }
    }
}
