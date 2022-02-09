package com.android.apksig.internal.apk.v3;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import com.android.apksig.internal.util.X509CertificateUtils;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class V3SigningCertificateLineage {
    private static final int CURRENT_VERSION = 1;
    private static final int FIRST_VERSION = 1;

    public static List<SigningCertificateNode> readSigningCertificateLineage(ByteBuffer inputBytes) throws IOException {
        CertificateException e;
        GeneralSecurityException e2;
        Exception e3;
        List<SigningCertificateNode> result = new ArrayList<>();
        int nodeCount = 0;
        if (inputBytes == null || !inputBytes.hasRemaining()) {
            return null;
        }
        ApkSigningBlockUtils.checkByteOrderLittleEndian(inputBytes);
        X509Certificate lastCert = null;
        int lastSigAlgorithmId = 0;
        try {
            if (inputBytes.getInt() != 1) {
                throw new IllegalArgumentException("Encoded SigningCertificateLineage has a version different than any of which we are aware");
            }
            HashSet<X509Certificate> certHistorySet = new HashSet<>();
            while (inputBytes.hasRemaining()) {
                nodeCount++;
                ByteBuffer nodeBytes = ApkSigningBlockUtils.getLengthPrefixedSlice(inputBytes);
                ByteBuffer signedData = ApkSigningBlockUtils.getLengthPrefixedSlice(nodeBytes);
                int flags = nodeBytes.getInt();
                int sigAlgorithmId = nodeBytes.getInt();
                SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(lastSigAlgorithmId);
                byte[] signature = ApkSigningBlockUtils.readLengthPrefixedByteArray(nodeBytes);
                if (lastCert != null) {
                    String jcaSignatureAlgorithm = sigAlgorithm.getJcaSignatureAlgorithmAndParams().getFirst();
                    AlgorithmParameterSpec jcaSignatureAlgorithmParams = (AlgorithmParameterSpec) sigAlgorithm.getJcaSignatureAlgorithmAndParams().getSecond();
                    PublicKey publicKey = lastCert.getPublicKey();
                    Signature sig = Signature.getInstance(jcaSignatureAlgorithm);
                    sig.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null) {
                        sig.setParameter(jcaSignatureAlgorithmParams);
                    }
                    sig.update(signedData);
                    if (!sig.verify(signature)) {
                        throw new SecurityException("Unable to verify signature of certificate #" + nodeCount + " using " + jcaSignatureAlgorithm + " when verifying V3SigningCertificateLineage object");
                    }
                }
                signedData.rewind();
                byte[] encodedCert = ApkSigningBlockUtils.readLengthPrefixedByteArray(signedData);
                int signedSigAlgorithm = signedData.getInt();
                if (lastCert == null || lastSigAlgorithmId == signedSigAlgorithm) {
                    try {
                        lastCert = new GuaranteedEncodedFormX509Certificate(X509CertificateUtils.generateCertificate(encodedCert), encodedCert);
                        if (certHistorySet.contains(lastCert)) {
                            throw new SecurityException("Encountered duplicate entries in SigningCertificateLineage at certificate #" + nodeCount + ".  All signing certificates should be unique");
                        }
                        certHistorySet.add(lastCert);
                        lastSigAlgorithmId = sigAlgorithmId;
                        result.add(new SigningCertificateNode(lastCert, SignatureAlgorithm.findById(signedSigAlgorithm), SignatureAlgorithm.findById(sigAlgorithmId), signature, flags));
                    } catch (ApkFormatException e4) {
                        e3 = e4;
                        throw new IOException("Failed to parse V3SigningCertificateLineage object", e3);
                    } catch (BufferUnderflowException e5) {
                        e3 = e5;
                        throw new IOException("Failed to parse V3SigningCertificateLineage object", e3);
                    } catch (NoSuchAlgorithmException e6) {
                        e2 = e6;
                        throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e2);
                    } catch (InvalidKeyException e7) {
                        e2 = e7;
                        throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e2);
                    } catch (InvalidAlgorithmParameterException e8) {
                        e2 = e8;
                        throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e2);
                    } catch (SignatureException e9) {
                        e2 = e9;
                        throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e2);
                    } catch (CertificateException e10) {
                        e = e10;
                        throw new SecurityException("Failed to decode certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e);
                    }
                } else {
                    throw new SecurityException("Signing algorithm ID mismatch for certificate #" + nodeBytes + " when verifying V3SigningCertificateLineage object");
                }
            }
            return result;
        } catch (ApkFormatException | BufferUnderflowException e11) {
            e3 = e11;
            throw new IOException("Failed to parse V3SigningCertificateLineage object", e3);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e12) {
            e2 = e12;
            throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e2);
        } catch (CertificateException e13) {
            e = e13;
            throw new SecurityException("Failed to decode certificate #" + nodeCount + " when parsing V3SigningCertificateLineage object", e);
        }
    }

    public static byte[] encodeSigningCertificateLineage(List<SigningCertificateNode> signingCertificateLineage) {
        List<byte[]> nodes = new ArrayList<>();
        for (SigningCertificateNode node : signingCertificateLineage) {
            nodes.add(encodeSigningCertificateNode(node));
        }
        byte[] encodedSigningCertificateLineage = ApkSigningBlockUtils.encodeAsSequenceOfLengthPrefixedElements(nodes);
        ByteBuffer encodedWithVersion = ByteBuffer.allocate(encodedSigningCertificateLineage.length + 4);
        encodedWithVersion.order(ByteOrder.LITTLE_ENDIAN);
        encodedWithVersion.putInt(1);
        encodedWithVersion.put(encodedSigningCertificateLineage);
        return encodedWithVersion.array();
    }

    public static byte[] encodeSigningCertificateNode(SigningCertificateNode node) {
        int parentSigAlgorithmId = 0;
        if (node.parentSigAlgorithm != null) {
            parentSigAlgorithmId = node.parentSigAlgorithm.getId();
        }
        int sigAlgorithmId = 0;
        if (node.sigAlgorithm != null) {
            sigAlgorithmId = node.sigAlgorithm.getId();
        }
        byte[] prefixedSignedData = encodeSignedData(node.signingCert, parentSigAlgorithmId);
        byte[] prefixedSignature = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(node.signature);
        ByteBuffer result = ByteBuffer.allocate(prefixedSignedData.length + 4 + 4 + prefixedSignature.length);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.put(prefixedSignedData);
        result.putInt(node.flags);
        result.putInt(sigAlgorithmId);
        result.put(prefixedSignature);
        return result.array();
    }

    public static byte[] encodeSignedData(X509Certificate certificate, int flags) {
        try {
            byte[] prefixedCertificate = ApkSigningBlockUtils.encodeAsLengthPrefixedElement(certificate.getEncoded());
            ByteBuffer result = ByteBuffer.allocate(prefixedCertificate.length + 4);
            result.order(ByteOrder.LITTLE_ENDIAN);
            result.put(prefixedCertificate);
            result.putInt(flags);
            return ApkSigningBlockUtils.encodeAsLengthPrefixedElement(result.array());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode V3SigningCertificateLineage certificate", e);
        }
    }

    public static class SigningCertificateNode {
        public int flags;
        public final SignatureAlgorithm parentSigAlgorithm;
        public SignatureAlgorithm sigAlgorithm;
        public final byte[] signature;
        public final X509Certificate signingCert;

        public SigningCertificateNode(X509Certificate signingCert2, SignatureAlgorithm parentSigAlgorithm2, SignatureAlgorithm sigAlgorithm2, byte[] signature2, int flags2) {
            this.signingCert = signingCert2;
            this.parentSigAlgorithm = parentSigAlgorithm2;
            this.sigAlgorithm = sigAlgorithm2;
            this.signature = signature2;
            this.flags = flags2;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof SigningCertificateNode)) {
                return false;
            }
            SigningCertificateNode that = (SigningCertificateNode) o;
            if (!this.signingCert.equals(that.signingCert)) {
                return false;
            }
            if (this.parentSigAlgorithm != that.parentSigAlgorithm) {
                return false;
            }
            if (this.sigAlgorithm != that.sigAlgorithm) {
                return false;
            }
            if (!Arrays.equals(this.signature, that.signature)) {
                return false;
            }
            return this.flags == that.flags;
        }
    }
}
