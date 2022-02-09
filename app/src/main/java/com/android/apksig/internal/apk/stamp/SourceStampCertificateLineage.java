package com.android.apksig.internal.apk.stamp;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.apk.ApkSigningBlockUtilsLite;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.util.GuaranteedEncodedFormX509Certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
import java.util.HashSet;
import java.util.List;

public class SourceStampCertificateLineage {
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
        ApkSigningBlockUtilsLite.checkByteOrderLittleEndian(inputBytes);
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate lastCert = null;
            int lastSigAlgorithmId = 0;
            try {
                if (inputBytes.getInt() != 1) {
                    throw new IllegalArgumentException("Encoded SigningCertificateLineage has a version different than any of which we are aware");
                }
                HashSet<X509Certificate> certHistorySet = new HashSet<>();
                while (inputBytes.hasRemaining()) {
                    nodeCount++;
                    ByteBuffer nodeBytes = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(inputBytes);
                    ByteBuffer signedData = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(nodeBytes);
                    int flags = nodeBytes.getInt();
                    int sigAlgorithmId = nodeBytes.getInt();
                    SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(lastSigAlgorithmId);
                    byte[] signature = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(nodeBytes);
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
                            throw new SecurityException("Unable to verify signature of certificate #" + nodeCount + " using " + jcaSignatureAlgorithm + " when verifying SourceStampCertificateLineage object");
                        }
                    }
                    signedData.rewind();
                    byte[] encodedCert = ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(signedData);
                    int signedSigAlgorithm = signedData.getInt();
                    if (lastCert == null || lastSigAlgorithmId == signedSigAlgorithm) {
                        try {
                            lastCert = new GuaranteedEncodedFormX509Certificate((X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(encodedCert)), encodedCert);
                            if (certHistorySet.contains(lastCert)) {
                                throw new SecurityException("Encountered duplicate entries in SigningCertificateLineage at certificate #" + nodeCount + ".  All signing certificates should be unique");
                            }
                            certHistorySet.add(lastCert);
                            lastSigAlgorithmId = sigAlgorithmId;
                            result.add(new SigningCertificateNode(lastCert, SignatureAlgorithm.findById(signedSigAlgorithm), SignatureAlgorithm.findById(sigAlgorithmId), signature, flags));
                        } catch (ApkFormatException e4) {
                            e3 = e4;
                            throw new IOException("Failed to parse SourceStampCertificateLineage object", e3);
                        } catch (BufferUnderflowException e5) {
                            e3 = e5;
                            throw new IOException("Failed to parse SourceStampCertificateLineage object", e3);
                        } catch (NoSuchAlgorithmException e6) {
                            e2 = e6;
                            throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e2);
                        } catch (InvalidKeyException e7) {
                            e2 = e7;
                            throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e2);
                        } catch (InvalidAlgorithmParameterException e8) {
                            e2 = e8;
                            throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e2);
                        } catch (SignatureException e9) {
                            e2 = e9;
                            throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e2);
                        } catch (CertificateException e10) {
                            e = e10;
                            throw new SecurityException("Failed to decode certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e);
                        }
                    } else {
                        throw new SecurityException("Signing algorithm ID mismatch for certificate #" + nodeBytes + " when verifying SourceStampCertificateLineage object");
                    }
                }
                return result;
            } catch (ApkFormatException | BufferUnderflowException e11) {
                e3 = e11;
                throw new IOException("Failed to parse SourceStampCertificateLineage object", e3);
            } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e12) {
                e2 = e12;
                throw new SecurityException("Failed to verify signature over signed data for certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e2);
            } catch (CertificateException e13) {
                e = e13;
                throw new SecurityException("Failed to decode certificate #" + nodeCount + " when parsing SourceStampCertificateLineage object", e);
            }
        } catch (CertificateException e14) {
            throw new IllegalStateException("Failed to obtain X.509 CertificateFactory", e14);
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

        public int hashCode() {
            int i = 0;
            int hashCode = ((((this.signingCert == null ? 0 : this.signingCert.hashCode()) + 31) * 31) + (this.parentSigAlgorithm == null ? 0 : this.parentSigAlgorithm.hashCode())) * 31;
            if (this.sigAlgorithm != null) {
                i = this.sigAlgorithm.hashCode();
            }
            return ((((hashCode + i) * 31) + Arrays.hashCode(this.signature)) * 31) + this.flags;
        }
    }
}
