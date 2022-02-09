package com.android.apksig;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtilsLite;
import com.android.apksig.internal.apk.ApkSigResult;
import com.android.apksig.internal.apk.ApkSignerInfo;
import com.android.apksig.internal.apk.ApkSigningBlockUtilsLite;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipFormatException;
import com.android.apksig.zip.ZipSections;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SourceStampVerifier {
    private final DataSource mApkDataSource;
    private final File mApkFile;
    private final int mMaxSdkVersion;
    private final int mMinSdkVersion;

    private SourceStampVerifier(File apkFile, DataSource apkDataSource, int minSdkVersion, int maxSdkVersion) {
        this.mApkFile = apkFile;
        this.mApkDataSource = apkDataSource;
        this.mMinSdkVersion = minSdkVersion;
        this.mMaxSdkVersion = maxSdkVersion;
    }

    public Result verifySourceStamp() {
        return verifySourceStamp(null);
    }

    public Result verifySourceStamp(String expectedCertDigest) {
        Result result;
        DataSource apk;
        Closeable in = null;
        try {
            if (this.mApkDataSource != null) {
                apk = this.mApkDataSource;
            } else if (this.mApkFile != null) {
                RandomAccessFile f = new RandomAccessFile(this.mApkFile, "r");
                in = f;
                apk = DataSources.asDataSource(f, 0, f.length());
            } else {
                throw new IllegalStateException("APK not provided");
            }
            result = verifySourceStamp(apk, expectedCertDigest);
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
        } catch (IOException e2) {
            result = new Result();
            result.addVerificationError(29, e2);
            if (0 != 0) {
                try {
                    in.close();
                } catch (IOException e3) {
                }
            }
        } catch (Throwable th) {
            if (0 != 0) {
                try {
                    in.close();
                } catch (IOException e4) {
                }
            }
            throw th;
        }
        return result;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0045, code lost:
        r17 = false;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0072, code lost:
        r12 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0073, code lost:
        r13.addVerificationError(28, r12);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:52:0x0117, code lost:
        r14 = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:54:0x011b, code lost:
        r14 = null;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:55:0x011d, code lost:
        r12 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:56:0x011e, code lost:
        r13.addVerificationError(29, r12);
     */
    /* JADX WARNING: Failed to process nested try/catch */
    /* JADX WARNING: Removed duplicated region for block: B:25:0x0072 A[ExcHandler: ApkFormatException | ZipFormatException | IOException (r12v2 'e' java.lang.Exception A[CUSTOM_DECLARE]), Splitter:B:1:0x0005] */
    /* JADX WARNING: Removed duplicated region for block: B:55:0x011d A[ExcHandler: NoSuchAlgorithmException (r12v1 'e' java.security.NoSuchAlgorithmException A[CUSTOM_DECLARE]), Splitter:B:1:0x0005] */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private com.android.apksig.SourceStampVerifier.Result verifySourceStamp(com.android.apksig.util.DataSource r19, java.lang.String r20) {
        /*
        // Method dump skipped, instructions count: 313
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.SourceStampVerifier.verifySourceStamp(com.android.apksig.util.DataSource, java.lang.String):com.android.apksig.SourceStampVerifier$Result");
    }

    public static void parseSigners(ByteBuffer apkSignatureSchemeBlock, int apkSigSchemeVersion, Map<ContentDigestAlgorithm, byte[]> apkContentDigests, Result result) {
        boolean isV2Block;
        Result.SignerInfo signerInfo;
        int i;
        int i2;
        int i3 = 1;
        if (apkSigSchemeVersion == 2) {
            isV2Block = true;
        } else {
            isV2Block = false;
        }
        try {
            ByteBuffer signers = ApkSigningBlockUtilsLite.getLengthPrefixedSlice(apkSignatureSchemeBlock);
            if (!signers.hasRemaining()) {
                if (isV2Block) {
                    i2 = 2;
                } else {
                    i2 = 10;
                }
                result.addVerificationWarning(i2, new Object[0]);
                return;
            }
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                while (signers.hasRemaining()) {
                    signerInfo = new Result.SignerInfo();
                    if (isV2Block) {
                        result.addV2Signer(signerInfo);
                    } else {
                        result.addV3Signer(signerInfo);
                    }
                    try {
                        parseSigner(ApkSigningBlockUtilsLite.getLengthPrefixedSlice(signers), apkSigSchemeVersion, certFactory, apkContentDigests, signerInfo);
                    } catch (ApkFormatException e) {
                    } catch (BufferUnderflowException e2) {
                    }
                }
                return;
            } catch (CertificateException e3) {
                throw new RuntimeException("Failed to obtain X.509 CertificateFactory", e3);
            }
            if (isV2Block) {
                i = 3;
            } else {
                i = 11;
            }
            signerInfo.addVerificationWarning(i, new Object[0]);
        } catch (ApkFormatException e4) {
            if (!isV2Block) {
                i3 = 9;
            }
            result.addVerificationWarning(i3, new Object[0]);
        }
    }

    /* JADX WARNING: Removed duplicated region for block: B:13:0x0038  */
    /* JADX WARNING: Removed duplicated region for block: B:16:0x0045  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static void parseSigner(java.nio.ByteBuffer r15, int r16, java.security.cert.CertificateFactory r17, java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]> r18, com.android.apksig.SourceStampVerifier.Result.SignerInfo r19) throws com.android.apksig.apk.ApkFormatException {
        /*
        // Method dump skipped, instructions count: 145
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.SourceStampVerifier.parseSigner(java.nio.ByteBuffer, int, java.security.cert.CertificateFactory, java.util.Map, com.android.apksig.SourceStampVerifier$Result$SignerInfo):void");
    }

    private static Map<ContentDigestAlgorithm, byte[]> getApkContentDigestFromV1SigningScheme(List<CentralDirectoryRecord> cdRecords, DataSource apk, ZipSections zipSections, Result result) throws IOException, ApkFormatException {
        CentralDirectoryRecord manifestCdRecord = null;
        List<CentralDirectoryRecord> signatureBlockRecords = new ArrayList<>(1);
        Map<ContentDigestAlgorithm, byte[]> v1ContentDigest = new EnumMap<>(ContentDigestAlgorithm.class);
        for (CentralDirectoryRecord cdRecord : cdRecords) {
            String cdRecordName = cdRecord.getName();
            if (cdRecordName != null) {
                if (manifestCdRecord == null && "META-INF/MANIFEST.MF".equals(cdRecordName)) {
                    manifestCdRecord = cdRecord;
                } else if (cdRecordName.startsWith("META-INF/") && (cdRecordName.endsWith(".RSA") || cdRecordName.endsWith(".DSA") || cdRecordName.endsWith(".EC"))) {
                    signatureBlockRecords.add(cdRecord);
                }
            }
        }
        if (manifestCdRecord != null) {
            if (signatureBlockRecords.isEmpty()) {
                result.addVerificationWarning(36, new Object[0]);
            } else {
                for (CentralDirectoryRecord signatureBlockRecord : signatureBlockRecords) {
                    try {
                        Iterator<? extends Certificate> it = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(LocalFileRecord.getUncompressedData(apk, signatureBlockRecord, zipSections.getZipCentralDirectoryOffset()))).iterator();
                        while (true) {
                            if (!it.hasNext()) {
                                break;
                            }
                            Certificate certificate = (Certificate) it.next();
                            if (certificate instanceof X509Certificate) {
                                Result.SignerInfo signerInfo = new Result.SignerInfo();
                                signerInfo.setSigningCertificate((X509Certificate) certificate);
                                result.addV1Signer(signerInfo);
                                break;
                            }
                        }
                    } catch (CertificateException e) {
                        result.addVerificationWarning(37, signatureBlockRecord.getName(), e);
                    } catch (ZipFormatException e2) {
                        throw new ApkFormatException("Failed to read APK", e2);
                    }
                }
            }
            try {
                v1ContentDigest.put(ContentDigestAlgorithm.SHA256, ApkUtilsLite.computeSha256DigestBytes(LocalFileRecord.getUncompressedData(apk, manifestCdRecord, zipSections.getZipCentralDirectoryOffset())));
            } catch (ZipFormatException e3) {
                throw new ApkFormatException("Failed to read APK", e3);
            }
        }
        return v1ContentDigest;
    }

    public static class Result {
        private final List<List<SignerInfo>> mAllSchemeSigners = Arrays.asList(this.mV1SchemeSigners, this.mV2SchemeSigners, this.mV3SchemeSigners);
        private final List<ApkVerificationIssue> mErrors = new ArrayList();
        private SourceStampInfo mSourceStampInfo;
        private final List<SignerInfo> mV1SchemeSigners = new ArrayList();
        private final List<SignerInfo> mV2SchemeSigners = new ArrayList();
        private final List<SignerInfo> mV3SchemeSigners = new ArrayList();
        private boolean mVerified;
        private final List<ApkVerificationIssue> mWarnings = new ArrayList();

        /* access modifiers changed from: package-private */
        public void addVerificationError(int errorId, Object... params) {
            this.mErrors.add(new ApkVerificationIssue(errorId, params));
        }

        /* access modifiers changed from: package-private */
        public void addVerificationWarning(int warningId, Object... params) {
            this.mWarnings.add(new ApkVerificationIssue(warningId, params));
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addV1Signer(SignerInfo signerInfo) {
            this.mV1SchemeSigners.add(signerInfo);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addV2Signer(SignerInfo signerInfo) {
            this.mV2SchemeSigners.add(signerInfo);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addV3Signer(SignerInfo signerInfo) {
            this.mV3SchemeSigners.add(signerInfo);
        }

        public boolean isVerified() {
            return this.mVerified;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void mergeFrom(ApkSigResult source) {
            switch (source.signatureSchemeVersion) {
                case BerEncoding.TAG_CLASS_UNIVERSAL /*{ENCODED_INT: 0}*/:
                    this.mVerified = source.verified;
                    if (!source.mSigners.isEmpty()) {
                        this.mSourceStampInfo = new SourceStampInfo(source.mSigners.get(0));
                        return;
                    }
                    return;
                default:
                    throw new IllegalArgumentException("Unknown ApkSigResult Signing Block Scheme Id " + source.signatureSchemeVersion);
            }
        }

        public List<SignerInfo> getV1SchemeSigners() {
            return this.mV1SchemeSigners;
        }

        public List<SignerInfo> getV2SchemeSigners() {
            return this.mV2SchemeSigners;
        }

        public List<SignerInfo> getV3SchemeSigners() {
            return this.mV3SchemeSigners;
        }

        public SourceStampInfo getSourceStampInfo() {
            return this.mSourceStampInfo;
        }

        public boolean containsErrors() {
            if (!this.mErrors.isEmpty()) {
                return true;
            }
            for (List<SignerInfo> signers : this.mAllSchemeSigners) {
                Iterator<SignerInfo> it = signers.iterator();
                while (true) {
                    if (it.hasNext()) {
                        if (it.next().containsErrors()) {
                            return true;
                        }
                    }
                }
            }
            if (this.mSourceStampInfo == null || !this.mSourceStampInfo.containsErrors()) {
                return false;
            }
            return true;
        }

        public List<ApkVerificationIssue> getErrors() {
            return this.mErrors;
        }

        public List<ApkVerificationIssue> getWarnings() {
            return this.mWarnings;
        }

        public List<ApkVerificationIssue> getAllErrors() {
            List<ApkVerificationIssue> errors = new ArrayList<>();
            errors.addAll(this.mErrors);
            for (List<SignerInfo> signers : this.mAllSchemeSigners) {
                for (SignerInfo signer : signers) {
                    errors.addAll(signer.getErrors());
                }
            }
            if (this.mSourceStampInfo != null) {
                errors.addAll(this.mSourceStampInfo.getErrors());
            }
            return errors;
        }

        public List<ApkVerificationIssue> getAllWarnings() {
            List<ApkVerificationIssue> warnings = new ArrayList<>();
            warnings.addAll(this.mWarnings);
            for (List<SignerInfo> signers : this.mAllSchemeSigners) {
                for (SignerInfo signer : signers) {
                    warnings.addAll(signer.getWarnings());
                }
            }
            if (this.mSourceStampInfo != null) {
                warnings.addAll(this.mSourceStampInfo.getWarnings());
            }
            return warnings;
        }

        public static class SignerInfo {
            private final List<ApkVerificationIssue> mErrors = new ArrayList();
            private X509Certificate mSigningCertificate;
            private final List<ApkVerificationIssue> mWarnings = new ArrayList();

            /* access modifiers changed from: package-private */
            public void setSigningCertificate(X509Certificate signingCertificate) {
                this.mSigningCertificate = signingCertificate;
            }

            /* access modifiers changed from: package-private */
            public void addVerificationError(int errorId, Object... params) {
                this.mErrors.add(new ApkVerificationIssue(errorId, params));
            }

            /* access modifiers changed from: package-private */
            public void addVerificationWarning(int warningId, Object... params) {
                this.mWarnings.add(new ApkVerificationIssue(warningId, params));
            }

            public X509Certificate getSigningCertificate() {
                return this.mSigningCertificate;
            }

            public List<ApkVerificationIssue> getErrors() {
                return this.mErrors;
            }

            public List<ApkVerificationIssue> getWarnings() {
                return this.mWarnings;
            }

            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }
        }

        public static class SourceStampInfo {
            private static final boolean mWarningsAsErrors = true;
            private final List<X509Certificate> mCertificateLineage;
            private final List<X509Certificate> mCertificates;
            private final List<ApkVerificationIssue> mErrors;
            private final List<ApkVerificationIssue> mWarnings;

            private SourceStampInfo(ApkSignerInfo result) {
                this.mErrors = new ArrayList();
                this.mWarnings = new ArrayList();
                this.mCertificates = result.certs;
                this.mCertificateLineage = result.certificateLineage;
                this.mErrors.addAll(result.getErrors());
                this.mWarnings.addAll(result.getWarnings());
            }

            public X509Certificate getCertificate() {
                if (this.mCertificates.isEmpty()) {
                    return null;
                }
                return this.mCertificates.get(0);
            }

            public List<X509Certificate> getCertificatesInLineage() {
                return this.mCertificateLineage;
            }

            public boolean containsErrors() {
                if (!this.mErrors.isEmpty() || !this.mWarnings.isEmpty()) {
                    return mWarningsAsErrors;
                }
                return false;
            }

            public List<ApkVerificationIssue> getErrors() {
                List<ApkVerificationIssue> result = new ArrayList<>();
                result.addAll(this.mErrors);
                result.addAll(this.mWarnings);
                return result;
            }

            public List<ApkVerificationIssue> getWarnings() {
                return this.mWarnings;
            }
        }
    }

    public static class Builder {
        private final DataSource mApkDataSource;
        private final File mApkFile;
        private int mMaxSdkVersion = Integer.MAX_VALUE;
        private int mMinSdkVersion = 1;

        public Builder(File apk) {
            if (apk == null) {
                throw new NullPointerException("apk == null");
            }
            this.mApkFile = apk;
            this.mApkDataSource = null;
        }

        public Builder(DataSource apk) {
            if (apk == null) {
                throw new NullPointerException("apk == null");
            }
            this.mApkDataSource = apk;
            this.mApkFile = null;
        }

        public Builder setMinCheckedPlatformVersion(int minSdkVersion) {
            this.mMinSdkVersion = minSdkVersion;
            return this;
        }

        public Builder setMaxCheckedPlatformVersion(int maxSdkVersion) {
            this.mMaxSdkVersion = maxSdkVersion;
            return this;
        }

        public SourceStampVerifier build() {
            return new SourceStampVerifier(this.mApkFile, this.mApkDataSource, this.mMinSdkVersion, this.mMaxSdkVersion);
        }
    }
}
