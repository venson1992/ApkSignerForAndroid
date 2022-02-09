package com.android.apksig;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigResult;
import com.android.apksig.internal.apk.ApkSignerInfo;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.SignatureInfo;
import com.android.apksig.internal.apk.SignatureNotFoundException;
import com.android.apksig.internal.apk.stamp.V2SourceStampVerifier;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.apk.v2.V2SchemeVerifier;
import com.android.apksig.internal.apk.v3.V3SchemeVerifier;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipFormatException;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ApkVerifier {
    private static final Map<Integer, String> SUPPORTED_APK_SIG_SCHEME_NAMES = loadSupportedApkSigSchemeNames();
    private final DataSource mApkDataSource;
    private final File mApkFile;
    private final int mMaxSdkVersion;
    private final Integer mMinSdkVersion;
    private final File mV4SignatureFile;

    private static Map<Integer, String> loadSupportedApkSigSchemeNames() {
        Map<Integer, String> supportedMap = new HashMap<>(2);
        supportedMap.put(2, "APK Signature Scheme v2");
        supportedMap.put(3, "APK Signature Scheme v3");
        return supportedMap;
    }

    private ApkVerifier(File apkFile, DataSource apkDataSource, File v4SignatureFile, Integer minSdkVersion, int maxSdkVersion) {
        this.mApkFile = apkFile;
        this.mApkDataSource = apkDataSource;
        this.mV4SignatureFile = v4SignatureFile;
        this.mMinSdkVersion = minSdkVersion;
        this.mMaxSdkVersion = maxSdkVersion;
    }

    public Result verify() throws IOException, ApkFormatException, NoSuchAlgorithmException, IllegalStateException {
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
            return verify(apk);
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:11:0x005d, code lost:
        if (r31.containsErrors() != false) goto L_0x005f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:174:0x050a, code lost:
        if (r31.isVerifiedUsingV2Scheme() == false) goto L_0x050c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:24:0x00a4, code lost:
        if (r31.containsErrors() == false) goto L_0x00a6;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x00c9, code lost:
        if (r31.containsErrors() == false) goto L_0x00cb;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private com.android.apksig.ApkVerifier.Result verify(com.android.apksig.util.DataSource r57) throws java.io.IOException, com.android.apksig.apk.ApkFormatException, java.security.NoSuchAlgorithmException {
        /*
        // Method dump skipped, instructions count: 1422
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.ApkVerifier.verify(com.android.apksig.util.DataSource):com.android.apksig.ApkVerifier$Result");
    }

    private int verifyAndGetMinSdkVersion(DataSource apk, ApkUtils.ZipSections zipSections) throws ApkFormatException, IOException {
        if (this.mMinSdkVersion == null) {
            ByteBuffer androidManifest = null;
            if (0 == 0) {
                androidManifest = getAndroidManifestFromApk(apk, zipSections);
            }
            int minSdkVersion = ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(androidManifest.slice());
            if (minSdkVersion <= this.mMaxSdkVersion) {
                return minSdkVersion;
            }
            throw new IllegalArgumentException("minSdkVersion from APK (" + minSdkVersion + ") > maxSdkVersion (" + this.mMaxSdkVersion + ")");
        } else if (this.mMinSdkVersion.intValue() < 0) {
            throw new IllegalArgumentException("minSdkVersion must not be negative: " + this.mMinSdkVersion);
        } else if (this.mMinSdkVersion == null || this.mMinSdkVersion.intValue() <= this.mMaxSdkVersion) {
            return this.mMinSdkVersion.intValue();
        } else {
            throw new IllegalArgumentException("minSdkVersion (" + this.mMinSdkVersion + ") > maxSdkVersion (" + this.mMaxSdkVersion + ")");
        }
    }

    private static Map<Integer, String> getSupportedSchemeNames(int maxSdkVersion) {
        if (maxSdkVersion >= 28) {
            return SUPPORTED_APK_SIG_SCHEME_NAMES;
        }
        if (maxSdkVersion < 24) {
            return Collections.emptyMap();
        }
        Map<Integer, String> supportedSchemeNames = new HashMap<>(1);
        supportedSchemeNames.put(2, SUPPORTED_APK_SIG_SCHEME_NAMES.get(2));
        return supportedSchemeNames;
    }

    public Result verifySourceStamp() {
        return verifySourceStamp(null);
    }

    public Result verifySourceStamp(String expectedCertDigest) {
        Result createSourceStampResultWithError;
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
            createSourceStampResultWithError = verifySourceStamp(apk, expectedCertDigest);
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                }
            }
        } catch (IOException e2) {
            createSourceStampResultWithError = createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR, Issue.UNEXPECTED_EXCEPTION, e2);
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
        return createSourceStampResultWithError;
    }

    private Result verifySourceStamp(DataSource apk, String expectedCertDigest) {
        ApkSigningBlockUtils.Result v2Result;
        ApkSigningBlockUtils.Result v3Result;
        boolean stampSigningBlockFound;
        try {
            ApkUtils.ZipSections zipSections = ApkUtils.findZipSections(apk);
            int minSdkVersion = verifyAndGetMinSdkVersion(apk, zipSections);
            List<CentralDirectoryRecord> cdRecords = V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections);
            CentralDirectoryRecord sourceStampCdRecord = null;
            Iterator<CentralDirectoryRecord> it = cdRecords.iterator();
            while (true) {
                if (!it.hasNext()) {
                    break;
                }
                CentralDirectoryRecord cdRecord = it.next();
                if ("stamp-cert-sha256".equals(cdRecord.getName())) {
                    sourceStampCdRecord = cdRecord;
                    break;
                }
            }
            if (sourceStampCdRecord == null) {
                try {
                    ApkSigningBlockUtils.findSignature(apk, zipSections, 1845461005, new ApkSigningBlockUtils.Result(0));
                    stampSigningBlockFound = true;
                } catch (ApkSigningBlockUtils.SignatureNotFoundException e) {
                    stampSigningBlockFound = false;
                }
                if (stampSigningBlockFound) {
                    return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_NOT_VERIFIED, Issue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST, new Object[0]);
                }
                return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_MISSING, Issue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING, new Object[0]);
            }
            byte[] sourceStampCertificateDigest = LocalFileRecord.getUncompressedData(apk, sourceStampCdRecord, zipSections.getZipCentralDirectoryOffset());
            if (expectedCertDigest != null) {
                String actualCertDigest = ApkSigningBlockUtils.toHex(sourceStampCertificateDigest);
                if (!expectedCertDigest.equalsIgnoreCase(actualCertDigest)) {
                    return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.CERT_DIGEST_MISMATCH, Issue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH, actualCertDigest, expectedCertDigest);
                }
            }
            Map<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeApkContentDigests = new HashMap<>();
            Map<Integer, String> supportedSchemeNames = getSupportedSchemeNames(this.mMaxSdkVersion);
            Set<Integer> foundApkSigSchemeIds = new HashSet<>(2);
            Result result = new Result();
            if (this.mMaxSdkVersion >= 28 && (v3Result = getApkContentDigests(apk, zipSections, foundApkSigSchemeIds, supportedSchemeNames, signatureSchemeApkContentDigests, 3, Math.max(minSdkVersion, 28))) != null && v3Result.containsErrors()) {
                result.mergeFrom((Result) v3Result);
                return mergeSourceStampResult(Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR, result);
            } else if (this.mMaxSdkVersion < 24 || ((minSdkVersion >= 28 && !foundApkSigSchemeIds.isEmpty()) || (v2Result = getApkContentDigests(apk, zipSections, foundApkSigSchemeIds, supportedSchemeNames, signatureSchemeApkContentDigests, 2, Math.max(minSdkVersion, 24))) == null || !v2Result.containsErrors())) {
                if (minSdkVersion < 24 || foundApkSigSchemeIds.isEmpty()) {
                    signatureSchemeApkContentDigests.put(1, getApkContentDigestFromV1SigningScheme(cdRecords, apk, zipSections));
                }
                ApkSigResult sourceStampResult = V2SourceStampVerifier.verify(apk, zipSections, sourceStampCertificateDigest, signatureSchemeApkContentDigests, minSdkVersion, this.mMaxSdkVersion);
                result.mergeFrom((Result) sourceStampResult);
                if (sourceStampResult.verified) {
                    result.setVerified();
                    return result;
                }
                result.setWarningsAsErrors(true);
                return result;
            } else {
                result.mergeFrom((Result) v2Result);
                return mergeSourceStampResult(Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR, result);
            }
        } catch (ApkFormatException | ZipFormatException | IOException e2) {
            return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR, Issue.MALFORMED_APK, e2);
        } catch (NoSuchAlgorithmException e3) {
            return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.VERIFICATION_ERROR, Issue.UNEXPECTED_EXCEPTION, e3);
        } catch (SignatureNotFoundException e4) {
            return createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus.STAMP_NOT_VERIFIED, Issue.SOURCE_STAMP_SIG_MISSING, new Object[0]);
        }
    }

    private static Result createSourceStampResultWithError(Result.SourceStampInfo.SourceStampVerificationStatus verificationStatus, Issue issue, Object... params) {
        Result result = new Result();
        result.addError(issue, params);
        return mergeSourceStampResult(verificationStatus, result);
    }

    private static Result mergeSourceStampResult(Result.SourceStampInfo.SourceStampVerificationStatus verificationStatus, Result result) {
        result.mSourceStampInfo = new Result.SourceStampInfo(verificationStatus);
        return result;
    }

    private ApkSigningBlockUtils.Result getApkContentDigests(DataSource apk, ApkUtils.ZipSections zipSections, Set<Integer> foundApkSigSchemeIds, Map<Integer, String> supportedSchemeNames, Map<Integer, Map<ContentDigestAlgorithm, byte[]>> sigSchemeApkContentDigests, int apkSigSchemeVersion, int minSdkVersion) throws IOException, NoSuchAlgorithmException {
        int sigSchemeBlockId;
        if (!(apkSigSchemeVersion == 2 || apkSigSchemeVersion == 3)) {
            return null;
        }
        ApkSigningBlockUtils.Result result = new ApkSigningBlockUtils.Result(apkSigSchemeVersion);
        if (apkSigSchemeVersion == 3) {
            sigSchemeBlockId = -262969152;
        } else {
            sigSchemeBlockId = 1896449818;
        }
        try {
            SignatureInfo signatureInfo = ApkSigningBlockUtils.findSignature(apk, zipSections, sigSchemeBlockId, result);
            foundApkSigSchemeIds.add(Integer.valueOf(apkSigSchemeVersion));
            Set<ContentDigestAlgorithm> contentDigestsToVerify = new HashSet<>(1);
            if (apkSigSchemeVersion == 2) {
                V2SchemeVerifier.parseSigners(signatureInfo.signatureBlock, contentDigestsToVerify, supportedSchemeNames, foundApkSigSchemeIds, minSdkVersion, this.mMaxSdkVersion, result);
            } else {
                V3SchemeVerifier.parseSigners(signatureInfo.signatureBlock, contentDigestsToVerify, result);
            }
            Map<ContentDigestAlgorithm, byte[]> apkContentDigests = new EnumMap<>(ContentDigestAlgorithm.class);
            for (ApkSigningBlockUtils.Result.SignerInfo signerInfo : result.signers) {
                for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest : signerInfo.contentDigests) {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(contentDigest.getSignatureAlgorithmId());
                    if (signatureAlgorithm != null) {
                        apkContentDigests.put(signatureAlgorithm.getContentDigestAlgorithm(), contentDigest.getValue());
                    }
                }
            }
            sigSchemeApkContentDigests.put(Integer.valueOf(apkSigSchemeVersion), apkContentDigests);
            return result;
        } catch (ApkSigningBlockUtils.SignatureNotFoundException e) {
            return null;
        }
    }

    private static void checkV4Certificate(List<X509Certificate> v4Certs, List<X509Certificate> v2v3Certs, Result result) {
        try {
            if (!Arrays.equals(v2v3Certs.get(0).getEncoded(), v4Certs.get(0).getEncoded())) {
                result.addError(Issue.V4_SIG_V2_V3_SIGNERS_MISMATCH, new Object[0]);
            }
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to encode APK signer cert", e);
        }
    }

    private static byte[] pickBestDigestForV4(List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests) {
        Map<ContentDigestAlgorithm, byte[]> apkContentDigests = new HashMap<>();
        collectApkContentDigests(contentDigests, apkContentDigests);
        return ApkSigningBlockUtils.pickBestDigestForV4(apkContentDigests);
    }

    private static Map<ContentDigestAlgorithm, byte[]> getApkContentDigestsFromSigningSchemeResult(ApkSigningBlockUtils.Result apkSigningSchemeResult) {
        Map<ContentDigestAlgorithm, byte[]> apkContentDigests = new HashMap<>();
        for (ApkSigningBlockUtils.Result.SignerInfo signerInfo : apkSigningSchemeResult.signers) {
            collectApkContentDigests(signerInfo.contentDigests, apkContentDigests);
        }
        return apkContentDigests;
    }

    private static Map<ContentDigestAlgorithm, byte[]> getApkContentDigestFromV1SigningScheme(List<CentralDirectoryRecord> cdRecords, DataSource apk, ApkUtils.ZipSections zipSections) throws IOException, ApkFormatException {
        CentralDirectoryRecord manifestCdRecord = null;
        Map<ContentDigestAlgorithm, byte[]> v1ContentDigest = new EnumMap<>(ContentDigestAlgorithm.class);
        Iterator<CentralDirectoryRecord> it = cdRecords.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            CentralDirectoryRecord cdRecord = it.next();
            if ("META-INF/MANIFEST.MF".equals(cdRecord.getName())) {
                manifestCdRecord = cdRecord;
                break;
            }
        }
        if (manifestCdRecord != null) {
            try {
                v1ContentDigest.put(ContentDigestAlgorithm.SHA256, ApkUtils.computeSha256DigestBytes(LocalFileRecord.getUncompressedData(apk, manifestCdRecord, zipSections.getZipCentralDirectoryOffset())));
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Failed to read APK", e);
            }
        }
        return v1ContentDigest;
    }

    private static void collectApkContentDigests(List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> contentDigests, Map<ContentDigestAlgorithm, byte[]> apkContentDigests) {
        for (ApkSigningBlockUtils.Result.SignerInfo.ContentDigest contentDigest : contentDigests) {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(contentDigest.getSignatureAlgorithmId());
            if (signatureAlgorithm != null) {
                apkContentDigests.put(signatureAlgorithm.getContentDigestAlgorithm(), contentDigest.getValue());
            }
        }
    }

    private static ByteBuffer getAndroidManifestFromApk(DataSource apk, ApkUtils.ZipSections zipSections) throws IOException, ApkFormatException {
        try {
            return ApkSigner.getAndroidManifestFromApk(V1SchemeVerifier.parseZipCentralDirectory(apk, zipSections), apk.slice(0, zipSections.getZipCentralDirectoryOffset()));
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Failed to read AndroidManifest.xml", e);
        }
    }

    private static int getMinimumSignatureSchemeVersionForTargetSdk(int targetSdkVersion) {
        if (targetSdkVersion >= 30) {
            return 2;
        }
        return 1;
    }

    public static class Result {
        private final List<IssueWithParams> mErrors = new ArrayList();
        private final List<X509Certificate> mSignerCerts = new ArrayList();
        private SigningCertificateLineage mSigningCertificateLineage;
        private SourceStampInfo mSourceStampInfo;
        private boolean mSourceStampVerified;
        private final List<V1SchemeSignerInfo> mV1SchemeIgnoredSigners = new ArrayList();
        private final List<V1SchemeSignerInfo> mV1SchemeSigners = new ArrayList();
        private final List<V2SchemeSignerInfo> mV2SchemeSigners = new ArrayList();
        private final List<V3SchemeSignerInfo> mV3SchemeSigners = new ArrayList();
        private final List<V4SchemeSignerInfo> mV4SchemeSigners = new ArrayList();
        private boolean mVerified;
        private boolean mVerifiedUsingV1Scheme;
        private boolean mVerifiedUsingV2Scheme;
        private boolean mVerifiedUsingV3Scheme;
        private boolean mVerifiedUsingV4Scheme;
        private final List<IssueWithParams> mWarnings = new ArrayList();
        private boolean mWarningsAsErrors;

        public boolean isVerified() {
            return this.mVerified;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void setVerified() {
            this.mVerified = true;
        }

        public boolean isVerifiedUsingV1Scheme() {
            return this.mVerifiedUsingV1Scheme;
        }

        public boolean isVerifiedUsingV2Scheme() {
            return this.mVerifiedUsingV2Scheme;
        }

        public boolean isVerifiedUsingV3Scheme() {
            return this.mVerifiedUsingV3Scheme;
        }

        public boolean isVerifiedUsingV4Scheme() {
            return this.mVerifiedUsingV4Scheme;
        }

        public boolean isSourceStampVerified() {
            return this.mSourceStampVerified;
        }

        public List<X509Certificate> getSignerCertificates() {
            return this.mSignerCerts;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addSignerCertificate(X509Certificate cert) {
            this.mSignerCerts.add(cert);
        }

        public List<V1SchemeSignerInfo> getV1SchemeSigners() {
            return this.mV1SchemeSigners;
        }

        public List<V1SchemeSignerInfo> getV1SchemeIgnoredSigners() {
            return this.mV1SchemeIgnoredSigners;
        }

        public List<V2SchemeSignerInfo> getV2SchemeSigners() {
            return this.mV2SchemeSigners;
        }

        public List<V3SchemeSignerInfo> getV3SchemeSigners() {
            return this.mV3SchemeSigners;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private List<V4SchemeSignerInfo> getV4SchemeSigners() {
            return this.mV4SchemeSigners;
        }

        public SourceStampInfo getSourceStampInfo() {
            return this.mSourceStampInfo;
        }

        public SigningCertificateLineage getSigningCertificateLineage() {
            return this.mSigningCertificateLineage;
        }

        /* access modifiers changed from: package-private */
        public void addError(Issue msg, Object... parameters) {
            this.mErrors.add(new IssueWithParams(msg, parameters));
        }

        /* access modifiers changed from: package-private */
        public void addWarning(Issue msg, Object... parameters) {
            this.mWarnings.add(new IssueWithParams(msg, parameters));
        }

        /* access modifiers changed from: package-private */
        public void setWarningsAsErrors(boolean value) {
            this.mWarningsAsErrors = value;
        }

        public List<IssueWithParams> getErrors() {
            if (!this.mWarningsAsErrors) {
                return this.mErrors;
            }
            List<IssueWithParams> allErrors = new ArrayList<>();
            allErrors.addAll(this.mErrors);
            allErrors.addAll(this.mWarnings);
            return allErrors;
        }

        public List<IssueWithParams> getWarnings() {
            return this.mWarnings;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void mergeFrom(V1SchemeVerifier.Result source) {
            this.mVerifiedUsingV1Scheme = source.verified;
            this.mErrors.addAll(source.getErrors());
            this.mWarnings.addAll(source.getWarnings());
            for (V1SchemeVerifier.Result.SignerInfo signer : source.signers) {
                this.mV1SchemeSigners.add(new V1SchemeSignerInfo(signer));
            }
            for (V1SchemeVerifier.Result.SignerInfo signer2 : source.ignoredSigners) {
                this.mV1SchemeIgnoredSigners.add(new V1SchemeSignerInfo(signer2));
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void mergeFrom(ApkSigResult source) {
            switch (source.signatureSchemeVersion) {
                case BerEncoding.TAG_CLASS_UNIVERSAL /*{ENCODED_INT: 0}*/:
                    this.mSourceStampVerified = source.verified;
                    if (!source.mSigners.isEmpty()) {
                        this.mSourceStampInfo = new SourceStampInfo(source.mSigners.get(0));
                        return;
                    }
                    return;
                default:
                    throw new IllegalArgumentException("Unknown ApkSigResult Signing Block Scheme Id " + source.signatureSchemeVersion);
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void mergeFrom(ApkSigningBlockUtils.Result source) {
            switch (source.signatureSchemeVersion) {
                case BerEncoding.TAG_CLASS_UNIVERSAL /*{ENCODED_INT: 0}*/:
                    this.mSourceStampVerified = source.verified;
                    if (!source.signers.isEmpty()) {
                        this.mSourceStampInfo = new SourceStampInfo(source.signers.get(0));
                        return;
                    }
                    return;
                case 1:
                default:
                    throw new IllegalArgumentException("Unknown Signing Block Scheme Id");
                case 2:
                    this.mVerifiedUsingV2Scheme = source.verified;
                    for (ApkSigningBlockUtils.Result.SignerInfo signer : source.signers) {
                        this.mV2SchemeSigners.add(new V2SchemeSignerInfo(signer));
                    }
                    return;
                case 3:
                    this.mVerifiedUsingV3Scheme = source.verified;
                    for (ApkSigningBlockUtils.Result.SignerInfo signer2 : source.signers) {
                        this.mV3SchemeSigners.add(new V3SchemeSignerInfo(signer2));
                    }
                    this.mSigningCertificateLineage = source.signingCertificateLineage;
                    return;
                case 4:
                    this.mVerifiedUsingV4Scheme = source.verified;
                    for (ApkSigningBlockUtils.Result.SignerInfo signer3 : source.signers) {
                        this.mV4SchemeSigners.add(new V4SchemeSignerInfo(signer3));
                    }
                    return;
            }
        }

        public boolean containsErrors() {
            if (!this.mErrors.isEmpty()) {
                return true;
            }
            if (this.mWarningsAsErrors && !this.mWarnings.isEmpty()) {
                return true;
            }
            if (!this.mV1SchemeSigners.isEmpty()) {
                for (V1SchemeSignerInfo signer : this.mV1SchemeSigners) {
                    if (signer.containsErrors()) {
                        return true;
                    }
                    if (this.mWarningsAsErrors && !signer.getWarnings().isEmpty()) {
                        return true;
                    }
                }
            }
            if (!this.mV2SchemeSigners.isEmpty()) {
                for (V2SchemeSignerInfo signer2 : this.mV2SchemeSigners) {
                    if (signer2.containsErrors()) {
                        return true;
                    }
                    if (this.mWarningsAsErrors && !signer2.getWarnings().isEmpty()) {
                        return true;
                    }
                }
            }
            if (!this.mV3SchemeSigners.isEmpty()) {
                for (V3SchemeSignerInfo signer3 : this.mV3SchemeSigners) {
                    if (signer3.containsErrors()) {
                        return true;
                    }
                    if (this.mWarningsAsErrors && !signer3.getWarnings().isEmpty()) {
                        return true;
                    }
                }
            }
            if (this.mSourceStampInfo != null) {
                if (this.mSourceStampInfo.containsErrors()) {
                    return true;
                }
                if (!this.mWarningsAsErrors || this.mSourceStampInfo.getWarnings().isEmpty()) {
                    return false;
                }
                return true;
            }
            return false;
        }

        public List<IssueWithParams> getAllErrors() {
            List<IssueWithParams> errors = new ArrayList<>();
            errors.addAll(this.mErrors);
            if (this.mWarningsAsErrors) {
                errors.addAll(this.mWarnings);
            }
            if (!this.mV1SchemeSigners.isEmpty()) {
                for (V1SchemeSignerInfo signer : this.mV1SchemeSigners) {
                    errors.addAll(signer.mErrors);
                    if (this.mWarningsAsErrors) {
                        errors.addAll(signer.getWarnings());
                    }
                }
            }
            if (!this.mV2SchemeSigners.isEmpty()) {
                for (V2SchemeSignerInfo signer2 : this.mV2SchemeSigners) {
                    errors.addAll(signer2.mErrors);
                    if (this.mWarningsAsErrors) {
                        errors.addAll(signer2.getWarnings());
                    }
                }
            }
            if (!this.mV3SchemeSigners.isEmpty()) {
                for (V3SchemeSignerInfo signer3 : this.mV3SchemeSigners) {
                    errors.addAll(signer3.mErrors);
                    if (this.mWarningsAsErrors) {
                        errors.addAll(signer3.getWarnings());
                    }
                }
            }
            if (this.mSourceStampInfo != null) {
                errors.addAll(this.mSourceStampInfo.getErrors());
                if (this.mWarningsAsErrors) {
                    errors.addAll(this.mSourceStampInfo.getWarnings());
                }
            }
            return errors;
        }

        public static class V1SchemeSignerInfo {
            private final List<X509Certificate> mCertChain;
            private final List<IssueWithParams> mErrors;
            private final String mName;
            private final String mSignatureBlockFileName;
            private final String mSignatureFileName;
            private final List<IssueWithParams> mWarnings;

            private V1SchemeSignerInfo(V1SchemeVerifier.Result.SignerInfo result) {
                this.mName = result.name;
                this.mCertChain = result.certChain;
                this.mSignatureBlockFileName = result.signatureBlockFileName;
                this.mSignatureFileName = result.signatureFileName;
                this.mErrors = result.getErrors();
                this.mWarnings = result.getWarnings();
            }

            public String getName() {
                return this.mName;
            }

            public String getSignatureBlockFileName() {
                return this.mSignatureBlockFileName;
            }

            public String getSignatureFileName() {
                return this.mSignatureFileName;
            }

            public X509Certificate getCertificate() {
                if (this.mCertChain.isEmpty()) {
                    return null;
                }
                return this.mCertChain.get(0);
            }

            public List<X509Certificate> getCertificateChain() {
                return this.mCertChain;
            }

            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            /* access modifiers changed from: private */
            /* access modifiers changed from: public */
            private void addError(Issue msg, Object... parameters) {
                this.mErrors.add(new IssueWithParams(msg, parameters));
            }
        }

        public static class V2SchemeSignerInfo {
            private final List<X509Certificate> mCerts;
            private final List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> mContentDigests;
            private final List<IssueWithParams> mErrors;
            private final int mIndex;
            private final List<IssueWithParams> mWarnings;

            private V2SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result) {
                this.mIndex = result.index;
                this.mCerts = result.certs;
                this.mErrors = result.getErrors();
                this.mWarnings = result.getWarnings();
                this.mContentDigests = result.contentDigests;
            }

            public int getIndex() {
                return this.mIndex;
            }

            public X509Certificate getCertificate() {
                if (this.mCerts.isEmpty()) {
                    return null;
                }
                return this.mCerts.get(0);
            }

            public List<X509Certificate> getCertificates() {
                return this.mCerts;
            }

            /* access modifiers changed from: private */
            /* access modifiers changed from: public */
            private void addError(Issue msg, Object... parameters) {
                this.mErrors.add(new IssueWithParams(msg, parameters));
            }

            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests() {
                return this.mContentDigests;
            }
        }

        public static class V3SchemeSignerInfo {
            private final List<X509Certificate> mCerts;
            private final List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> mContentDigests;
            private final List<IssueWithParams> mErrors;
            private final int mIndex;
            private final List<IssueWithParams> mWarnings;

            private V3SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result) {
                this.mIndex = result.index;
                this.mCerts = result.certs;
                this.mErrors = result.getErrors();
                this.mWarnings = result.getWarnings();
                this.mContentDigests = result.contentDigests;
            }

            public int getIndex() {
                return this.mIndex;
            }

            public X509Certificate getCertificate() {
                if (this.mCerts.isEmpty()) {
                    return null;
                }
                return this.mCerts.get(0);
            }

            public List<X509Certificate> getCertificates() {
                return this.mCerts;
            }

            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests() {
                return this.mContentDigests;
            }
        }

        public static class V4SchemeSignerInfo {
            private final List<X509Certificate> mCerts;
            private final List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> mContentDigests;
            private final List<IssueWithParams> mErrors;
            private final int mIndex;
            private final List<IssueWithParams> mWarnings;

            private V4SchemeSignerInfo(ApkSigningBlockUtils.Result.SignerInfo result) {
                this.mIndex = result.index;
                this.mCerts = result.certs;
                this.mErrors = result.getErrors();
                this.mWarnings = result.getWarnings();
                this.mContentDigests = result.contentDigests;
            }

            public int getIndex() {
                return this.mIndex;
            }

            public X509Certificate getCertificate() {
                if (this.mCerts.isEmpty()) {
                    return null;
                }
                return this.mCerts.get(0);
            }

            public List<X509Certificate> getCertificates() {
                return this.mCerts;
            }

            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            public List<ApkSigningBlockUtils.Result.SignerInfo.ContentDigest> getContentDigests() {
                return this.mContentDigests;
            }
        }

        public static class SourceStampInfo {
            private final List<X509Certificate> mCertificateLineage;
            private final List<X509Certificate> mCertificates;
            private final List<IssueWithParams> mErrors;
            private final SourceStampVerificationStatus mSourceStampVerificationStatus;
            private final List<IssueWithParams> mWarnings;

            public enum SourceStampVerificationStatus {
                STAMP_VERIFIED,
                STAMP_VERIFICATION_FAILED,
                CERT_DIGEST_MISMATCH,
                STAMP_MISSING,
                STAMP_NOT_VERIFIED,
                VERIFICATION_ERROR
            }

            private SourceStampInfo(ApkSignerInfo result) {
                this.mCertificates = result.certs;
                this.mCertificateLineage = result.certificateLineage;
                this.mErrors = ApkVerificationIssueAdapter.getIssuesFromVerificationIssues(result.getErrors());
                this.mWarnings = ApkVerificationIssueAdapter.getIssuesFromVerificationIssues(result.getWarnings());
                if (!this.mErrors.isEmpty() || !this.mWarnings.isEmpty()) {
                    this.mSourceStampVerificationStatus = SourceStampVerificationStatus.STAMP_VERIFICATION_FAILED;
                } else {
                    this.mSourceStampVerificationStatus = SourceStampVerificationStatus.STAMP_VERIFIED;
                }
            }

            SourceStampInfo(SourceStampVerificationStatus sourceStampVerificationStatus) {
                this.mCertificates = Collections.emptyList();
                this.mCertificateLineage = Collections.emptyList();
                this.mErrors = Collections.emptyList();
                this.mWarnings = Collections.emptyList();
                this.mSourceStampVerificationStatus = sourceStampVerificationStatus;
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
                return !this.mErrors.isEmpty();
            }

            public List<IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            public SourceStampVerificationStatus getSourceStampVerificationStatus() {
                return this.mSourceStampVerificationStatus;
            }
        }
    }

    public enum Issue {
        JAR_SIG_NO_SIGNATURES("No JAR signatures"),
        JAR_SIG_NO_SIGNED_ZIP_ENTRIES("No JAR entries covered by JAR signatures"),
        JAR_SIG_DUPLICATE_ZIP_ENTRY("Duplicate entry: %1$s"),
        JAR_SIG_DUPLICATE_MANIFEST_SECTION("Duplicate section in META-INF/MANIFEST.MF: %1$s"),
        JAR_SIG_UNNNAMED_MANIFEST_SECTION("Malformed META-INF/MANIFEST.MF: invidual section #%1$d does not have a name"),
        JAR_SIG_UNNNAMED_SIG_FILE_SECTION("Malformed %1$s: invidual section #%2$d does not have a name"),
        JAR_SIG_NO_MANIFEST("Missing META-INF/MANIFEST.MF"),
        JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST("%1$s entry referenced by META-INF/MANIFEST.MF not found in the APK"),
        JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST("No digest for %1$s in META-INF/MANIFEST.MF"),
        JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE("No digest for %1$s in %2$s"),
        JAR_SIG_ZIP_ENTRY_NOT_SIGNED("%1$s entry not signed"),
        JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH("Entries %1$s and %3$s are signed with different sets of signers : <%2$s> vs <%4$s>"),
        JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY("%2$s digest of %1$s does not match the digest specified in %3$s. Expected: <%5$s>, actual: <%4$s>"),
        JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY("%1$s digest of META-INF/MANIFEST.MF main section does not match the digest specified in %2$s. Expected: <%4$s>, actual: <%3$s>"),
        JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY("%2$s digest of META-INF/MANIFEST.MF section for %1$s does not match the digest specified in %3$s. Expected: <%5$s>, actual: <%4$s>"),
        JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE("%1$s does not specify digest of META-INF/MANIFEST.MF. This slows down verification."),
        JAR_SIG_NO_APK_SIG_STRIP_PROTECTION("APK is signed using APK Signature Scheme v2 but these signatures may be stripped without being detected because %1$s does not contain anti-stripping protections."),
        JAR_SIG_MISSING_FILE("Partial JAR signature. Found: %1$s, missing: %2$s"),
        JAR_SIG_VERIFY_EXCEPTION("Failed to verify JAR signature %1$s against %2$s: %3$s"),
        JAR_SIG_UNSUPPORTED_SIG_ALG("JAR signature %1$s uses digest algorithm %5$s and signature algorithm %6$s which is not supported on API Level(s) %4$s for which this APK is being verified"),
        JAR_SIG_PARSE_EXCEPTION("Failed to parse JAR signature %1$s: %2$s"),
        JAR_SIG_MALFORMED_CERTIFICATE("Malformed certificate in JAR signature %1$s: %2$s"),
        JAR_SIG_DID_NOT_VERIFY("JAR signature %1$s did not verify against %2$s"),
        JAR_SIG_NO_SIGNERS("JAR signature %1$s contains no signers"),
        JAR_SIG_DUPLICATE_SIG_FILE_SECTION("Duplicate section in %1$s: %2$s"),
        JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE("Malformed %1$s: missing Signature-Version attribute"),
        JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID("JAR signature %1$s references unknown APK signature scheme ID: %2$d"),
        JAR_SIG_MISSING_APK_SIG_REFERENCED("JAR signature %1$s indicates the APK is signed using %3$s but no such signature was found. Signature stripped?"),
        JAR_SIG_UNPROTECTED_ZIP_ENTRY("%1$s not protected by signature. Unauthorized modifications to this JAR entry will not be detected. Delete or move the entry outside of META-INF/."),
        JAR_SIG_MISSING("No JAR signature from this signer"),
        NO_SIG_FOR_TARGET_SANDBOX_VERSION("Missing APK Signature Scheme v2 signature required for target sandbox version %1$d"),
        MIN_SIG_SCHEME_FOR_TARGET_SDK_NOT_MET("Target SDK version %1$d requires a minimum of signature scheme v%2$d; the APK is not signed with this or a later signature scheme"),
        V2_SIG_MISSING("No APK Signature Scheme v2 signature from this signer"),
        V2_SIG_MALFORMED_SIGNERS("Malformed list of signers"),
        V2_SIG_MALFORMED_SIGNER("Malformed signer block"),
        V2_SIG_MALFORMED_PUBLIC_KEY("Malformed public key: %1$s"),
        V2_SIG_MALFORMED_CERTIFICATE("Malformed certificate #%2$d: %3$s"),
        V2_SIG_MALFORMED_SIGNATURE("Malformed APK Signature Scheme v2 signature record #%1$d"),
        V2_SIG_MALFORMED_DIGEST("Malformed APK Signature Scheme v2 digest record #%1$d"),
        V2_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE("Malformed additional attribute #%1$d"),
        V2_SIG_UNKNOWN_APK_SIG_SCHEME_ID("APK Signature Scheme v2 signer: %1$s references unknown APK signature scheme ID: %2$d"),
        V2_SIG_MISSING_APK_SIG_REFERENCED("APK Signature Scheme v2 signature %1$s indicates the APK is signed using %2$s but no such signature was found. Signature stripped?"),
        V2_SIG_NO_SIGNERS("No signers in APK Signature Scheme v2 signature"),
        V2_SIG_UNKNOWN_SIG_ALGORITHM("Unknown signature algorithm: %1$#x"),
        V2_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE("Unknown additional attribute: ID %1$#x"),
        V2_SIG_VERIFY_EXCEPTION("Failed to verify %1$s signature: %2$s"),
        V2_SIG_DID_NOT_VERIFY("%1$s signature over signed-data did not verify"),
        V2_SIG_NO_SIGNATURES("No signatures"),
        V2_SIG_NO_SUPPORTED_SIGNATURES("No supported signatures: %1$s"),
        V2_SIG_NO_CERTIFICATES("No certificates"),
        V2_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD("Public key mismatch between certificate and signature record: <%1$s> vs <%2$s>"),
        V2_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS("Signature algorithms mismatch between signatures and digests records: %1$s vs %2$s"),
        V2_SIG_APK_DIGEST_DID_NOT_VERIFY("APK integrity check failed. %1$s digest mismatch. Expected: <%2$s>, actual: <%3$s>"),
        V3_SIG_MALFORMED_SIGNERS("Malformed list of signers"),
        V3_SIG_MALFORMED_SIGNER("Malformed signer block"),
        V3_SIG_MALFORMED_PUBLIC_KEY("Malformed public key: %1$s"),
        V3_SIG_MALFORMED_CERTIFICATE("Malformed certificate #%2$d: %3$s"),
        V3_SIG_MALFORMED_SIGNATURE("Malformed APK Signature Scheme v3 signature record #%1$d"),
        V3_SIG_MALFORMED_DIGEST("Malformed APK Signature Scheme v3 digest record #%1$d"),
        V3_SIG_MALFORMED_ADDITIONAL_ATTRIBUTE("Malformed additional attribute #%1$d"),
        V3_SIG_NO_SIGNERS("No signers in APK Signature Scheme v3 signature"),
        V3_SIG_MULTIPLE_SIGNERS("Multiple APK Signature Scheme v3 signatures found for a single  platform version."),
        V3_SIG_MULTIPLE_PAST_SIGNERS("Multiple signatures found for pre-v3 signing with an APK  Signature Scheme v3 signer.  Only one allowed."),
        V3_SIG_PAST_SIGNERS_MISMATCH("v3 signer differs from v1/v2 signer without proper signing certificate lineage."),
        V3_SIG_UNKNOWN_SIG_ALGORITHM("Unknown signature algorithm: %1$#x"),
        V3_SIG_UNKNOWN_ADDITIONAL_ATTRIBUTE("Unknown additional attribute: ID %1$#x"),
        V3_SIG_VERIFY_EXCEPTION("Failed to verify %1$s signature: %2$s"),
        V3_SIG_INVALID_SDK_VERSIONS("Invalid SDK Version parameter(s) encountered in APK Signature scheme v3 signature: minSdkVersion %1$s maxSdkVersion: %2$s"),
        V3_SIG_DID_NOT_VERIFY("%1$s signature over signed-data did not verify"),
        V3_SIG_NO_SIGNATURES("No signatures"),
        V3_SIG_NO_SUPPORTED_SIGNATURES("No supported signatures"),
        V3_SIG_NO_CERTIFICATES("No certificates"),
        V3_MIN_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD("minSdkVersion mismatch between signed data and signature record: <%1$s> vs <%2$s>"),
        V3_MAX_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD("maxSdkVersion mismatch between signed data and signature record: <%1$s> vs <%2$s>"),
        V3_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD("Public key mismatch between certificate and signature record: <%1$s> vs <%2$s>"),
        V3_SIG_SIG_ALG_MISMATCH_BETWEEN_SIGNATURES_AND_DIGESTS_RECORDS("Signature algorithms mismatch between signatures and digests records: %1$s vs %2$s"),
        V3_SIG_APK_DIGEST_DID_NOT_VERIFY("APK integrity check failed. %1$s digest mismatch. Expected: <%2$s>, actual: <%3$s>"),
        V3_SIG_POR_DID_NOT_VERIFY("SigningCertificateLineage attribute containd a proof-of-rotation record with signature(s) that did not verify."),
        V3_SIG_MALFORMED_LINEAGE("Failed to parse the SigningCertificateLineage structure in the APK Signature Scheme v3 signature's additional attributes section."),
        V3_SIG_POR_CERT_MISMATCH("APK signing certificate differs from the associated certificate found in the signer's SigningCertificateLineage."),
        V3_INCONSISTENT_SDK_VERSIONS("APK Signature Scheme v3 signers supported min/max SDK versions are not continuous."),
        V3_MISSING_SDK_VERSIONS("APK Signature Scheme v3 signers supported min/max SDK versions do not cover the entire desired range.  Found min:  %1$s max %2$s"),
        V3_INCONSISTENT_LINEAGES("SigningCertificateLineages targeting different platform versions using APK Signature Scheme v3 are not all a part of the same overall lineage."),
        APK_SIG_BLOCK_UNKNOWN_ENTRY_ID("APK Signing Block contains unknown entry: ID %1$#x"),
        V4_SIG_MALFORMED_SIGNERS("V4 signature has malformed signer block"),
        V4_SIG_UNKNOWN_SIG_ALGORITHM("V4 signature has unknown signing algorithm: %1$#x"),
        V4_SIG_NO_SIGNATURES("V4 signature has no signature found"),
        V4_SIG_NO_SUPPORTED_SIGNATURES("V4 signature has no supported signature"),
        V4_SIG_DID_NOT_VERIFY("%1$s signature over signed-data did not verify"),
        V4_SIG_VERIFY_EXCEPTION("Failed to verify %1$s signature: %2$s"),
        V4_SIG_MALFORMED_PUBLIC_KEY("Malformed public key: %1$s"),
        V4_SIG_MALFORMED_CERTIFICATE("V4 signature has malformed certificate"),
        V4_SIG_NO_CERTIFICATE("V4 signature has no certificate"),
        V4_SIG_PUBLIC_KEY_MISMATCH_BETWEEN_CERTIFICATE_AND_SIGNATURES_RECORD("V4 signature has mismatched certificate and signature: <%1$s> vs <%2$s>"),
        V4_SIG_APK_ROOT_DID_NOT_VERIFY("V4 signature's hash tree root (content digest) did not verity"),
        V4_SIG_APK_TREE_DID_NOT_VERIFY("V4 signature's hash tree did not verity"),
        V4_SIG_MULTIPLE_SIGNERS("V4 signature only supports one signer"),
        V4_SIG_V2_V3_SIGNERS_MISMATCH("V4 signature and V2/V3 signature have mismatched certificates"),
        V4_SIG_V2_V3_DIGESTS_MISMATCH("V4 signature and V2/V3 signature have mismatched digests"),
        V4_SIG_VERSION_NOT_CURRENT("V4 signature format version %1$d is different from the tool's current version %2$d"),
        SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING("Neither the source stamp certificate digest file nor the signature block are present in the APK"),
        SOURCE_STAMP_SIG_MISSING("No SourceStamp signature"),
        SOURCE_STAMP_MALFORMED_CERTIFICATE("Malformed certificate: %1$s"),
        SOURCE_STAMP_MALFORMED_SIGNATURE("Malformed SourceStamp signature"),
        SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM("Unknown signature algorithm: %1$#x"),
        SOURCE_STAMP_VERIFY_EXCEPTION("Failed to verify %1$s signature: %2$s"),
        SOURCE_STAMP_DID_NOT_VERIFY("%1$s signature over signed-data did not verify"),
        SOURCE_STAMP_NO_SIGNATURE("No signature"),
        SOURCE_STAMP_NO_SUPPORTED_SIGNATURE("Signature(s) {%1$s} not supported: %2$s"),
        SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK("Certificate mismatch between SourceStamp block in APK signing block and SourceStamp file in APK: <%1$s> vs <%2$s>"),
        SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST("A source stamp signature block was found without a corresponding certificate digest in the APK"),
        SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH("The source stamp certificate digest in the APK, %1$s, does not match the expected digest, %2$s"),
        SOURCE_STAMP_MALFORMED_ATTRIBUTE("Malformed stamp attribute #%1$d"),
        SOURCE_STAMP_UNKNOWN_ATTRIBUTE("Unknown stamp attribute: ID %1$#x"),
        SOURCE_STAMP_MALFORMED_LINEAGE("Failed to parse the SigningCertificateLineage structure in the source stamp attributes section."),
        SOURCE_STAMP_POR_CERT_MISMATCH("APK signing certificate differs from the associated certificate found in the signer's SigningCertificateLineage."),
        SOURCE_STAMP_POR_DID_NOT_VERIFY("Source stamp SigningCertificateLineage attribute contains a proof-of-rotation record with signature(s) that did not verify."),
        MALFORMED_APK("Malformed APK; the following exception was caught when attempting to parse the APK: %1$s"),
        UNEXPECTED_EXCEPTION("An unexpected exception was caught when verifying the signature: %1$s");
        
        private final String mFormat;

        private Issue(String format) {
            this.mFormat = format;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private String getFormat() {
            return this.mFormat;
        }
    }

    public static class IssueWithParams extends ApkVerificationIssue {
        private final Issue mIssue;
        private final Object[] mParams;

        public IssueWithParams(Issue issue, Object[] params) {
            super(issue.mFormat, params);
            this.mIssue = issue;
            this.mParams = params;
        }

        public Issue getIssue() {
            return this.mIssue;
        }

        @Override // com.android.apksig.ApkVerificationIssue
        public Object[] getParams() {
            return (Object[]) this.mParams.clone();
        }

        @Override // com.android.apksig.ApkVerificationIssue
        public String toString() {
            return String.format(this.mIssue.getFormat(), this.mParams);
        }
    }

    /* access modifiers changed from: private */
    public static class ByteArray {
        private final byte[] mArray;
        private final int mHashCode;

        private ByteArray(byte[] arr) {
            this.mArray = arr;
            this.mHashCode = Arrays.hashCode(this.mArray);
        }

        public int hashCode() {
            return this.mHashCode;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof ByteArray)) {
                return false;
            }
            ByteArray other = (ByteArray) obj;
            if (hashCode() != other.hashCode()) {
                return false;
            }
            return Arrays.equals(this.mArray, other.mArray);
        }
    }

    public static class Builder {
        private final DataSource mApkDataSource;
        private final File mApkFile;
        private int mMaxSdkVersion = Integer.MAX_VALUE;
        private Integer mMinSdkVersion;
        private File mV4SignatureFile;

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
            this.mMinSdkVersion = Integer.valueOf(minSdkVersion);
            return this;
        }

        public Builder setMaxCheckedPlatformVersion(int maxSdkVersion) {
            this.mMaxSdkVersion = maxSdkVersion;
            return this;
        }

        public Builder setV4SignatureFile(File v4SignatureFile) {
            this.mV4SignatureFile = v4SignatureFile;
            return this;
        }

        public ApkVerifier build() {
            return new ApkVerifier(this.mApkFile, this.mApkDataSource, this.mV4SignatureFile, this.mMinSdkVersion, this.mMaxSdkVersion);
        }
    }

    public static class ApkVerificationIssueAdapter {
        static final Map<Integer, Issue> sVerificationIssueIdToIssue = new HashMap();

        private ApkVerificationIssueAdapter() {
        }

        static {
            sVerificationIssueIdToIssue.put(1, Issue.V2_SIG_MALFORMED_SIGNERS);
            sVerificationIssueIdToIssue.put(2, Issue.V2_SIG_NO_SIGNERS);
            sVerificationIssueIdToIssue.put(3, Issue.V2_SIG_MALFORMED_SIGNER);
            sVerificationIssueIdToIssue.put(4, Issue.V2_SIG_MALFORMED_SIGNATURE);
            sVerificationIssueIdToIssue.put(5, Issue.V2_SIG_NO_SIGNATURES);
            sVerificationIssueIdToIssue.put(6, Issue.V2_SIG_MALFORMED_CERTIFICATE);
            sVerificationIssueIdToIssue.put(7, Issue.V2_SIG_NO_CERTIFICATES);
            sVerificationIssueIdToIssue.put(8, Issue.V2_SIG_MALFORMED_DIGEST);
            sVerificationIssueIdToIssue.put(9, Issue.V3_SIG_MALFORMED_SIGNERS);
            sVerificationIssueIdToIssue.put(10, Issue.V3_SIG_NO_SIGNERS);
            sVerificationIssueIdToIssue.put(11, Issue.V3_SIG_MALFORMED_SIGNER);
            sVerificationIssueIdToIssue.put(12, Issue.V3_SIG_MALFORMED_SIGNATURE);
            sVerificationIssueIdToIssue.put(13, Issue.V3_SIG_NO_SIGNATURES);
            sVerificationIssueIdToIssue.put(14, Issue.V3_SIG_MALFORMED_CERTIFICATE);
            sVerificationIssueIdToIssue.put(15, Issue.V3_SIG_NO_CERTIFICATES);
            sVerificationIssueIdToIssue.put(16, Issue.V3_SIG_MALFORMED_DIGEST);
            sVerificationIssueIdToIssue.put(17, Issue.SOURCE_STAMP_NO_SIGNATURE);
            sVerificationIssueIdToIssue.put(18, Issue.SOURCE_STAMP_MALFORMED_CERTIFICATE);
            sVerificationIssueIdToIssue.put(19, Issue.SOURCE_STAMP_UNKNOWN_SIG_ALGORITHM);
            sVerificationIssueIdToIssue.put(20, Issue.SOURCE_STAMP_MALFORMED_SIGNATURE);
            sVerificationIssueIdToIssue.put(21, Issue.SOURCE_STAMP_DID_NOT_VERIFY);
            sVerificationIssueIdToIssue.put(22, Issue.SOURCE_STAMP_VERIFY_EXCEPTION);
            sVerificationIssueIdToIssue.put(23, Issue.SOURCE_STAMP_EXPECTED_DIGEST_MISMATCH);
            sVerificationIssueIdToIssue.put(24, Issue.SOURCE_STAMP_SIGNATURE_BLOCK_WITHOUT_CERT_DIGEST);
            sVerificationIssueIdToIssue.put(25, Issue.SOURCE_STAMP_CERT_DIGEST_AND_SIG_BLOCK_MISSING);
            sVerificationIssueIdToIssue.put(26, Issue.SOURCE_STAMP_NO_SUPPORTED_SIGNATURE);
            sVerificationIssueIdToIssue.put(27, Issue.SOURCE_STAMP_CERTIFICATE_MISMATCH_BETWEEN_SIGNATURE_BLOCK_AND_APK);
            sVerificationIssueIdToIssue.put(28, Issue.MALFORMED_APK);
            sVerificationIssueIdToIssue.put(29, Issue.UNEXPECTED_EXCEPTION);
            sVerificationIssueIdToIssue.put(30, Issue.SOURCE_STAMP_SIG_MISSING);
            sVerificationIssueIdToIssue.put(31, Issue.SOURCE_STAMP_MALFORMED_ATTRIBUTE);
            sVerificationIssueIdToIssue.put(32, Issue.SOURCE_STAMP_UNKNOWN_ATTRIBUTE);
            sVerificationIssueIdToIssue.put(33, Issue.SOURCE_STAMP_MALFORMED_LINEAGE);
            sVerificationIssueIdToIssue.put(34, Issue.SOURCE_STAMP_POR_CERT_MISMATCH);
            sVerificationIssueIdToIssue.put(35, Issue.SOURCE_STAMP_POR_DID_NOT_VERIFY);
            sVerificationIssueIdToIssue.put(36, Issue.JAR_SIG_NO_SIGNATURES);
            sVerificationIssueIdToIssue.put(37, Issue.JAR_SIG_PARSE_EXCEPTION);
        }

        public static List<IssueWithParams> getIssuesFromVerificationIssues(List<? extends ApkVerificationIssue> verificationIssues) {
            List<IssueWithParams> result = new ArrayList<>(verificationIssues.size());
            for (ApkVerificationIssue issue : verificationIssues) {
                if (issue instanceof IssueWithParams) {
                    result.add((IssueWithParams) issue);
                } else {
                    result.add(new IssueWithParams(sVerificationIssueIdToIssue.get(Integer.valueOf(issue.getIssueId())), issue.getParams()));
                }
            }
            return result;
        }
    }
}
