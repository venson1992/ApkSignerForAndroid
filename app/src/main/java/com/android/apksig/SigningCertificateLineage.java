package com.android.apksig;

import com.android.apksig.DefaultApkSignerEngine;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SigningCertificateLineage;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.RandomAccessFileDataSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.zip.ZipFormatException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SigningCertificateLineage {
    private static final int CURRENT_VERSION = 1;
    private static final int FIRST_VERSION = 1;
    public static final int MAGIC = 1056913873;
    private static final int PAST_CERT_AUTH = 16;
    private static final int PAST_CERT_INSTALLED_DATA = 1;
    private static final int PAST_CERT_PERMISSION = 4;
    private static final int PAST_CERT_ROLLBACK = 8;
    private static final int PAST_CERT_SHARED_USER_ID = 2;
    private final int mMinSdkVersion;
    private final List<V3SigningCertificateLineage.SigningCertificateNode> mSigningLineage;

    private SigningCertificateLineage(int minSdkVersion, List<V3SigningCertificateLineage.SigningCertificateNode> list) {
        this.mMinSdkVersion = minSdkVersion;
        this.mSigningLineage = list;
    }

    /* access modifiers changed from: private */
    public static SigningCertificateLineage createSigningLineage(int minSdkVersion, SignerConfig parent, SignerCapabilities parentCapabilities, SignerConfig child, SignerCapabilities childCapabilities) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        return new SigningCertificateLineage(minSdkVersion, new ArrayList()).spawnFirstDescendant(parent, parentCapabilities).spawnDescendant(parent, child, childCapabilities);
    }

    public static SigningCertificateLineage readFromFile(File file) throws IOException {
        if (file != null) {
            return readFromDataSource(DataSources.asDataSource(new RandomAccessFile(file, "r")));
        }
        throw new NullPointerException("file == null");
    }

    public static SigningCertificateLineage readFromDataSource(DataSource dataSource) throws IOException {
        if (dataSource == null) {
            throw new NullPointerException("dataSource == null");
        }
        ByteBuffer inBuff = dataSource.getByteBuffer(0, (int) dataSource.size());
        inBuff.order(ByteOrder.LITTLE_ENDIAN);
        return read(inBuff);
    }

    public static SigningCertificateLineage readFromV3AttributeValue(byte[] attrValue) throws IOException {
        List<V3SigningCertificateLineage.SigningCertificateNode> parsedLineage = V3SigningCertificateLineage.readSigningCertificateLineage(ByteBuffer.wrap(attrValue).order(ByteOrder.LITTLE_ENDIAN));
        return new SigningCertificateLineage(calculateMinSdkVersion(parsedLineage), parsedLineage);
    }

    public static SigningCertificateLineage readFromApkFile(File apkFile) throws IOException, ApkFormatException {
        RandomAccessFile f = new RandomAccessFile(apkFile, "r");
        try {
            SigningCertificateLineage readFromApkDataSource = readFromApkDataSource(DataSources.asDataSource(f, 0, f.length()));
            f.close();
            return readFromApkDataSource;
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    }

    /* JADX INFO: Multiple debug info for r3v2 com.android.apksig.SigningCertificateLineage: [D('result' com.android.apksig.internal.apk.ApkSigningBlockUtils$Result), D('result' com.android.apksig.SigningCertificateLineage)] */
    /* JADX INFO: Multiple debug info for r3v3 com.android.apksig.SigningCertificateLineage: [D('result' com.android.apksig.internal.apk.ApkSigningBlockUtils$Result), D('result' com.android.apksig.SigningCertificateLineage)] */
    public static SigningCertificateLineage readFromApkDataSource(DataSource apk) throws IOException, ApkFormatException {
        try {
            ByteBuffer signers = ApkSigningBlockUtils.getLengthPrefixedSlice(ApkSigningBlockUtils.findSignature(apk, ApkUtils.findZipSections(apk), -262969152, new ApkSigningBlockUtils.Result(3)).signatureBlock);
            List<SigningCertificateLineage> lineages = new ArrayList<>(1);
            while (signers.hasRemaining()) {
                try {
                    lineages.add(readFromSignedData(ApkSigningBlockUtils.getLengthPrefixedSlice(ApkSigningBlockUtils.getLengthPrefixedSlice(signers))));
                } catch (IllegalArgumentException e) {
                }
            }
            if (lineages.isEmpty()) {
                throw new IllegalArgumentException("The provided APK does not contain a valid lineage.");
            } else if (lineages.size() > 1) {
                return consolidateLineages(lineages);
            } else {
                return lineages.get(0);
            }
        } catch (ZipFormatException e2) {
            throw new ApkFormatException(e2.getMessage());
        } catch (ApkSigningBlockUtils.SignatureNotFoundException e3) {
            throw new IllegalArgumentException("The provided APK does not contain a valid V3 signature block.");
        }
    }

    public static SigningCertificateLineage readFromSignedData(ByteBuffer signedData) throws IOException, ApkFormatException {
        ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        signedData.getInt();
        signedData.getInt();
        ByteBuffer additionalAttributes = ApkSigningBlockUtils.getLengthPrefixedSlice(signedData);
        List<SigningCertificateLineage> lineages = new ArrayList<>(1);
        while (additionalAttributes.hasRemaining()) {
            ByteBuffer attribute = ApkSigningBlockUtils.getLengthPrefixedSlice(additionalAttributes);
            if (attribute.getInt() == 1000370060) {
                lineages.add(readFromV3AttributeValue(ByteBufferUtils.toByteArray(attribute)));
            }
        }
        if (lineages.isEmpty()) {
            throw new IllegalArgumentException("The signed data does not contain a valid lineage.");
        } else if (lineages.size() > 1) {
            return consolidateLineages(lineages);
        } else {
            return lineages.get(0);
        }
    }

    public void writeToFile(File file) throws IOException {
        if (file == null) {
            throw new NullPointerException("file == null");
        }
        writeToDataSink(new RandomAccessFileDataSink(new RandomAccessFile(file, "rw")));
    }

    public void writeToDataSink(DataSink dataSink) throws IOException {
        if (dataSink == null) {
            throw new NullPointerException("dataSink == null");
        }
        dataSink.consume(write());
    }

    public SigningCertificateLineage spawnDescendant(SignerConfig parent, SignerConfig child) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (parent != null && child != null) {
            return spawnDescendant(parent, child, new SignerCapabilities.Builder().build());
        }
        throw new NullPointerException("can't add new descendant to lineage with null inputs");
    }

    public SigningCertificateLineage spawnDescendant(SignerConfig parent, SignerConfig child, SignerCapabilities childCapabilities) throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (parent == null) {
            throw new NullPointerException("parent == null");
        } else if (child == null) {
            throw new NullPointerException("child == null");
        } else if (childCapabilities == null) {
            throw new NullPointerException("childCapabilities == null");
        } else if (this.mSigningLineage.isEmpty()) {
            throw new IllegalArgumentException("Cannot spawn descendant signing certificate on an empty SigningCertificateLineage: no parent node");
        } else {
            V3SigningCertificateLineage.SigningCertificateNode currentGeneration = this.mSigningLineage.get(this.mSigningLineage.size() - 1);
            if (!Arrays.equals(currentGeneration.signingCert.getEncoded(), parent.getCertificate().getEncoded())) {
                throw new IllegalArgumentException("SignerConfig Certificate containing private key to sign the new SigningCertificateLineage record does not match the existing most recent record");
            }
            SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(parent);
            ByteBuffer prefixedSignedData = ByteBuffer.wrap(V3SigningCertificateLineage.encodeSignedData(child.getCertificate(), signatureAlgorithm.getId()));
            prefixedSignedData.position(4);
            ByteBuffer signedDataBuffer = ByteBuffer.allocate(prefixedSignedData.remaining());
            signedDataBuffer.put(prefixedSignedData);
            byte[] signedData = signedDataBuffer.array();
            List<X509Certificate> certificates = new ArrayList<>(1);
            certificates.add(parent.getCertificate());
            ApkSigningBlockUtils.SignerConfig newSignerConfig = new ApkSigningBlockUtils.SignerConfig();
            newSignerConfig.privateKey = parent.getPrivateKey();
            newSignerConfig.certificates = certificates;
            newSignerConfig.signatureAlgorithms = Collections.singletonList(signatureAlgorithm);
            List<Pair<Integer, byte[]>> signatures = ApkSigningBlockUtils.generateSignaturesOverData(newSignerConfig, signedData);
            SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.findById(signatures.get(0).getFirst().intValue());
            currentGeneration.sigAlgorithm = sigAlgorithm;
            V3SigningCertificateLineage.SigningCertificateNode childNode = new V3SigningCertificateLineage.SigningCertificateNode(child.getCertificate(), sigAlgorithm, null, signatures.get(0).getSecond(), childCapabilities.getFlags());
            List<V3SigningCertificateLineage.SigningCertificateNode> lineageCopy = new ArrayList<>(this.mSigningLineage);
            lineageCopy.add(childNode);
            return new SigningCertificateLineage(this.mMinSdkVersion, lineageCopy);
        }
    }

    public int size() {
        return this.mSigningLineage.size();
    }

    private SignatureAlgorithm getSignatureAlgorithm(SignerConfig parent) throws InvalidKeyException {
        return V3SchemeSigner.getSuggestedSignatureAlgorithms(parent.getCertificate().getPublicKey(), this.mMinSdkVersion, false).get(0);
    }

    private SigningCertificateLineage spawnFirstDescendant(SignerConfig parent, SignerCapabilities signerCapabilities) {
        if (!this.mSigningLineage.isEmpty()) {
            throw new IllegalStateException("SigningCertificateLineage already has its first node");
        }
        try {
            getSignatureAlgorithm(parent);
            return new SigningCertificateLineage(this.mMinSdkVersion, Collections.singletonList(new V3SigningCertificateLineage.SigningCertificateNode(parent.getCertificate(), null, null, new byte[0], signerCapabilities.getFlags())));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Algorithm associated with first signing certificate invalid on desired platform versions", e);
        }
    }

    private static SigningCertificateLineage read(ByteBuffer inputByteBuffer) throws IOException {
        ApkSigningBlockUtils.checkByteOrderLittleEndian(inputByteBuffer);
        if (inputByteBuffer.remaining() < 8) {
            throw new IllegalArgumentException("Improper SigningCertificateLineage format: insufficient data for header.");
        } else if (inputByteBuffer.getInt() == 1056913873) {
            return read(inputByteBuffer, inputByteBuffer.getInt());
        } else {
            throw new IllegalArgumentException("Improper SigningCertificateLineage format: MAGIC header mismatch.");
        }
    }

    private static SigningCertificateLineage read(ByteBuffer inputByteBuffer, int version) throws IOException {
        switch (version) {
            case 1:
                try {
                    List<V3SigningCertificateLineage.SigningCertificateNode> nodes = V3SigningCertificateLineage.readSigningCertificateLineage(ApkSigningBlockUtils.getLengthPrefixedSlice(inputByteBuffer));
                    return new SigningCertificateLineage(calculateMinSdkVersion(nodes), nodes);
                } catch (ApkFormatException e) {
                    throw new IOException("Unable to read list of signing certificate nodes in SigningCertificateLineage", e);
                }
            default:
                throw new IllegalArgumentException("Improper SigningCertificateLineage format: unrecognized version.");
        }
    }

    private static int calculateMinSdkVersion(List<V3SigningCertificateLineage.SigningCertificateNode> nodes) {
        int nodeMinSdkVersion;
        if (nodes == null) {
            throw new IllegalArgumentException("Can't calculate minimum SDK version of null nodes");
        }
        int minSdkVersion = 28;
        for (V3SigningCertificateLineage.SigningCertificateNode node : nodes) {
            if (node.sigAlgorithm != null && (nodeMinSdkVersion = node.sigAlgorithm.getMinSdkVersion()) > minSdkVersion) {
                minSdkVersion = nodeMinSdkVersion;
            }
        }
        return minSdkVersion;
    }

    private ByteBuffer write() {
        byte[] encodedLineage = V3SigningCertificateLineage.encodeSigningCertificateLineage(this.mSigningLineage);
        ByteBuffer result = ByteBuffer.allocate(encodedLineage.length + 12);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(MAGIC);
        result.putInt(1);
        result.putInt(encodedLineage.length);
        result.put(encodedLineage);
        result.flip();
        return result;
    }

    public byte[] encodeSigningCertificateLineage() {
        return V3SigningCertificateLineage.encodeSigningCertificateLineage(this.mSigningLineage);
    }

    public List<DefaultApkSignerEngine.SignerConfig> sortSignerConfigs(List<DefaultApkSignerEngine.SignerConfig> signerConfigs) {
        if (signerConfigs == null) {
            throw new NullPointerException("signerConfigs == null");
        }
        List<DefaultApkSignerEngine.SignerConfig> sortedSignerConfigs = new ArrayList<>(signerConfigs.size());
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            int j = 0;
            while (true) {
                if (j >= signerConfigs.size()) {
                    break;
                }
                DefaultApkSignerEngine.SignerConfig config = signerConfigs.get(j);
                if (this.mSigningLineage.get(i).signingCert.equals(config.getCertificates().get(0))) {
                    sortedSignerConfigs.add(config);
                    break;
                }
                j++;
            }
        }
        if (sortedSignerConfigs.size() == signerConfigs.size()) {
            return sortedSignerConfigs;
        }
        throw new IllegalArgumentException("SignerConfigs supplied which are not present in the SigningCertificateLineage");
    }

    public SignerCapabilities getSignerCapabilities(SignerConfig config) {
        if (config != null) {
            return getSignerCapabilities(config.getCertificate());
        }
        throw new NullPointerException("config == null");
    }

    public SignerCapabilities getSignerCapabilities(X509Certificate cert) {
        if (cert == null) {
            throw new NullPointerException("cert == null");
        }
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            V3SigningCertificateLineage.SigningCertificateNode lineageNode = this.mSigningLineage.get(i);
            if (lineageNode.signingCert.equals(cert)) {
                return new SignerCapabilities.Builder(lineageNode.flags).build();
            }
        }
        throw new IllegalArgumentException("Certificate (" + cert.getSubjectDN() + ") not found in the SigningCertificateLineage");
    }

    public void updateSignerCapabilities(SignerConfig config, SignerCapabilities capabilities) {
        if (config == null) {
            throw new NullPointerException("config == null");
        }
        X509Certificate cert = config.getCertificate();
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            V3SigningCertificateLineage.SigningCertificateNode lineageNode = this.mSigningLineage.get(i);
            if (lineageNode.signingCert.equals(cert)) {
                lineageNode.flags = new SignerCapabilities.Builder(lineageNode.flags).setCallerConfiguredCapabilities(capabilities).build().getFlags();
                return;
            }
        }
        throw new IllegalArgumentException("Certificate (" + cert.getSubjectDN() + ") not found in the SigningCertificateLineage");
    }

    public List<X509Certificate> getCertificatesInLineage() {
        List<X509Certificate> certs = new ArrayList<>();
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            certs.add(this.mSigningLineage.get(i).signingCert);
        }
        return certs;
    }

    public boolean isSignerInLineage(SignerConfig config) {
        if (config != null) {
            return isCertificateInLineage(config.getCertificate());
        }
        throw new NullPointerException("config == null");
    }

    public boolean isCertificateInLineage(X509Certificate cert) {
        if (cert == null) {
            throw new NullPointerException("cert == null");
        }
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            if (this.mSigningLineage.get(i).signingCert.equals(cert)) {
                return true;
            }
        }
        return false;
    }

    /* access modifiers changed from: private */
    public static int calculateDefaultFlags() {
        return 23;
    }

    public SigningCertificateLineage getSubLineage(X509Certificate x509Certificate) {
        if (x509Certificate == null) {
            throw new NullPointerException("x509Certificate == null");
        }
        for (int i = 0; i < this.mSigningLineage.size(); i++) {
            if (this.mSigningLineage.get(i).signingCert.equals(x509Certificate)) {
                return new SigningCertificateLineage(this.mMinSdkVersion, new ArrayList(this.mSigningLineage.subList(0, i + 1)));
            }
        }
        throw new IllegalArgumentException("Certificate not found in SigningCertificateLineage");
    }

    public static SigningCertificateLineage consolidateLineages(List<SigningCertificateLineage> lineages) {
        if (lineages == null || lineages.isEmpty()) {
            return null;
        }
        int largestIndex = 0;
        int maxSize = 0;
        for (int i = 0; i < lineages.size(); i++) {
            int curSize = lineages.get(i).size();
            if (curSize > maxSize) {
                largestIndex = i;
                maxSize = curSize;
            }
        }
        List<V3SigningCertificateLineage.SigningCertificateNode> largestList = lineages.get(largestIndex).mSigningLineage;
        for (int i2 = 0; i2 < lineages.size(); i2++) {
            if (i2 != largestIndex) {
                List<V3SigningCertificateLineage.SigningCertificateNode> underTest = lineages.get(i2).mSigningLineage;
                if (!underTest.equals(largestList.subList(0, underTest.size()))) {
                    throw new IllegalArgumentException("Inconsistent SigningCertificateLineages. Not all lineages are subsets of each other.");
                }
            }
        }
        return lineages.get(largestIndex);
    }

    public static class SignerCapabilities {
        private final int mCallerConfiguredFlags;
        private final int mFlags;

        private SignerCapabilities(int flags) {
            this(flags, 0);
        }

        private SignerCapabilities(int flags, int callerConfiguredFlags) {
            this.mFlags = flags;
            this.mCallerConfiguredFlags = callerConfiguredFlags;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private int getFlags() {
            return this.mFlags;
        }

        public boolean equals(SignerCapabilities other) {
            return this.mFlags == other.mFlags;
        }

        public boolean hasInstalledData() {
            return (this.mFlags & 1) != 0;
        }

        public boolean hasSharedUid() {
            return (this.mFlags & 2) != 0;
        }

        public boolean hasPermission() {
            return (this.mFlags & 4) != 0;
        }

        public boolean hasRollback() {
            return (this.mFlags & 8) != 0;
        }

        public boolean hasAuth() {
            return (this.mFlags & 16) != 0;
        }

        public static class Builder {
            private int mCallerConfiguredFlags;
            private int mFlags;

            public Builder() {
                this.mFlags = SigningCertificateLineage.calculateDefaultFlags();
            }

            public Builder(int flags) {
                this.mFlags = flags;
            }

            public Builder setInstalledData(boolean enabled) {
                this.mCallerConfiguredFlags |= 1;
                if (enabled) {
                    this.mFlags |= 1;
                } else {
                    this.mFlags &= -2;
                }
                return this;
            }

            public Builder setSharedUid(boolean enabled) {
                this.mCallerConfiguredFlags |= 2;
                if (enabled) {
                    this.mFlags |= 2;
                } else {
                    this.mFlags &= -3;
                }
                return this;
            }

            public Builder setPermission(boolean enabled) {
                this.mCallerConfiguredFlags |= 4;
                if (enabled) {
                    this.mFlags |= 4;
                } else {
                    this.mFlags &= -5;
                }
                return this;
            }

            public Builder setRollback(boolean enabled) {
                this.mCallerConfiguredFlags |= 8;
                if (enabled) {
                    this.mFlags |= 8;
                } else {
                    this.mFlags &= -9;
                }
                return this;
            }

            public Builder setAuth(boolean enabled) {
                this.mCallerConfiguredFlags |= 16;
                if (enabled) {
                    this.mFlags |= 16;
                } else {
                    this.mFlags &= -17;
                }
                return this;
            }

            public Builder setCallerConfiguredCapabilities(SignerCapabilities capabilities) {
                this.mFlags = (this.mFlags & (capabilities.mCallerConfiguredFlags ^ -1)) | (capabilities.mFlags & capabilities.mCallerConfiguredFlags);
                return this;
            }

            public SignerCapabilities build() {
                return new SignerCapabilities(this.mFlags, this.mCallerConfiguredFlags);
            }
        }
    }

    public static class SignerConfig {
        private final X509Certificate mCertificate;
        private final PrivateKey mPrivateKey;

        private SignerConfig(PrivateKey privateKey, X509Certificate certificate) {
            this.mPrivateKey = privateKey;
            this.mCertificate = certificate;
        }

        public PrivateKey getPrivateKey() {
            return this.mPrivateKey;
        }

        public X509Certificate getCertificate() {
            return this.mCertificate;
        }

        public static class Builder {
            private final X509Certificate mCertificate;
            private final PrivateKey mPrivateKey;

            public Builder(PrivateKey privateKey, X509Certificate certificate) {
                this.mPrivateKey = privateKey;
                this.mCertificate = certificate;
            }

            public SignerConfig build() {
                return new SignerConfig(this.mPrivateKey, this.mCertificate);
            }
        }
    }

    public static class Builder {
        private int mMinSdkVersion;
        private SignerCapabilities mNewCapabilities;
        private final SignerConfig mNewSignerConfig;
        private SignerCapabilities mOriginalCapabilities;
        private final SignerConfig mOriginalSignerConfig;

        public Builder(SignerConfig originalSignerConfig, SignerConfig newSignerConfig) {
            if (originalSignerConfig == null || newSignerConfig == null) {
                throw new NullPointerException("Can't pass null SignerConfigs when constructing a new SigningCertificateLineage");
            }
            this.mOriginalSignerConfig = originalSignerConfig;
            this.mNewSignerConfig = newSignerConfig;
        }

        public Builder setMinSdkVersion(int minSdkVersion) {
            this.mMinSdkVersion = minSdkVersion;
            return this;
        }

        public Builder setOriginalCapabilities(SignerCapabilities signerCapabilities) {
            if (signerCapabilities == null) {
                throw new NullPointerException("signerCapabilities == null");
            }
            this.mOriginalCapabilities = signerCapabilities;
            return this;
        }

        public Builder setNewCapabilities(SignerCapabilities signerCapabilities) {
            if (signerCapabilities == null) {
                throw new NullPointerException("signerCapabilities == null");
            }
            this.mNewCapabilities = signerCapabilities;
            return this;
        }

        public SigningCertificateLineage build() throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
            if (this.mMinSdkVersion < 28) {
                this.mMinSdkVersion = 28;
            }
            if (this.mOriginalCapabilities == null) {
                this.mOriginalCapabilities = new SignerCapabilities.Builder().build();
            }
            if (this.mNewCapabilities == null) {
                this.mNewCapabilities = new SignerCapabilities.Builder().build();
            }
            return SigningCertificateLineage.createSigningLineage(this.mMinSdkVersion, this.mOriginalSignerConfig, this.mOriginalCapabilities, this.mNewSignerConfig, this.mNewCapabilities);
        }
    }
}
