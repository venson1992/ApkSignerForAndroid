package com.android.apksig;

import com.android.apksig.ApkSignerEngine;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.apk.ContentDigestAlgorithm;
import com.android.apksig.internal.apk.SignatureAlgorithm;
import com.android.apksig.internal.apk.stamp.V2SourceStampSigner;
import com.android.apksig.internal.apk.v1.DigestAlgorithm;
import com.android.apksig.internal.apk.v1.V1SchemeSigner;
import com.android.apksig.internal.apk.v1.V1SchemeVerifier;
import com.android.apksig.internal.apk.v2.V2SchemeSigner;
import com.android.apksig.internal.apk.v3.V3SchemeSigner;
import com.android.apksig.internal.apk.v4.V4SchemeSigner;
import com.android.apksig.internal.apk.v4.V4Signature;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.jar.ManifestParser;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.TeeDataSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DefaultApkSignerEngine implements ApkSignerEngine {
    private OutputApkSigningBlockRequestImpl mAddSigningBlockRequest;
    private OutputJarSignatureRequestImpl mAddV1SignatureRequest;
    private boolean mClosed;
    private final String mCreatedBy;
    private Boolean mDebuggable;
    private final boolean mDebuggableApkPermitted;
    private final Map<String, byte[]> mEmittedSignatureJarEntryData;
    private RunnablesExecutor mExecutor;
    private GetJarEntryDataRequest mInputJarManifestEntryDataRequest;
    private final int mMinSdkVersion;
    private final boolean mOtherSignersSignaturesPreserved;
    private GetJarEntryDataRequest mOutputAndroidManifestEntryDataRequest;
    private final Map<String, GetJarEntryDataDigestRequest> mOutputJarEntryDigestRequests;
    private final Map<String, byte[]> mOutputJarEntryDigests;
    private final Map<String, GetJarEntryDataRequest> mOutputSignatureJarEntryDataRequests;
    private Set<String> mSignatureExpectedOutputJarEntryNames;
    private final List<SignerConfig> mSignerConfigs;
    private final SigningCertificateLineage mSigningCertificateLineage;
    private final SignerConfig mSourceStampSignerConfig;
    private final SigningCertificateLineage mSourceStampSigningCertificateLineage;
    private DigestAlgorithm mV1ContentDigestAlgorithm;
    private boolean mV1SignaturePending;
    private List<V1SchemeSigner.SignerConfig> mV1SignerConfigs;
    private final boolean mV1SigningEnabled;
    private boolean mV2SignaturePending;
    private final boolean mV2SigningEnabled;
    private boolean mV3SignaturePending;
    private final boolean mV3SigningEnabled;
    private final boolean mVerityEnabled;

    private DefaultApkSignerEngine(List<SignerConfig> signerConfigs, SignerConfig sourceStampSignerConfig, SigningCertificateLineage sourceStampSigningCertificateLineage, int minSdkVersion, boolean v1SigningEnabled, boolean v2SigningEnabled, boolean v3SigningEnabled, boolean verityEnabled, boolean debuggableApkPermitted, boolean otherSignersSignaturesPreserved, String createdBy, SigningCertificateLineage signingCertificateLineage) throws InvalidKeyException {
        this.mV1SignerConfigs = Collections.emptyList();
        this.mSignatureExpectedOutputJarEntryNames = Collections.emptySet();
        this.mOutputJarEntryDigestRequests = new HashMap();
        this.mOutputJarEntryDigests = new HashMap();
        this.mEmittedSignatureJarEntryData = new HashMap();
        this.mOutputSignatureJarEntryDataRequests = new HashMap();
        this.mExecutor = RunnablesExecutor.MULTI_THREADED;
        if (signerConfigs.isEmpty()) {
            throw new IllegalArgumentException("At least one signer config must be provided");
        } else if (otherSignersSignaturesPreserved) {
            throw new UnsupportedOperationException("Preserving other signer's signatures is not yet implemented");
        } else {
            this.mV1SigningEnabled = v1SigningEnabled;
            this.mV2SigningEnabled = v2SigningEnabled;
            this.mV3SigningEnabled = v3SigningEnabled;
            this.mVerityEnabled = verityEnabled;
            this.mV1SignaturePending = v1SigningEnabled;
            this.mV2SignaturePending = v2SigningEnabled;
            this.mV3SignaturePending = v3SigningEnabled;
            this.mDebuggableApkPermitted = debuggableApkPermitted;
            this.mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
            this.mCreatedBy = createdBy;
            this.mSignerConfigs = signerConfigs;
            this.mSourceStampSignerConfig = sourceStampSignerConfig;
            this.mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
            this.mMinSdkVersion = minSdkVersion;
            this.mSigningCertificateLineage = signingCertificateLineage;
            if (!v1SigningEnabled) {
                return;
            }
            if (v3SigningEnabled) {
                SignerConfig oldestConfig = signerConfigs.get(0);
                if (signingCertificateLineage == null || signingCertificateLineage.getSubLineage((X509Certificate) oldestConfig.mCertificates.get(0)).size() == 1) {
                    createV1SignerConfigs(Collections.singletonList(oldestConfig), minSdkVersion);
                    return;
                }
                throw new IllegalArgumentException("v1 signing enabled but the oldest signer in the SigningCertificateLineage is missing.  Please provide the oldest signer to enable v1 signing");
            }
            createV1SignerConfigs(signerConfigs, minSdkVersion);
        }
    }

    private void createV1SignerConfigs(List<SignerConfig> signerConfigs, int minSdkVersion) throws InvalidKeyException {
        this.mV1SignerConfigs = new ArrayList(signerConfigs.size());
        Map<String, Integer> v1SignerNameToSignerIndex = new HashMap<>(signerConfigs.size());
        DigestAlgorithm v1ContentDigestAlgorithm = null;
        for (int i = 0; i < signerConfigs.size(); i++) {
            SignerConfig signerConfig = signerConfigs.get(i);
            List<X509Certificate> certificates = signerConfig.getCertificates();
            PublicKey publicKey = certificates.get(0).getPublicKey();
            String v1SignerName = V1SchemeSigner.getSafeSignerName(signerConfig.getName());
            Integer indexOfOtherSignerWithSameName = v1SignerNameToSignerIndex.put(v1SignerName, Integer.valueOf(i));
            if (indexOfOtherSignerWithSameName != null) {
                throw new IllegalArgumentException("Signers #" + (indexOfOtherSignerWithSameName.intValue() + 1) + " and #" + (i + 1) + " have the same name: " + v1SignerName + ". v1 signer names must be unique");
            }
            DigestAlgorithm v1SignatureDigestAlgorithm = V1SchemeSigner.getSuggestedSignatureDigestAlgorithm(publicKey, minSdkVersion);
            V1SchemeSigner.SignerConfig v1SignerConfig = new V1SchemeSigner.SignerConfig();
            v1SignerConfig.name = v1SignerName;
            v1SignerConfig.privateKey = signerConfig.getPrivateKey();
            v1SignerConfig.certificates = certificates;
            v1SignerConfig.signatureDigestAlgorithm = v1SignatureDigestAlgorithm;
            if (v1ContentDigestAlgorithm == null) {
                v1ContentDigestAlgorithm = v1SignatureDigestAlgorithm;
            } else if (DigestAlgorithm.BY_STRENGTH_COMPARATOR.compare(v1SignatureDigestAlgorithm, v1ContentDigestAlgorithm) > 0) {
                v1ContentDigestAlgorithm = v1SignatureDigestAlgorithm;
            }
            this.mV1SignerConfigs.add(v1SignerConfig);
        }
        this.mV1ContentDigestAlgorithm = v1ContentDigestAlgorithm;
        this.mSignatureExpectedOutputJarEntryNames = V1SchemeSigner.getOutputEntryNames(this.mV1SignerConfigs);
    }

    private List<ApkSigningBlockUtils.SignerConfig> createV2SignerConfigs(boolean apkSigningBlockPaddingSupported) throws InvalidKeyException {
        if (!this.mV3SigningEnabled) {
            return createSigningBlockSignerConfigs(apkSigningBlockPaddingSupported, 2);
        }
        List<ApkSigningBlockUtils.SignerConfig> signerConfig = new ArrayList<>();
        SignerConfig oldestConfig = this.mSignerConfigs.get(0);
        if (this.mSigningCertificateLineage == null || this.mSigningCertificateLineage.getSubLineage((X509Certificate) oldestConfig.mCertificates.get(0)).size() == 1) {
            signerConfig.add(createSigningBlockSignerConfig(this.mSignerConfigs.get(0), apkSigningBlockPaddingSupported, 2));
            return signerConfig;
        }
        throw new IllegalArgumentException("v2 signing enabled but the oldest signer in the SigningCertificateLineage is missing.  Please provide the oldest signer to enable v2 signing.");
    }

    private List<ApkSigningBlockUtils.SignerConfig> processV3Configs(List<ApkSigningBlockUtils.SignerConfig> rawConfigs) throws InvalidKeyException {
        List<ApkSigningBlockUtils.SignerConfig> processedConfigs = new ArrayList<>();
        int currentMinSdk = Integer.MAX_VALUE;
        for (int i = rawConfigs.size() - 1; i >= 0; i--) {
            ApkSigningBlockUtils.SignerConfig config = rawConfigs.get(i);
            if (config.signatureAlgorithms != null) {
                if (i == rawConfigs.size() - 1) {
                    config.maxSdkVersion = Integer.MAX_VALUE;
                } else {
                    config.maxSdkVersion = currentMinSdk - 1;
                }
                config.minSdkVersion = getMinSdkFromV3SignatureAlgorithms(config.signatureAlgorithms);
                if (this.mSigningCertificateLineage != null) {
                    config.mSigningCertificateLineage = this.mSigningCertificateLineage.getSubLineage(config.certificates.get(0));
                }
                processedConfigs.add(config);
                currentMinSdk = config.minSdkVersion;
                if (currentMinSdk <= this.mMinSdkVersion || currentMinSdk <= 28) {
                    break;
                }
            } else {
                throw new InvalidKeyException("Unsupported key algorithm " + config.certificates.get(0).getPublicKey().getAlgorithm() + " is not supported for APK Signature Scheme v3 signing");
            }
        }
        if (currentMinSdk <= 28 || currentMinSdk <= this.mMinSdkVersion) {
            return processedConfigs;
        }
        throw new InvalidKeyException("Provided key algorithms not supported on all desired Android SDK versions");
    }

    private List<ApkSigningBlockUtils.SignerConfig> createV3SignerConfigs(boolean apkSigningBlockPaddingSupported) throws InvalidKeyException {
        return processV3Configs(createSigningBlockSignerConfigs(apkSigningBlockPaddingSupported, 3));
    }

    private ApkSigningBlockUtils.SignerConfig createV4SignerConfig() throws InvalidKeyException {
        List<ApkSigningBlockUtils.SignerConfig> configs = createSigningBlockSignerConfigs(true, 4);
        if (configs.size() != 1) {
            configs = processV3Configs(configs);
        }
        if (configs.size() == 1) {
            return configs.get(0);
        }
        throw new InvalidKeyException("Only accepting one signer config for V4 Signature.");
    }

    private ApkSigningBlockUtils.SignerConfig createSourceStampSignerConfig() throws InvalidKeyException {
        ApkSigningBlockUtils.SignerConfig config = createSigningBlockSignerConfig(this.mSourceStampSignerConfig, false, 0);
        if (this.mSourceStampSigningCertificateLineage != null) {
            config.mSigningCertificateLineage = this.mSourceStampSigningCertificateLineage.getSubLineage(config.certificates.get(0));
        }
        return config;
    }

    private int getMinSdkFromV3SignatureAlgorithms(List<SignatureAlgorithm> algorithms) {
        int min = Integer.MAX_VALUE;
        for (SignatureAlgorithm algorithm : algorithms) {
            int current = algorithm.getMinSdkVersion();
            if (current < min) {
                if (current <= this.mMinSdkVersion || current <= 28) {
                    return current;
                }
                min = current;
            }
        }
        return min;
    }

    private List<ApkSigningBlockUtils.SignerConfig> createSigningBlockSignerConfigs(boolean apkSigningBlockPaddingSupported, int schemeId) throws InvalidKeyException {
        List<ApkSigningBlockUtils.SignerConfig> signerConfigs = new ArrayList<>(this.mSignerConfigs.size());
        for (int i = 0; i < this.mSignerConfigs.size(); i++) {
            signerConfigs.add(createSigningBlockSignerConfig(this.mSignerConfigs.get(i), apkSigningBlockPaddingSupported, schemeId));
        }
        return signerConfigs;
    }

    private ApkSigningBlockUtils.SignerConfig createSigningBlockSignerConfig(SignerConfig signerConfig, boolean apkSigningBlockPaddingSupported, int schemeId) throws InvalidKeyException {
        boolean z = true;
        List<X509Certificate> certificates = signerConfig.getCertificates();
        PublicKey publicKey = certificates.get(0).getPublicKey();
        ApkSigningBlockUtils.SignerConfig newSignerConfig = new ApkSigningBlockUtils.SignerConfig();
        newSignerConfig.privateKey = signerConfig.getPrivateKey();
        newSignerConfig.certificates = certificates;
        switch (schemeId) {
            case BerEncoding.TAG_CLASS_UNIVERSAL /*{ENCODED_INT: 0}*/:
                newSignerConfig.signatureAlgorithms = Collections.singletonList(SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256);
                break;
            case 1:
            default:
                throw new IllegalArgumentException("Unknown APK Signature Scheme ID requested");
            case 2:
                newSignerConfig.signatureAlgorithms = V2SchemeSigner.getSuggestedSignatureAlgorithms(publicKey, this.mMinSdkVersion, apkSigningBlockPaddingSupported && this.mVerityEnabled);
                break;
            case 3:
                try {
                    int i = this.mMinSdkVersion;
                    if (!apkSigningBlockPaddingSupported || !this.mVerityEnabled) {
                        z = false;
                    }
                    newSignerConfig.signatureAlgorithms = V3SchemeSigner.getSuggestedSignatureAlgorithms(publicKey, i, z);
                    break;
                } catch (InvalidKeyException e) {
                    newSignerConfig.signatureAlgorithms = null;
                    break;
                }
            case 4:
                try {
                    newSignerConfig.signatureAlgorithms = V4SchemeSigner.getSuggestedSignatureAlgorithms(publicKey, this.mMinSdkVersion, apkSigningBlockPaddingSupported);
                    break;
                } catch (InvalidKeyException e2) {
                    newSignerConfig.signatureAlgorithms = null;
                    break;
                }
        }
        return newSignerConfig;
    }

    private boolean isDebuggable(String entryName) {
        return this.mDebuggableApkPermitted || !ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.equals(entryName);
    }

    @Override // com.android.apksig.ApkSignerEngine
    public Set<String> initWith(byte[] manifestBytes, Set<String> entryNames) {
        Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> sections = V1SchemeVerifier.parseManifest(manifestBytes, entryNames, new V1SchemeVerifier.Result());
        String alg = V1SchemeSigner.getJcaMessageDigestAlgorithm(this.mV1ContentDigestAlgorithm);
        for (Map.Entry<String, ManifestParser.Section> entry : sections.getSecond().entrySet()) {
            String entryName = entry.getKey();
            if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entry.getKey()) && isDebuggable(entryName)) {
                V1SchemeVerifier.NamedDigest extractedDigest = null;
                Iterator<V1SchemeVerifier.NamedDigest> it = V1SchemeVerifier.getDigestsToVerify(entry.getValue(), "-Digest", this.mMinSdkVersion, Integer.MAX_VALUE).iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    V1SchemeVerifier.NamedDigest digestToVerify = it.next();
                    if (digestToVerify.jcaDigestAlgorithm.equals(alg)) {
                        extractedDigest = digestToVerify;
                        break;
                    }
                }
                if (extractedDigest != null) {
                    this.mOutputJarEntryDigests.put(entryName, extractedDigest.digest);
                }
            }
        }
        return this.mOutputJarEntryDigests.keySet();
    }

    @Override // com.android.apksig.ApkSignerEngine
    public void setExecutor(RunnablesExecutor executor) {
        this.mExecutor = executor;
    }

    @Override // com.android.apksig.ApkSignerEngine
    public void inputApkSigningBlock(DataSource apkSigningBlock) {
        checkNotClosed();
        if (apkSigningBlock == null || apkSigningBlock.size() == 0 || this.mOtherSignersSignaturesPreserved) {
        }
    }

    @Override // com.android.apksig.ApkSignerEngine
    public ApkSignerEngine.InputJarEntryInstructions inputJarEntry(String entryName) {
        checkNotClosed();
        ApkSignerEngine.InputJarEntryInstructions.OutputPolicy outputPolicy = getInputJarEntryOutputPolicy(entryName);
        switch (outputPolicy) {
            case SKIP:
                return new ApkSignerEngine.InputJarEntryInstructions(ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.SKIP);
            case OUTPUT:
                return new ApkSignerEngine.InputJarEntryInstructions(ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT);
            case OUTPUT_BY_ENGINE:
                if (!"META-INF/MANIFEST.MF".equals(entryName)) {
                    return new ApkSignerEngine.InputJarEntryInstructions(ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE);
                }
                this.mInputJarManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
                return new ApkSignerEngine.InputJarEntryInstructions(ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE, this.mInputJarManifestEntryDataRequest);
            default:
                throw new RuntimeException("Unsupported output policy: " + outputPolicy);
        }
    }

    @Override // com.android.apksig.ApkSignerEngine
    public ApkSignerEngine.InspectJarEntryRequest outputJarEntry(String entryName) {
        GetJarEntryDataRequest dataRequest;
        checkNotClosed();
        invalidateV2Signature();
        if (!isDebuggable(entryName)) {
            forgetOutputApkDebuggableStatus();
        }
        if (!this.mV1SigningEnabled) {
            if (isDebuggable(entryName)) {
                return null;
            }
            this.mOutputAndroidManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
            return this.mOutputAndroidManifestEntryDataRequest;
        } else if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName)) {
            invalidateV1Signature();
            GetJarEntryDataDigestRequest dataDigestRequest = new GetJarEntryDataDigestRequest(entryName, V1SchemeSigner.getJcaMessageDigestAlgorithm(this.mV1ContentDigestAlgorithm));
            this.mOutputJarEntryDigestRequests.put(entryName, dataDigestRequest);
            this.mOutputJarEntryDigests.remove(entryName);
            if (this.mDebuggableApkPermitted || !ApkUtils.ANDROID_MANIFEST_ZIP_ENTRY_NAME.equals(entryName)) {
                return dataDigestRequest;
            }
            this.mOutputAndroidManifestEntryDataRequest = new GetJarEntryDataRequest(entryName);
            return new CompoundInspectJarEntryRequest(entryName, new ApkSignerEngine.InspectJarEntryRequest[]{this.mOutputAndroidManifestEntryDataRequest, dataDigestRequest});
        } else if (!this.mSignatureExpectedOutputJarEntryNames.contains(entryName)) {
            return null;
        } else {
            invalidateV1Signature();
            if ("META-INF/MANIFEST.MF".equals(entryName)) {
                dataRequest = new GetJarEntryDataRequest(entryName);
                this.mInputJarManifestEntryDataRequest = dataRequest;
            } else if (this.mEmittedSignatureJarEntryData.containsKey(entryName)) {
                dataRequest = new GetJarEntryDataRequest(entryName);
            } else {
                dataRequest = null;
            }
            if (dataRequest != null) {
                this.mOutputSignatureJarEntryDataRequests.put(entryName, dataRequest);
            }
            return dataRequest;
        }
    }

    @Override // com.android.apksig.ApkSignerEngine
    public ApkSignerEngine.InputJarEntryInstructions.OutputPolicy inputJarEntryRemoved(String entryName) {
        checkNotClosed();
        return getInputJarEntryOutputPolicy(entryName);
    }

    @Override // com.android.apksig.ApkSignerEngine
    public void outputJarEntryRemoved(String entryName) {
        checkNotClosed();
        invalidateV2Signature();
        if (this.mV1SigningEnabled) {
            if (V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName)) {
                invalidateV1Signature();
                this.mOutputJarEntryDigests.remove(entryName);
                this.mOutputJarEntryDigestRequests.remove(entryName);
                this.mOutputSignatureJarEntryDataRequests.remove(entryName);
            } else if (this.mSignatureExpectedOutputJarEntryNames.contains(entryName)) {
                invalidateV1Signature();
            }
        }
    }

    @Override // com.android.apksig.ApkSignerEngine
    public ApkSignerEngine.OutputJarSignatureRequest outputJarEntries() throws ApkFormatException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        byte[] inputJarManifest;
        List<Pair<String, byte[]>> signatureZipEntries;
        checkNotClosed();
        if (!this.mV1SignaturePending) {
            return null;
        }
        if (this.mInputJarManifestEntryDataRequest == null || this.mInputJarManifestEntryDataRequest.isDone()) {
            for (GetJarEntryDataDigestRequest digestRequest : this.mOutputJarEntryDigestRequests.values()) {
                String entryName = digestRequest.getEntryName();
                if (!digestRequest.isDone()) {
                    throw new IllegalStateException("Still waiting to inspect output APK's " + entryName);
                }
                this.mOutputJarEntryDigests.put(entryName, digestRequest.getDigest());
            }
            if (isEligibleForSourceStamp()) {
                MessageDigest messageDigest = MessageDigest.getInstance(V1SchemeSigner.getJcaMessageDigestAlgorithm(this.mV1ContentDigestAlgorithm));
                messageDigest.update(generateSourceStampCertificateDigest());
                this.mOutputJarEntryDigests.put("stamp-cert-sha256", messageDigest.digest());
            }
            this.mOutputJarEntryDigestRequests.clear();
            for (GetJarEntryDataRequest dataRequest : this.mOutputSignatureJarEntryDataRequests.values()) {
                if (!dataRequest.isDone()) {
                    throw new IllegalStateException("Still waiting to inspect output APK's " + dataRequest.getEntryName());
                }
            }
            List<Integer> apkSigningSchemeIds = new ArrayList<>();
            if (this.mV2SigningEnabled) {
                apkSigningSchemeIds.add(2);
            }
            if (this.mV3SigningEnabled) {
                apkSigningSchemeIds.add(3);
            }
            if (this.mInputJarManifestEntryDataRequest != null) {
                inputJarManifest = this.mInputJarManifestEntryDataRequest.getData();
            } else {
                inputJarManifest = null;
            }
            if (isEligibleForSourceStamp()) {
                inputJarManifest = V1SchemeSigner.generateManifestFile(this.mV1ContentDigestAlgorithm, this.mOutputJarEntryDigests, inputJarManifest).contents;
            }
            checkOutputApkNotDebuggableIfDebuggableMustBeRejected();
            if (this.mAddV1SignatureRequest == null || !this.mAddV1SignatureRequest.isDone()) {
                try {
                    signatureZipEntries = V1SchemeSigner.sign(this.mV1SignerConfigs, this.mV1ContentDigestAlgorithm, this.mOutputJarEntryDigests, apkSigningSchemeIds, inputJarManifest, this.mCreatedBy);
                } catch (CertificateException e) {
                    throw new SignatureException("Failed to generate v1 signature", e);
                }
            } else {
                V1SchemeSigner.OutputManifestFile newManifest = V1SchemeSigner.generateManifestFile(this.mV1ContentDigestAlgorithm, this.mOutputJarEntryDigests, inputJarManifest);
                if (!Arrays.equals(newManifest.contents, this.mEmittedSignatureJarEntryData.get("META-INF/MANIFEST.MF"))) {
                    try {
                        signatureZipEntries = V1SchemeSigner.signManifest(this.mV1SignerConfigs, this.mV1ContentDigestAlgorithm, apkSigningSchemeIds, this.mCreatedBy, newManifest);
                    } catch (CertificateException e2) {
                        throw new SignatureException("Failed to generate v1 signature", e2);
                    }
                } else {
                    signatureZipEntries = new ArrayList<>();
                    for (Map.Entry<String, byte[]> expectedOutputEntry : this.mEmittedSignatureJarEntryData.entrySet()) {
                        String entryName2 = expectedOutputEntry.getKey();
                        byte[] expectedData = expectedOutputEntry.getValue();
                        GetJarEntryDataRequest actualDataRequest = this.mOutputSignatureJarEntryDataRequests.get(entryName2);
                        if (actualDataRequest == null) {
                            signatureZipEntries.add(Pair.of(entryName2, expectedData));
                        } else if (!Arrays.equals(expectedData, actualDataRequest.getData())) {
                            signatureZipEntries.add(Pair.of(entryName2, expectedData));
                        }
                    }
                    if (signatureZipEntries.isEmpty()) {
                        return null;
                    }
                }
            }
            if (signatureZipEntries.isEmpty()) {
                this.mV1SignaturePending = false;
                return null;
            }
            List<ApkSignerEngine.OutputJarSignatureRequest.JarEntry> sigEntries = new ArrayList<>(signatureZipEntries.size());
            for (Pair<String, byte[]> entry : signatureZipEntries) {
                String entryName3 = entry.getFirst();
                byte[] entryData = entry.getSecond();
                sigEntries.add(new ApkSignerEngine.OutputJarSignatureRequest.JarEntry(entryName3, entryData));
                this.mEmittedSignatureJarEntryData.put(entryName3, entryData);
            }
            this.mAddV1SignatureRequest = new OutputJarSignatureRequestImpl(sigEntries);
            return this.mAddV1SignatureRequest;
        }
        throw new IllegalStateException("Still waiting to inspect input APK's " + this.mInputJarManifestEntryDataRequest.getEntryName());
    }

    @Override // com.android.apksig.ApkSignerEngine
    @Deprecated
    public ApkSignerEngine.OutputApkSigningBlockRequest outputZipSections(DataSource zipEntries, DataSource zipCentralDirectory, DataSource zipEocd) throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        return outputZipSectionsInternal(zipEntries, zipCentralDirectory, zipEocd, false);
    }

    @Override // com.android.apksig.ApkSignerEngine
    public ApkSignerEngine.OutputApkSigningBlockRequest2 outputZipSections2(DataSource zipEntries, DataSource zipCentralDirectory, DataSource zipEocd) throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        return outputZipSectionsInternal(zipEntries, zipCentralDirectory, zipEocd, true);
    }

    private OutputApkSigningBlockRequestImpl outputZipSectionsInternal(DataSource zipEntries, DataSource zipCentralDirectory, DataSource zipEocd, boolean apkSigningBlockPaddingSupported) throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        byte[] inputJarManifest;
        checkNotClosed();
        checkV1SigningDoneIfEnabled();
        if (!this.mV2SigningEnabled && !this.mV3SigningEnabled && !isEligibleForSourceStamp()) {
            return null;
        }
        checkOutputApkNotDebuggableIfDebuggableMustBeRejected();
        Pair<DataSource, Integer> paddingPair = ApkSigningBlockUtils.generateApkSigningBlockPadding(zipEntries, apkSigningBlockPaddingSupported);
        DataSource beforeCentralDir = paddingPair.getFirst();
        int padSizeBeforeApkSigningBlock = paddingPair.getSecond().intValue();
        DataSource eocd = ApkSigningBlockUtils.copyWithModifiedCDOffset(beforeCentralDir, zipEocd);
        List<Pair<byte[], Integer>> signingSchemeBlocks = new ArrayList<>();
        ApkSigningBlockUtils.SigningSchemeBlockAndDigests v2SigningSchemeBlockAndDigests = null;
        ApkSigningBlockUtils.SigningSchemeBlockAndDigests v3SigningSchemeBlockAndDigests = null;
        if (this.mV2SigningEnabled) {
            invalidateV2Signature();
            v2SigningSchemeBlockAndDigests = V2SchemeSigner.generateApkSignatureSchemeV2Block(this.mExecutor, beforeCentralDir, zipCentralDirectory, eocd, createV2SignerConfigs(apkSigningBlockPaddingSupported), this.mV3SigningEnabled);
            signingSchemeBlocks.add(v2SigningSchemeBlockAndDigests.signingSchemeBlock);
        }
        if (this.mV3SigningEnabled) {
            invalidateV3Signature();
            v3SigningSchemeBlockAndDigests = V3SchemeSigner.generateApkSignatureSchemeV3Block(this.mExecutor, beforeCentralDir, zipCentralDirectory, eocd, createV3SignerConfigs(apkSigningBlockPaddingSupported));
            signingSchemeBlocks.add(v3SigningSchemeBlockAndDigests.signingSchemeBlock);
        }
        if (isEligibleForSourceStamp()) {
            ApkSigningBlockUtils.SignerConfig sourceStampSignerConfig = createSourceStampSignerConfig();
            Map<Integer, Map<ContentDigestAlgorithm, byte[]>> signatureSchemeDigestInfos = new HashMap<>();
            if (this.mV3SigningEnabled) {
                signatureSchemeDigestInfos.put(3, v3SigningSchemeBlockAndDigests.digestInfo);
            }
            if (this.mV2SigningEnabled) {
                signatureSchemeDigestInfos.put(2, v2SigningSchemeBlockAndDigests.digestInfo);
            }
            if (this.mV1SigningEnabled) {
                Map<ContentDigestAlgorithm, byte[]> v1SigningSchemeDigests = new HashMap<>();
                try {
                    if (this.mInputJarManifestEntryDataRequest != null) {
                        inputJarManifest = this.mInputJarManifestEntryDataRequest.getData();
                    } else {
                        inputJarManifest = null;
                    }
                    v1SigningSchemeDigests.put(ContentDigestAlgorithm.SHA256, ApkUtils.computeSha256DigestBytes(V1SchemeSigner.generateManifestFile(this.mV1ContentDigestAlgorithm, this.mOutputJarEntryDigests, inputJarManifest).contents));
                    signatureSchemeDigestInfos.put(1, v1SigningSchemeDigests);
                } catch (ApkFormatException e) {
                    throw new RuntimeException("Failed to generate manifest file", e);
                }
            }
            signingSchemeBlocks.add(V2SourceStampSigner.generateSourceStampBlock(sourceStampSignerConfig, signatureSchemeDigestInfos));
        }
        this.mAddSigningBlockRequest = new OutputApkSigningBlockRequestImpl(ApkSigningBlockUtils.generateApkSigningBlock(signingSchemeBlocks), padSizeBeforeApkSigningBlock);
        return this.mAddSigningBlockRequest;
    }

    @Override // com.android.apksig.ApkSignerEngine
    public void outputDone() {
        checkNotClosed();
        checkV1SigningDoneIfEnabled();
        checkSigningBlockDoneIfEnabled();
    }

    @Override // com.android.apksig.ApkSignerEngine
    public void signV4(DataSource dataSource, File outputFile, boolean ignoreFailures) throws SignatureException {
        Exception e;
        if (outputFile != null) {
            try {
                V4SchemeSigner.generateV4Signature(dataSource, createV4SignerConfig(), outputFile);
                return;
            } catch (InvalidKeyException e2) {
                e = e2;
            } catch (IOException e3) {
                e = e3;
            } catch (NoSuchAlgorithmException e4) {
                e = e4;
            }
        } else if (!ignoreFailures) {
            throw new SignatureException("Missing V4 output file.");
        } else {
            return;
        }
        if (!ignoreFailures) {
            throw new SignatureException("V4 signing failed", e);
        }
    }

    public byte[] produceV4Signature(DataSource dataSource, OutputStream sigOutput) throws SignatureException {
        if (sigOutput == null) {
            throw new SignatureException("Missing V4 output streams.");
        }
        try {
            Pair<V4Signature, byte[]> pair = V4SchemeSigner.generateV4Signature(dataSource, createV4SignerConfig());
            pair.getFirst().writeTo(sigOutput);
            return pair.getSecond();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SignatureException("V4 signing failed", e);
        }
    }

    @Override // com.android.apksig.ApkSignerEngine
    public boolean isEligibleForSourceStamp() {
        return this.mSourceStampSignerConfig != null && (this.mV2SigningEnabled || this.mV3SigningEnabled || this.mV1SigningEnabled);
    }

    @Override // com.android.apksig.ApkSignerEngine
    public byte[] generateSourceStampCertificateDigest() throws SignatureException {
        if (this.mSourceStampSignerConfig.getCertificates().isEmpty()) {
            throw new SignatureException("No certificates configured for stamp");
        }
        try {
            return ApkUtils.computeSha256DigestBytes(this.mSourceStampSignerConfig.getCertificates().get(0).getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SignatureException("Failed to encode source stamp certificate", e);
        }
    }

    @Override // java.io.Closeable, com.android.apksig.ApkSignerEngine, java.lang.AutoCloseable
    public void close() {
        this.mClosed = true;
        this.mAddV1SignatureRequest = null;
        this.mInputJarManifestEntryDataRequest = null;
        this.mOutputAndroidManifestEntryDataRequest = null;
        this.mDebuggable = null;
        this.mOutputJarEntryDigestRequests.clear();
        this.mOutputJarEntryDigests.clear();
        this.mEmittedSignatureJarEntryData.clear();
        this.mOutputSignatureJarEntryDataRequests.clear();
        this.mAddSigningBlockRequest = null;
    }

    private void invalidateV1Signature() {
        if (this.mV1SigningEnabled) {
            this.mV1SignaturePending = true;
        }
        invalidateV2Signature();
    }

    private void invalidateV2Signature() {
        if (this.mV2SigningEnabled) {
            this.mV2SignaturePending = true;
            this.mAddSigningBlockRequest = null;
        }
    }

    private void invalidateV3Signature() {
        if (this.mV3SigningEnabled) {
            this.mV3SignaturePending = true;
            this.mAddSigningBlockRequest = null;
        }
    }

    private void checkNotClosed() {
        if (this.mClosed) {
            throw new IllegalStateException("Engine closed");
        }
    }

    private void checkV1SigningDoneIfEnabled() {
        if (this.mV1SignaturePending) {
            if (this.mAddV1SignatureRequest == null) {
                throw new IllegalStateException("v1 signature (JAR signature) not yet generated. Skipped outputJarEntries()?");
            } else if (!this.mAddV1SignatureRequest.isDone()) {
                throw new IllegalStateException("v1 signature (JAR signature) addition requested by outputJarEntries() hasn't been fulfilled");
            } else {
                for (Map.Entry<String, byte[]> expectedOutputEntry : this.mEmittedSignatureJarEntryData.entrySet()) {
                    String entryName = expectedOutputEntry.getKey();
                    byte[] expectedData = expectedOutputEntry.getValue();
                    GetJarEntryDataRequest actualDataRequest = this.mOutputSignatureJarEntryDataRequests.get(entryName);
                    if (actualDataRequest == null) {
                        throw new IllegalStateException("APK entry " + entryName + " not yet output despite this having been requested");
                    } else if (!actualDataRequest.isDone()) {
                        throw new IllegalStateException("Still waiting to inspect output APK's " + entryName);
                    } else if (!Arrays.equals(expectedData, actualDataRequest.getData())) {
                        throw new IllegalStateException("Output APK entry " + entryName + " data differs from what was requested");
                    }
                }
                this.mV1SignaturePending = false;
            }
        }
    }

    private void checkSigningBlockDoneIfEnabled() {
        if (!this.mV2SignaturePending && !this.mV3SignaturePending) {
            return;
        }
        if (this.mAddSigningBlockRequest == null) {
            throw new IllegalStateException("Signed APK Signing BLock not yet generated. Skipped outputZipSections()?");
        } else if (!this.mAddSigningBlockRequest.isDone()) {
            throw new IllegalStateException("APK Signing Block addition of signature(s) requested by outputZipSections() hasn't been fulfilled yet");
        } else {
            this.mAddSigningBlockRequest = null;
            this.mV2SignaturePending = false;
            this.mV3SignaturePending = false;
        }
    }

    private void checkOutputApkNotDebuggableIfDebuggableMustBeRejected() throws SignatureException {
        if (!this.mDebuggableApkPermitted) {
            try {
                if (isOutputApkDebuggable()) {
                    throw new SignatureException("APK is debuggable (see android:debuggable attribute) and this engine is configured to refuse to sign debuggable APKs");
                }
            } catch (ApkFormatException e) {
                throw new SignatureException("Failed to determine whether the APK is debuggable", e);
            }
        }
    }

    private boolean isOutputApkDebuggable() throws ApkFormatException {
        if (this.mDebuggable != null) {
            return this.mDebuggable.booleanValue();
        }
        if (this.mOutputAndroidManifestEntryDataRequest == null) {
            throw new IllegalStateException("Cannot determine debuggable status of output APK because AndroidManifest.xml entry contents have not yet been requested");
        } else if (!this.mOutputAndroidManifestEntryDataRequest.isDone()) {
            throw new IllegalStateException("Still waiting to inspect output APK's " + this.mOutputAndroidManifestEntryDataRequest.getEntryName());
        } else {
            this.mDebuggable = Boolean.valueOf(ApkUtils.getDebuggableFromBinaryAndroidManifest(ByteBuffer.wrap(this.mOutputAndroidManifestEntryDataRequest.getData())));
            return this.mDebuggable.booleanValue();
        }
    }

    private void forgetOutputApkDebuggableStatus() {
        this.mDebuggable = null;
    }

    private ApkSignerEngine.InputJarEntryInstructions.OutputPolicy getInputJarEntryOutputPolicy(String entryName) {
        if (this.mSignatureExpectedOutputJarEntryNames.contains(entryName)) {
            return ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT_BY_ENGINE;
        }
        if (this.mOtherSignersSignaturesPreserved || V1SchemeSigner.isJarEntryDigestNeededInManifest(entryName)) {
            return ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.OUTPUT;
        }
        return ApkSignerEngine.InputJarEntryInstructions.OutputPolicy.SKIP;
    }

    /* access modifiers changed from: private */
    public static class OutputJarSignatureRequestImpl implements ApkSignerEngine.OutputJarSignatureRequest {
        private final List<ApkSignerEngine.OutputJarSignatureRequest.JarEntry> mAdditionalJarEntries;
        private volatile boolean mDone;

        private OutputJarSignatureRequestImpl(List<ApkSignerEngine.OutputJarSignatureRequest.JarEntry> additionalZipEntries) {
            this.mAdditionalJarEntries = Collections.unmodifiableList(new ArrayList(additionalZipEntries));
        }

        @Override // com.android.apksig.ApkSignerEngine.OutputJarSignatureRequest
        public List<ApkSignerEngine.OutputJarSignatureRequest.JarEntry> getAdditionalJarEntries() {
            return this.mAdditionalJarEntries;
        }

        @Override // com.android.apksig.ApkSignerEngine.OutputJarSignatureRequest
        public void done() {
            this.mDone = true;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean isDone() {
            return this.mDone;
        }
    }

    /* access modifiers changed from: private */
    public static class OutputApkSigningBlockRequestImpl implements ApkSignerEngine.OutputApkSigningBlockRequest, ApkSignerEngine.OutputApkSigningBlockRequest2 {
        private final byte[] mApkSigningBlock;
        private volatile boolean mDone;
        private final int mPaddingBeforeApkSigningBlock;

        private OutputApkSigningBlockRequestImpl(byte[] apkSigingBlock, int paddingBefore) {
            this.mApkSigningBlock = (byte[]) apkSigingBlock.clone();
            this.mPaddingBeforeApkSigningBlock = paddingBefore;
        }

        @Override // com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest2, com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest
        public byte[] getApkSigningBlock() {
            return (byte[]) this.mApkSigningBlock.clone();
        }

        @Override // com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest2, com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest
        public void done() {
            this.mDone = true;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean isDone() {
            return this.mDone;
        }

        @Override // com.android.apksig.ApkSignerEngine.OutputApkSigningBlockRequest2
        public int getPaddingSizeBeforeApkSigningBlock() {
            return this.mPaddingBeforeApkSigningBlock;
        }
    }

    /* access modifiers changed from: private */
    public static class GetJarEntryDataRequest implements ApkSignerEngine.InspectJarEntryRequest {
        private DataSink mDataSink;
        private ByteArrayOutputStream mDataSinkBuf;
        private boolean mDone;
        private final String mEntryName;
        private final Object mLock;

        private GetJarEntryDataRequest(String entryName) {
            this.mLock = new Object();
            this.mEntryName = entryName;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public String getEntryName() {
            return this.mEntryName;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public DataSink getDataSink() {
            DataSink dataSink;
            synchronized (this.mLock) {
                checkNotDone();
                if (this.mDataSinkBuf == null) {
                    this.mDataSinkBuf = new ByteArrayOutputStream();
                }
                if (this.mDataSink == null) {
                    this.mDataSink = DataSinks.asDataSink(this.mDataSinkBuf);
                }
                dataSink = this.mDataSink;
            }
            return dataSink;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public void done() {
            synchronized (this.mLock) {
                if (!this.mDone) {
                    this.mDone = true;
                }
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean isDone() {
            boolean z;
            synchronized (this.mLock) {
                z = this.mDone;
            }
            return z;
        }

        private void checkNotDone() throws IllegalStateException {
            synchronized (this.mLock) {
                if (this.mDone) {
                    throw new IllegalStateException("Already done");
                }
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private byte[] getData() {
            byte[] byteArray;
            synchronized (this.mLock) {
                if (!this.mDone) {
                    throw new IllegalStateException("Not yet done");
                }
                byteArray = this.mDataSinkBuf != null ? this.mDataSinkBuf.toByteArray() : new byte[0];
            }
            return byteArray;
        }
    }

    private static class GetJarEntryDataDigestRequest implements ApkSignerEngine.InspectJarEntryRequest {
        private DataSink mDataSink;
        private byte[] mDigest;
        private boolean mDone;
        private final String mEntryName;
        private final String mJcaDigestAlgorithm;
        private final Object mLock;
        private MessageDigest mMessageDigest;

        private GetJarEntryDataDigestRequest(String entryName, String jcaDigestAlgorithm) {
            this.mLock = new Object();
            this.mEntryName = entryName;
            this.mJcaDigestAlgorithm = jcaDigestAlgorithm;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public String getEntryName() {
            return this.mEntryName;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public DataSink getDataSink() {
            DataSink dataSink;
            synchronized (this.mLock) {
                checkNotDone();
                if (this.mDataSink == null) {
                    this.mDataSink = DataSinks.asDataSink(getMessageDigest());
                }
                dataSink = this.mDataSink;
            }
            return dataSink;
        }

        private MessageDigest getMessageDigest() {
            MessageDigest messageDigest;
            synchronized (this.mLock) {
                if (this.mMessageDigest == null) {
                    try {
                        this.mMessageDigest = MessageDigest.getInstance(this.mJcaDigestAlgorithm);
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(this.mJcaDigestAlgorithm + " MessageDigest not available", e);
                    }
                }
                messageDigest = this.mMessageDigest;
            }
            return messageDigest;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public void done() {
            synchronized (this.mLock) {
                if (!this.mDone) {
                    this.mDone = true;
                    this.mDigest = getMessageDigest().digest();
                    this.mMessageDigest = null;
                    this.mDataSink = null;
                }
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean isDone() {
            boolean z;
            synchronized (this.mLock) {
                z = this.mDone;
            }
            return z;
        }

        private void checkNotDone() throws IllegalStateException {
            synchronized (this.mLock) {
                if (this.mDone) {
                    throw new IllegalStateException("Already done");
                }
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private byte[] getDigest() {
            byte[] bArr;
            synchronized (this.mLock) {
                if (!this.mDone) {
                    throw new IllegalStateException("Not yet done");
                }
                bArr = (byte[]) this.mDigest.clone();
            }
            return bArr;
        }
    }

    private static class CompoundInspectJarEntryRequest implements ApkSignerEngine.InspectJarEntryRequest {
        private final String mEntryName;
        private final Object mLock;
        private final ApkSignerEngine.InspectJarEntryRequest[] mRequests;
        private DataSink mSink;

        private CompoundInspectJarEntryRequest(String entryName, ApkSignerEngine.InspectJarEntryRequest... requests) {
            this.mLock = new Object();
            this.mEntryName = entryName;
            this.mRequests = requests;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public String getEntryName() {
            return this.mEntryName;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public DataSink getDataSink() {
            DataSink dataSink;
            synchronized (this.mLock) {
                if (this.mSink == null) {
                    DataSink[] sinks = new DataSink[this.mRequests.length];
                    for (int i = 0; i < sinks.length; i++) {
                        sinks[i] = this.mRequests[i].getDataSink();
                    }
                    this.mSink = new TeeDataSink(sinks);
                }
                dataSink = this.mSink;
            }
            return dataSink;
        }

        @Override // com.android.apksig.ApkSignerEngine.InspectJarEntryRequest
        public void done() {
            for (ApkSignerEngine.InspectJarEntryRequest request : this.mRequests) {
                request.done();
            }
        }
    }

    public static class SignerConfig {
        private final List<X509Certificate> mCertificates;
        private final String mName;
        private final PrivateKey mPrivateKey;

        private SignerConfig(String name, PrivateKey privateKey, List<X509Certificate> certificates) {
            this.mName = name;
            this.mPrivateKey = privateKey;
            this.mCertificates = Collections.unmodifiableList(new ArrayList(certificates));
        }

        public String getName() {
            return this.mName;
        }

        public PrivateKey getPrivateKey() {
            return this.mPrivateKey;
        }

        public List<X509Certificate> getCertificates() {
            return this.mCertificates;
        }

        public static class Builder {
            private final List<X509Certificate> mCertificates;
            private final String mName;
            private final PrivateKey mPrivateKey;

            public Builder(String name, PrivateKey privateKey, List<X509Certificate> certificates) {
                if (name.isEmpty()) {
                    throw new IllegalArgumentException("Empty name");
                }
                this.mName = name;
                this.mPrivateKey = privateKey;
                this.mCertificates = new ArrayList(certificates);
            }

            public SignerConfig build() {
                return new SignerConfig(this.mName, this.mPrivateKey, this.mCertificates);
            }
        }
    }

    public static class Builder {
        private String mCreatedBy = "1.0 (Android)";
        private boolean mDebuggableApkPermitted = true;
        private final int mMinSdkVersion;
        private boolean mOtherSignersSignaturesPreserved;
        private List<SignerConfig> mSignerConfigs;
        private SigningCertificateLineage mSigningCertificateLineage;
        private SigningCertificateLineage mSourceStampSigningCertificateLineage;
        private SignerConfig mStampSignerConfig;
        private boolean mV1SigningEnabled = true;
        private boolean mV2SigningEnabled = true;
        private boolean mV3SigningEnabled = true;
        private boolean mV3SigningExplicitlyDisabled = false;
        private boolean mV3SigningExplicitlyEnabled = false;
        private boolean mVerityEnabled = false;

        public Builder(List<SignerConfig> signerConfigs, int minSdkVersion) {
            if (signerConfigs.isEmpty()) {
                throw new IllegalArgumentException("At least one signer config must be provided");
            }
            if (signerConfigs.size() > 1) {
                this.mV3SigningEnabled = false;
            }
            this.mSignerConfigs = new ArrayList(signerConfigs);
            this.mMinSdkVersion = minSdkVersion;
        }

        public DefaultApkSignerEngine build() throws InvalidKeyException {
            if (!this.mV3SigningExplicitlyDisabled || !this.mV3SigningExplicitlyEnabled) {
                if (this.mV3SigningExplicitlyDisabled) {
                    this.mV3SigningEnabled = false;
                } else if (this.mV3SigningExplicitlyEnabled) {
                    this.mV3SigningEnabled = true;
                }
                if (this.mSigningCertificateLineage != null) {
                    try {
                        this.mSignerConfigs = this.mSigningCertificateLineage.sortSignerConfigs(this.mSignerConfigs);
                        if (!this.mV3SigningEnabled && this.mSignerConfigs.size() > 1) {
                            throw new IllegalStateException("Provided multiple signers which are part of the SigningCertificateLineage, but not signing with APK Signature Scheme v3");
                        }
                    } catch (IllegalArgumentException e) {
                        throw new IllegalStateException("Provided signer configs do not match the provided SigningCertificateLineage", e);
                    }
                } else if (this.mV3SigningEnabled && this.mSignerConfigs.size() > 1) {
                    throw new IllegalStateException("Multiple signing certificates provided for use with APK Signature Scheme v3 without an accompanying SigningCertificateLineage");
                }
                return new DefaultApkSignerEngine(this.mSignerConfigs, this.mStampSignerConfig, this.mSourceStampSigningCertificateLineage, this.mMinSdkVersion, this.mV1SigningEnabled, this.mV2SigningEnabled, this.mV3SigningEnabled, this.mVerityEnabled, this.mDebuggableApkPermitted, this.mOtherSignersSignaturesPreserved, this.mCreatedBy, this.mSigningCertificateLineage);
            }
            throw new IllegalStateException("Builder configured to both enable and disable APK Signature Scheme v3 signing");
        }

        public Builder setStampSignerConfig(SignerConfig stampSignerConfig) {
            this.mStampSignerConfig = stampSignerConfig;
            return this;
        }

        public Builder setSourceStampSigningCertificateLineage(SigningCertificateLineage sourceStampSigningCertificateLineage) {
            this.mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
            return this;
        }

        public Builder setV1SigningEnabled(boolean enabled) {
            this.mV1SigningEnabled = enabled;
            return this;
        }

        public Builder setV2SigningEnabled(boolean enabled) {
            this.mV2SigningEnabled = enabled;
            return this;
        }

        public Builder setV3SigningEnabled(boolean enabled) {
            this.mV3SigningEnabled = enabled;
            if (enabled) {
                this.mV3SigningExplicitlyEnabled = true;
            } else {
                this.mV3SigningExplicitlyDisabled = true;
            }
            return this;
        }

        public Builder setVerityEnabled(boolean enabled) {
            this.mVerityEnabled = enabled;
            return this;
        }

        public Builder setDebuggableApkPermitted(boolean permitted) {
            this.mDebuggableApkPermitted = permitted;
            return this;
        }

        public Builder setOtherSignersSignaturesPreserved(boolean preserved) {
            this.mOtherSignersSignaturesPreserved = preserved;
            return this;
        }

        public Builder setCreatedBy(String createdBy) {
            if (createdBy == null) {
                throw new NullPointerException();
            }
            this.mCreatedBy = createdBy;
            return this;
        }

        public Builder setSigningCertificateLineage(SigningCertificateLineage signingCertificateLineage) {
            if (signingCertificateLineage != null) {
                this.mV3SigningEnabled = true;
                this.mSigningCertificateLineage = signingCertificateLineage;
            }
            return this;
        }
    }
}
