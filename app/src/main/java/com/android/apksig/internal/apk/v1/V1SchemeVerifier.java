package com.android.apksig.internal.apk.v1;

import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1Class;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.asn1.Asn1Field;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.asn1.Asn1Type;
import com.android.apksig.internal.jar.ManifestParser;
import com.android.apksig.internal.oid.OidConstants;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import com.android.apksig.internal.pkcs7.Attribute;
import com.android.apksig.internal.pkcs7.ContentInfo;
import com.android.apksig.internal.pkcs7.Pkcs7Constants;
import com.android.apksig.internal.pkcs7.Pkcs7DecodingException;
import com.android.apksig.internal.pkcs7.SignedData;
import com.android.apksig.internal.pkcs7.SignerInfo;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.android.apksig.internal.util.InclusiveIntRange;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.x509.Certificate;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.jar.Attributes;

public abstract class V1SchemeVerifier {
    private static final String[] JB_MR2_AND_NEWER_DIGEST_ALGS = {"SHA-512", "SHA-384", "SHA-256", "SHA-1"};
    private static final Map<String, Integer> MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST = new HashMap(5);
    private static final Map<String, String> UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL = new HashMap(8);

    @Asn1Class(type = Asn1Type.CHOICE)
    public static class ObjectIdentifierChoice {
        @Asn1Field(type = Asn1Type.OBJECT_IDENTIFIER)
        public String value;
    }

    @Asn1Class(type = Asn1Type.CHOICE)
    public static class OctetStringChoice {
        @Asn1Field(type = Asn1Type.OCTET_STRING)
        public byte[] value;
    }

    private V1SchemeVerifier() {
    }

    public static Result verify(DataSource apk, ApkUtils.ZipSections apkSections, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds, int minSdkVersion, int maxSdkVersion) throws IOException, ApkFormatException, NoSuchAlgorithmException {
        if (minSdkVersion > maxSdkVersion) {
            throw new IllegalArgumentException("minSdkVersion (" + minSdkVersion + ") > maxSdkVersion (" + maxSdkVersion + ")");
        }
        Result result = new Result();
        List<CentralDirectoryRecord> cdRecords = parseZipCentralDirectory(apk, apkSections);
        Set<String> cdEntryNames = checkForDuplicateEntries(cdRecords, result);
        if (!result.containsErrors()) {
            Signers.verify(apk, apkSections.getZipCentralDirectoryOffset(), cdRecords, cdEntryNames, supportedApkSigSchemeNames, foundApkSigSchemeIds, minSdkVersion, maxSdkVersion, result);
        }
        return result;
    }

    private static Set<String> checkForDuplicateEntries(List<CentralDirectoryRecord> cdRecords, Result result) {
        Set<String> cdEntryNames = new HashSet<>(cdRecords.size());
        Set<String> duplicateCdEntryNames = null;
        for (CentralDirectoryRecord cdRecord : cdRecords) {
            String entryName = cdRecord.getName();
            if (!cdEntryNames.add(entryName)) {
                if (duplicateCdEntryNames == null) {
                    duplicateCdEntryNames = new HashSet<>();
                }
                if (duplicateCdEntryNames.add(entryName)) {
                    result.addError(ApkVerifier.Issue.JAR_SIG_DUPLICATE_ZIP_ENTRY, new Object[]{entryName});
                }
            }
        }
        return cdEntryNames;
    }

    public static Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> parseManifest(byte[] manifestBytes, Set<String> cdEntryNames, Result result) {
        ManifestParser manifest = new ManifestParser(manifestBytes);
        ManifestParser.Section manifestMainSection = manifest.readSection();
        List<ManifestParser.Section> manifestIndividualSections = manifest.readAllSections();
        Map<String, ManifestParser.Section> entryNameToManifestSection = new HashMap<>(manifestIndividualSections.size());
        int manifestSectionNumber = 0;
        for (ManifestParser.Section manifestSection : manifestIndividualSections) {
            manifestSectionNumber++;
            String entryName = manifestSection.getName();
            if (entryName == null) {
                result.addError(ApkVerifier.Issue.JAR_SIG_UNNNAMED_MANIFEST_SECTION, new Object[]{Integer.valueOf(manifestSectionNumber)});
            } else if (entryNameToManifestSection.put(entryName, manifestSection) != null) {
                result.addError(ApkVerifier.Issue.JAR_SIG_DUPLICATE_MANIFEST_SECTION, new Object[]{entryName});
            } else if (!cdEntryNames.contains(entryName)) {
                result.addError(ApkVerifier.Issue.JAR_SIG_MISSING_ZIP_ENTRY_REFERENCED_IN_MANIFEST, new Object[]{entryName});
            }
        }
        return Pair.of(manifestMainSection, entryNameToManifestSection);
    }

    private static class Signers {
        private Signers() {
        }

        /* access modifiers changed from: private */
        public static void verify(DataSource apk, long cdStartOffset, List<CentralDirectoryRecord> cdRecords, Set<String> cdEntryNames, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds, int minSdkVersion, int maxSdkVersion, Result result) throws ApkFormatException, IOException, NoSuchAlgorithmException {
            CentralDirectoryRecord manifestEntry = null;
            Map<String, CentralDirectoryRecord> sigFileEntries = new HashMap<>(1);
            List<CentralDirectoryRecord> sigBlockEntries = new ArrayList<>(1);
            for (CentralDirectoryRecord cdRecord : cdRecords) {
                String entryName = cdRecord.getName();
                if (entryName.startsWith("META-INF/")) {
                    if (manifestEntry == null && "META-INF/MANIFEST.MF".equals(entryName)) {
                        manifestEntry = cdRecord;
                    } else if (entryName.endsWith(".SF")) {
                        sigFileEntries.put(entryName, cdRecord);
                    } else if (entryName.endsWith(".RSA") || entryName.endsWith(".DSA") || entryName.endsWith(".EC")) {
                        sigBlockEntries.add(cdRecord);
                    }
                }
            }
            if (manifestEntry == null) {
                result.addError(ApkVerifier.Issue.JAR_SIG_NO_MANIFEST, new Object[0]);
                return;
            }
            try {
                byte[] manifestBytes = LocalFileRecord.getUncompressedData(apk, manifestEntry, cdStartOffset);
                Pair<ManifestParser.Section, Map<String, ManifestParser.Section>> manifestSections = V1SchemeVerifier.parseManifest(manifestBytes, cdEntryNames, result);
                if (!result.containsErrors()) {
                    ManifestParser.Section manifestMainSection = manifestSections.getFirst();
                    Map<String, ManifestParser.Section> entryNameToManifestSection = manifestSections.getSecond();
                    List<Signer> signers = new ArrayList<>(sigBlockEntries.size());
                    for (CentralDirectoryRecord sigBlockEntry : sigBlockEntries) {
                        String sigBlockEntryName = sigBlockEntry.getName();
                        int extensionDelimiterIndex = sigBlockEntryName.lastIndexOf(46);
                        if (extensionDelimiterIndex == -1) {
                            throw new RuntimeException("Signature block file name does not contain extension: " + sigBlockEntryName);
                        }
                        String sigFileEntryName = sigBlockEntryName.substring(0, extensionDelimiterIndex) + ".SF";
                        CentralDirectoryRecord sigFileEntry = sigFileEntries.get(sigFileEntryName);
                        if (sigFileEntry == null) {
                            result.addWarning(ApkVerifier.Issue.JAR_SIG_MISSING_FILE, new Object[]{sigBlockEntryName, sigFileEntryName});
                        } else {
                            String signerName = sigBlockEntryName.substring("META-INF/".length());
                            signers.add(new Signer(signerName, sigBlockEntry, sigFileEntry, new Result.SignerInfo(signerName, sigBlockEntryName, sigFileEntry.getName())));
                        }
                    }
                    if (signers.isEmpty()) {
                        result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNATURES, new Object[0]);
                        return;
                    }
                    for (Signer signer : signers) {
                        signer.verifySigBlockAgainstSigFile(apk, cdStartOffset, minSdkVersion, maxSdkVersion);
                        if (signer.getResult().containsErrors()) {
                            result.signers.add(signer.getResult());
                        }
                    }
                    if (!result.containsErrors()) {
                        List<Signer> remainingSigners = new ArrayList<>(signers.size());
                        for (Signer signer2 : signers) {
                            signer2.verifySigFileAgainstManifest(manifestBytes, manifestMainSection, entryNameToManifestSection, supportedApkSigSchemeNames, foundApkSigSchemeIds, minSdkVersion, maxSdkVersion);
                            if (signer2.isIgnored()) {
                                result.ignoredSigners.add(signer2.getResult());
                            } else if (signer2.getResult().containsErrors()) {
                                result.signers.add(signer2.getResult());
                            } else {
                                remainingSigners.add(signer2);
                            }
                        }
                        if (result.containsErrors()) {
                            return;
                        }
                        if (remainingSigners.isEmpty()) {
                            result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNATURES, new Object[0]);
                            return;
                        }
                        Set<Signer> apkSigners = V1SchemeVerifier.verifyJarEntriesAgainstManifestAndSigners(apk, cdStartOffset, cdRecords, entryNameToManifestSection, remainingSigners, minSdkVersion, maxSdkVersion, result);
                        if (!result.containsErrors()) {
                            Set<String> signatureEntryNames = new HashSet<>((result.signers.size() * 2) + 1);
                            signatureEntryNames.add(manifestEntry.getName());
                            for (Signer signer3 : apkSigners) {
                                signatureEntryNames.add(signer3.getSignatureBlockEntryName());
                                signatureEntryNames.add(signer3.getSignatureFileEntryName());
                            }
                            for (CentralDirectoryRecord cdRecord2 : cdRecords) {
                                String entryName2 = cdRecord2.getName();
                                if (entryName2.startsWith("META-INF/") && !entryName2.endsWith("/") && !signatureEntryNames.contains(entryName2)) {
                                    result.addWarning(ApkVerifier.Issue.JAR_SIG_UNPROTECTED_ZIP_ENTRY, new Object[]{entryName2});
                                }
                            }
                            for (Signer signer4 : remainingSigners) {
                                if (apkSigners.contains(signer4)) {
                                    result.signers.add(signer4.getResult());
                                } else {
                                    result.ignoredSigners.add(signer4.getResult());
                                }
                            }
                            result.verified = true;
                        }
                    }
                }
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed ZIP entry: " + manifestEntry.getName(), e);
            }
        }
    }

    /* access modifiers changed from: package-private */
    public static class Signer {
        private boolean mIgnored;
        private final String mName;
        private final Result.SignerInfo mResult;
        private byte[] mSigFileBytes;
        private Set<String> mSigFileEntryNames;
        private final CentralDirectoryRecord mSignatureBlockEntry;
        private final CentralDirectoryRecord mSignatureFileEntry;

        private Signer(String name, CentralDirectoryRecord sigBlockEntry, CentralDirectoryRecord sigFileEntry, Result.SignerInfo result) {
            this.mName = name;
            this.mResult = result;
            this.mSignatureBlockEntry = sigBlockEntry;
            this.mSignatureFileEntry = sigFileEntry;
        }

        public String getName() {
            return this.mName;
        }

        public String getSignatureFileEntryName() {
            return this.mSignatureFileEntry.getName();
        }

        public String getSignatureBlockEntryName() {
            return this.mSignatureBlockEntry.getName();
        }

        /* access modifiers changed from: package-private */
        public void setIgnored() {
            this.mIgnored = true;
        }

        public boolean isIgnored() {
            return this.mIgnored;
        }

        public Set<String> getSigFileEntryNames() {
            return this.mSigFileEntryNames;
        }

        public Result.SignerInfo getResult() {
            return this.mResult;
        }

        public void verifySigBlockAgainstSigFile(DataSource apk, long cdStartOffset, int minSdkVersion, int maxSdkVersion) throws IOException, ApkFormatException, NoSuchAlgorithmException {
            List<SignerInfo> unverifiedSignerInfosToTry;
            try {
                byte[] sigBlockBytes = LocalFileRecord.getUncompressedData(apk, this.mSignatureBlockEntry, cdStartOffset);
                try {
                    this.mSigFileBytes = LocalFileRecord.getUncompressedData(apk, this.mSignatureFileEntry, cdStartOffset);
                    try {
                        ContentInfo contentInfo = (ContentInfo) Asn1BerParser.parse(ByteBuffer.wrap(sigBlockBytes), ContentInfo.class);
                        if (!Pkcs7Constants.OID_SIGNED_DATA.equals(contentInfo.contentType)) {
                            throw new Asn1DecodingException("Unsupported ContentInfo.contentType: " + contentInfo.contentType);
                        }
                        SignedData signedData = (SignedData) Asn1BerParser.parse(contentInfo.content.getEncoded(), SignedData.class);
                        if (signedData.signerInfos.isEmpty()) {
                            this.mResult.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNERS, new Object[]{this.mSignatureBlockEntry.getName()});
                            return;
                        }
                        SignerInfo firstVerifiedSignerInfo = null;
                        X509Certificate firstVerifiedSignerInfoSigningCertificate = null;
                        if (minSdkVersion < 24) {
                            unverifiedSignerInfosToTry = Collections.singletonList(signedData.signerInfos.get(0));
                        } else {
                            unverifiedSignerInfosToTry = signedData.signerInfos;
                        }
                        List<X509Certificate> signedDataCertificates = null;
                        for (SignerInfo unverifiedSignerInfo : unverifiedSignerInfosToTry) {
                            if (signedDataCertificates == null) {
                                try {
                                    signedDataCertificates = Certificate.parseCertificates(signedData.certificates);
                                } catch (CertificateException e) {
                                    this.mResult.addError(ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, new Object[]{this.mSignatureBlockEntry.getName(), e});
                                    return;
                                }
                            }
                            try {
                                X509Certificate signingCertificate = verifySignerInfoAgainstSigFile(signedData, signedDataCertificates, unverifiedSignerInfo, this.mSigFileBytes, minSdkVersion, maxSdkVersion);
                                if (this.mResult.containsErrors()) {
                                    return;
                                }
                                if (signingCertificate != null && firstVerifiedSignerInfo == null) {
                                    firstVerifiedSignerInfo = unverifiedSignerInfo;
                                    firstVerifiedSignerInfoSigningCertificate = signingCertificate;
                                }
                            } catch (Pkcs7DecodingException e2) {
                                this.mResult.addError(ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, new Object[]{this.mSignatureBlockEntry.getName(), e2});
                                return;
                            } catch (InvalidKeyException | SignatureException e3) {
                                this.mResult.addError(ApkVerifier.Issue.JAR_SIG_VERIFY_EXCEPTION, new Object[]{this.mSignatureBlockEntry.getName(), this.mSignatureFileEntry.getName(), e3});
                                return;
                            }
                        }
                        if (firstVerifiedSignerInfo == null) {
                            this.mResult.addError(ApkVerifier.Issue.JAR_SIG_DID_NOT_VERIFY, new Object[]{this.mSignatureBlockEntry.getName(), this.mSignatureFileEntry.getName()});
                            return;
                        }
                        List<X509Certificate> signingCertChain = getCertificateChain(signedDataCertificates, firstVerifiedSignerInfoSigningCertificate);
                        this.mResult.certChain.clear();
                        this.mResult.certChain.addAll(signingCertChain);
                    } catch (Asn1DecodingException e4) {
                        e4.printStackTrace();
                        this.mResult.addError(ApkVerifier.Issue.JAR_SIG_PARSE_EXCEPTION, new Object[]{this.mSignatureBlockEntry.getName(), e4});
                    }
                } catch (ZipFormatException e5) {
                    throw new ApkFormatException("Malformed ZIP entry: " + this.mSignatureFileEntry.getName(), e5);
                }
            } catch (ZipFormatException e6) {
                throw new ApkFormatException("Malformed ZIP entry: " + this.mSignatureBlockEntry.getName(), e6);
            }
        }

        private X509Certificate verifySignerInfoAgainstSigFile(SignedData signedData, Collection<X509Certificate> signedDataCertificates, SignerInfo signerInfo, byte[] signatureFile, int minSdkVersion, int maxSdkVersion) throws Pkcs7DecodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            String digestAlgorithmOid = signerInfo.digestAlgorithm.algorithm;
            String signatureAlgorithmOid = signerInfo.signatureAlgorithm.algorithm;
            List<InclusiveIntRange> apiLevelsWhereDigestAlgorithmNotSupported = InclusiveIntRange.fromTo(minSdkVersion, maxSdkVersion).getValuesNotIn(OidConstants.getSigAlgSupportedApiLevels(digestAlgorithmOid, signatureAlgorithmOid));
            if (!apiLevelsWhereDigestAlgorithmNotSupported.isEmpty()) {
                String digestAlgorithmUserFriendly = OidConstants.OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(digestAlgorithmOid);
                if (digestAlgorithmUserFriendly == null) {
                    digestAlgorithmUserFriendly = digestAlgorithmOid;
                }
                String signatureAlgorithmUserFriendly = OidConstants.OidToUserFriendlyNameMapper.getUserFriendlyNameForOid(signatureAlgorithmOid);
                if (signatureAlgorithmUserFriendly == null) {
                    signatureAlgorithmUserFriendly = signatureAlgorithmOid;
                }
                StringBuilder apiLevelsUserFriendly = new StringBuilder();
                for (InclusiveIntRange range : apiLevelsWhereDigestAlgorithmNotSupported) {
                    if (apiLevelsUserFriendly.length() > 0) {
                        apiLevelsUserFriendly.append(", ");
                    }
                    if (range.getMin() == range.getMax()) {
                        apiLevelsUserFriendly.append(String.valueOf(range.getMin()));
                    } else if (range.getMax() == Integer.MAX_VALUE) {
                        apiLevelsUserFriendly.append(range.getMin() + "+");
                    } else {
                        apiLevelsUserFriendly.append(range.getMin() + "-" + range.getMax());
                    }
                }
                this.mResult.addError(ApkVerifier.Issue.JAR_SIG_UNSUPPORTED_SIG_ALG, new Object[]{this.mSignatureBlockEntry.getName(), digestAlgorithmOid, signatureAlgorithmOid, apiLevelsUserFriendly.toString(), digestAlgorithmUserFriendly, signatureAlgorithmUserFriendly});
                return null;
            }
            X509Certificate signingCertificate = Certificate.findCertificate(signedDataCertificates, signerInfo.sid);
            if (signingCertificate == null) {
                throw new SignatureException("Signing certificate referenced in SignerInfo not found in SignedData");
            } else if (signingCertificate.hasUnsupportedCriticalExtension()) {
                throw new SignatureException("Signing certificate has unsupported critical extensions");
            } else {
                boolean[] keyUsageExtension = signingCertificate.getKeyUsage();
                if (keyUsageExtension != null) {
                    boolean digitalSignature = keyUsageExtension.length >= 1 && keyUsageExtension[0];
                    boolean nonRepudiation = keyUsageExtension.length >= 2 && keyUsageExtension[1];
                    if (!digitalSignature && !nonRepudiation) {
                        throw new SignatureException("Signing certificate not authorized for use in digital signatures: keyUsage extension missing digitalSignature and nonRepudiation");
                    }
                }
                Signature s = Signature.getInstance(AlgorithmIdentifier.getJcaSignatureAlgorithm(digestAlgorithmOid, signatureAlgorithmOid));
                s.initVerify(signingCertificate.getPublicKey());
                if (signerInfo.signedAttrs == null) {
                    s.update(signatureFile);
                } else if (minSdkVersion < 19) {
                    throw new SignatureException("APKs with Signed Attributes broken on platforms with API Level < 19");
                } else {
                    try {
                        SignedAttributes signedAttrs = new SignedAttributes(Asn1BerParser.parseImplicitSetOf(signerInfo.signedAttrs.getEncoded(), Attribute.class));
                        if (maxSdkVersion >= 24) {
                            String contentType = signedAttrs.getSingleObjectIdentifierValue(Pkcs7Constants.OID_CONTENT_TYPE);
                            if (contentType == null) {
                                throw new SignatureException("No Content Type in signed attributes");
                            } else if (!contentType.equals(signedData.encapContentInfo.contentType)) {
                                return null;
                            }
                        }
                        byte[] expectedSignatureFileDigest = signedAttrs.getSingleOctetStringValue(Pkcs7Constants.OID_MESSAGE_DIGEST);
                        if (expectedSignatureFileDigest == null) {
                            throw new SignatureException("No content digest in signed attributes");
                        } else if (!Arrays.equals(expectedSignatureFileDigest, MessageDigest.getInstance(AlgorithmIdentifier.getJcaDigestAlgorithm(digestAlgorithmOid)).digest(signatureFile))) {
                            return null;
                        } else {
                            ByteBuffer signedAttrsOriginalEncoding = signerInfo.signedAttrs.getEncoded();
                            s.update((byte) 49);
                            signedAttrsOriginalEncoding.position(1);
                            s.update(signedAttrsOriginalEncoding);
                        }
                    } catch (Asn1DecodingException e) {
                        throw new SignatureException("Failed to parse signed attributes", e);
                    }
                }
                if (!s.verify(ByteBufferUtils.toByteArray(signerInfo.signature.slice()))) {
                    return null;
                }
                return signingCertificate;
            }
        }

        public static List<X509Certificate> getCertificateChain(List<X509Certificate> certs, X509Certificate leaf) {
            List<X509Certificate> unusedCerts = new ArrayList<>(certs);
            List<X509Certificate> result = new ArrayList<>(1);
            result.add(leaf);
            unusedCerts.remove(leaf);
            X509Certificate root = leaf;
            while (!root.getSubjectDN().equals(root.getIssuerDN())) {
                Principal targetDn = root.getIssuerDN();
                boolean issuerFound = false;
                int i = 0;
                while (true) {
                    if (i >= unusedCerts.size()) {
                        break;
                    }
                    X509Certificate unusedCert = unusedCerts.get(i);
                    if (targetDn.equals(unusedCert.getSubjectDN())) {
                        issuerFound = true;
                        unusedCerts.remove(i);
                        result.add(unusedCert);
                        root = unusedCert;
                        continue;
                        break;
                    }
                    i++;
                }
                if (!issuerFound) {
                    break;
                }
            }
            return result;
        }

        public void verifySigFileAgainstManifest(byte[] manifestBytes, ManifestParser.Section manifestMainSection, Map<String, ManifestParser.Section> entryNameToManifestSection, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds, int minSdkVersion, int maxSdkVersion) throws NoSuchAlgorithmException {
            ManifestParser sf = new ManifestParser(this.mSigFileBytes);
            ManifestParser.Section sfMainSection = sf.readSection();
            if (sfMainSection.getAttributeValue(Attributes.Name.SIGNATURE_VERSION) == null) {
                this.mResult.addError(ApkVerifier.Issue.JAR_SIG_MISSING_VERSION_ATTR_IN_SIG_FILE, new Object[]{this.mSignatureFileEntry.getName()});
                setIgnored();
                return;
            }
            if (maxSdkVersion >= 24) {
                checkForStrippedApkSignatures(sfMainSection, supportedApkSigSchemeNames, foundApkSigSchemeIds);
                if (this.mResult.containsErrors()) {
                    return;
                }
            }
            boolean createdBySigntool = false;
            String createdBy = sfMainSection.getAttributeValue("Created-By");
            if (createdBy != null) {
                createdBySigntool = createdBy.indexOf("signtool") != -1;
            }
            boolean manifestDigestVerified = verifyManifestDigest(sfMainSection, createdBySigntool, manifestBytes, minSdkVersion, maxSdkVersion);
            if (!createdBySigntool) {
                verifyManifestMainSectionDigest(sfMainSection, manifestMainSection, manifestBytes, minSdkVersion, maxSdkVersion);
            }
            if (!this.mResult.containsErrors()) {
                List<ManifestParser.Section> sfSections = sf.readAllSections();
                Set<String> sfEntryNames = new HashSet<>(sfSections.size());
                int sfSectionNumber = 0;
                for (ManifestParser.Section sfSection : sfSections) {
                    sfSectionNumber++;
                    String entryName = sfSection.getName();
                    if (entryName == null) {
                        this.mResult.addError(ApkVerifier.Issue.JAR_SIG_UNNNAMED_SIG_FILE_SECTION, new Object[]{this.mSignatureFileEntry.getName(), Integer.valueOf(sfSectionNumber)});
                        setIgnored();
                        return;
                    } else if (!sfEntryNames.add(entryName)) {
                        this.mResult.addError(ApkVerifier.Issue.JAR_SIG_DUPLICATE_SIG_FILE_SECTION, new Object[]{this.mSignatureFileEntry.getName(), entryName});
                        setIgnored();
                        return;
                    } else if (!manifestDigestVerified) {
                        ManifestParser.Section manifestSection = entryNameToManifestSection.get(entryName);
                        if (manifestSection == null) {
                            this.mResult.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE, new Object[]{entryName, this.mSignatureFileEntry.getName()});
                            setIgnored();
                        } else {
                            verifyManifestIndividualSectionDigest(sfSection, createdBySigntool, manifestSection, manifestBytes, minSdkVersion, maxSdkVersion);
                        }
                    }
                }
                this.mSigFileEntryNames = sfEntryNames;
            }
        }

        private boolean verifyManifestDigest(ManifestParser.Section sfMainSection, boolean createdBySigntool, byte[] manifestBytes, int minSdkVersion, int maxSdkVersion) throws NoSuchAlgorithmException {
            Collection<NamedDigest> expectedDigests = V1SchemeVerifier.getDigestsToVerify(sfMainSection, createdBySigntool ? "-Digest" : "-Digest-Manifest", minSdkVersion, maxSdkVersion);
            if (!(!expectedDigests.isEmpty())) {
                this.mResult.addWarning(ApkVerifier.Issue.JAR_SIG_NO_MANIFEST_DIGEST_IN_SIG_FILE, new Object[]{this.mSignatureFileEntry.getName()});
                return false;
            }
            boolean verified = true;
            for (NamedDigest expectedDigest : expectedDigests) {
                String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                byte[] actual = V1SchemeVerifier.digest(jcaDigestAlgorithm, manifestBytes);
                byte[] expected = expectedDigest.digest;
                if (!Arrays.equals(expected, actual)) {
                    this.mResult.addWarning(ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY, new Object[]{"META-INF/MANIFEST.MF", jcaDigestAlgorithm, this.mSignatureFileEntry.getName(), Base64.getEncoder().encodeToString(actual), Base64.getEncoder().encodeToString(expected)});
                    verified = false;
                }
            }
            return verified;
        }

        private void verifyManifestMainSectionDigest(ManifestParser.Section sfMainSection, ManifestParser.Section manifestMainSection, byte[] manifestBytes, int minSdkVersion, int maxSdkVersion) throws NoSuchAlgorithmException {
            Collection<NamedDigest> expectedDigests = V1SchemeVerifier.getDigestsToVerify(sfMainSection, "-Digest-Manifest-Main-Attributes", minSdkVersion, maxSdkVersion);
            if (!expectedDigests.isEmpty()) {
                for (NamedDigest expectedDigest : expectedDigests) {
                    String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                    byte[] actual = V1SchemeVerifier.digest(jcaDigestAlgorithm, manifestBytes, manifestMainSection.getStartOffset(), manifestMainSection.getSizeBytes());
                    byte[] expected = expectedDigest.digest;
                    if (!Arrays.equals(expected, actual)) {
                        this.mResult.addError(ApkVerifier.Issue.JAR_SIG_MANIFEST_MAIN_SECTION_DIGEST_DID_NOT_VERIFY, new Object[]{jcaDigestAlgorithm, this.mSignatureFileEntry.getName(), Base64.getEncoder().encodeToString(actual), Base64.getEncoder().encodeToString(expected)});
                    }
                }
            }
        }

        private void verifyManifestIndividualSectionDigest(ManifestParser.Section sfIndividualSection, boolean createdBySigntool, ManifestParser.Section manifestIndividualSection, byte[] manifestBytes, int minSdkVersion, int maxSdkVersion) throws NoSuchAlgorithmException {
            String entryName = sfIndividualSection.getName();
            Collection<NamedDigest> expectedDigests = V1SchemeVerifier.getDigestsToVerify(sfIndividualSection, "-Digest", minSdkVersion, maxSdkVersion);
            if (expectedDigests.isEmpty()) {
                this.mResult.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_SIG_FILE, new Object[]{entryName, this.mSignatureFileEntry.getName()});
                return;
            }
            int sectionStartIndex = manifestIndividualSection.getStartOffset();
            int sectionSizeBytes = manifestIndividualSection.getSizeBytes();
            if (createdBySigntool) {
                int sectionEndIndex = sectionStartIndex + sectionSizeBytes;
                if (manifestBytes[sectionEndIndex - 1] == 10 && manifestBytes[sectionEndIndex - 2] == 10) {
                    sectionSizeBytes--;
                }
            }
            for (NamedDigest expectedDigest : expectedDigests) {
                String jcaDigestAlgorithm = expectedDigest.jcaDigestAlgorithm;
                byte[] actual = V1SchemeVerifier.digest(jcaDigestAlgorithm, manifestBytes, sectionStartIndex, sectionSizeBytes);
                byte[] expected = expectedDigest.digest;
                if (!Arrays.equals(expected, actual)) {
                    this.mResult.addError(ApkVerifier.Issue.JAR_SIG_MANIFEST_SECTION_DIGEST_DID_NOT_VERIFY, new Object[]{entryName, jcaDigestAlgorithm, this.mSignatureFileEntry.getName(), Base64.getEncoder().encodeToString(actual), Base64.getEncoder().encodeToString(expected)});
                }
            }
        }

        private void checkForStrippedApkSignatures(ManifestParser.Section sfMainSection, Map<Integer, String> supportedApkSigSchemeNames, Set<Integer> foundApkSigSchemeIds) {
            String signedWithApkSchemes = sfMainSection.getAttributeValue(V1SchemeConstants.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR);
            if (signedWithApkSchemes == null) {
                if (!foundApkSigSchemeIds.isEmpty()) {
                    this.mResult.addWarning(ApkVerifier.Issue.JAR_SIG_NO_APK_SIG_STRIP_PROTECTION, new Object[]{this.mSignatureFileEntry.getName()});
                }
            } else if (!supportedApkSigSchemeNames.isEmpty()) {
                Set<Integer> supportedApkSigSchemeIds = supportedApkSigSchemeNames.keySet();
                Set<Integer> supportedExpectedApkSigSchemeIds = new HashSet<>(1);
                StringTokenizer tokenizer = new StringTokenizer(signedWithApkSchemes, ",");
                while (tokenizer.hasMoreTokens()) {
                    String idText = tokenizer.nextToken().trim();
                    if (!idText.isEmpty()) {
                        try {
                            int id = Integer.parseInt(idText);
                            if (supportedApkSigSchemeIds.contains(Integer.valueOf(id))) {
                                supportedExpectedApkSigSchemeIds.add(Integer.valueOf(id));
                            } else {
                                this.mResult.addWarning(ApkVerifier.Issue.JAR_SIG_UNKNOWN_APK_SIG_SCHEME_ID, new Object[]{this.mSignatureFileEntry.getName(), Integer.valueOf(id)});
                            }
                        } catch (Exception e) {
                        }
                    }
                }
                for (Integer num : supportedExpectedApkSigSchemeIds) {
                    int id2 = num.intValue();
                    if (!foundApkSigSchemeIds.contains(Integer.valueOf(id2))) {
                        this.mResult.addError(ApkVerifier.Issue.JAR_SIG_MISSING_APK_SIG_REFERENCED, new Object[]{this.mSignatureFileEntry.getName(), Integer.valueOf(id2), supportedApkSigSchemeNames.get(Integer.valueOf(id2))});
                    }
                }
            }
        }
    }

    /* JADX WARNING: Code restructure failed: missing block: B:16:0x005b, code lost:
        if (r7.isEmpty() != false) goto L_0x005d;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static java.util.Collection<com.android.apksig.internal.apk.v1.V1SchemeVerifier.NamedDigest> getDigestsToVerify(com.android.apksig.internal.jar.ManifestParser.Section r12, java.lang.String r13, int r14, int r15) {
        /*
        // Method dump skipped, instructions count: 145
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.v1.V1SchemeVerifier.getDigestsToVerify(com.android.apksig.internal.jar.ManifestParser$Section, java.lang.String, int, int):java.util.Collection");
    }

    static {
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("MD5", "MD5");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA", "SHA-1");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA1", "SHA-1");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA-1", "SHA-1");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA-256", "SHA-256");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA-384", "SHA-384");
        UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.put("SHA-512", "SHA-512");
        MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.put("MD5", 0);
        MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.put("SHA-1", 0);
        MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.put("SHA-256", 0);
        MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.put("SHA-384", 9);
        MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.put("SHA-512", 9);
    }

    private static String getCanonicalJcaMessageDigestAlgorithm(String algorithm) {
        return UPPER_CASE_JCA_DIGEST_ALG_TO_CANONICAL.get(algorithm.toUpperCase(Locale.US));
    }

    public static int getMinSdkVersionFromWhichSupportedInManifestOrSignatureFile(String jcaAlgorithmName) {
        Integer result = MIN_SDK_VESION_FROM_WHICH_DIGEST_SUPPORTED_IN_MANIFEST.get(jcaAlgorithmName.toUpperCase(Locale.US));
        if (result != null) {
            return result.intValue();
        }
        return Integer.MAX_VALUE;
    }

    private static String getJarDigestAttributeName(String jcaDigestAlgorithm, String attrNameSuffix) {
        if ("SHA-1".equalsIgnoreCase(jcaDigestAlgorithm)) {
            return "SHA1" + attrNameSuffix;
        }
        return jcaDigestAlgorithm + attrNameSuffix;
    }

    private static byte[] getDigest(Collection<NamedDigest> digests, String jcaDigestAlgorithm) {
        for (NamedDigest digest : digests) {
            if (digest.jcaDigestAlgorithm.equalsIgnoreCase(jcaDigestAlgorithm)) {
                return digest.digest;
            }
        }
        return null;
    }

    public static List<CentralDirectoryRecord> parseZipCentralDirectory(DataSource apk, ApkUtils.ZipSections apkSections) throws IOException, ApkFormatException {
        return ZipUtils.parseZipCentralDirectory(apk, apkSections);
    }

    private static boolean isJarEntryDigestNeededInManifest(String entryName) {
        if (!entryName.startsWith("META-INF/") && !entryName.endsWith("/")) {
            return true;
        }
        return false;
    }

    /* access modifiers changed from: private */
    public static Set<Signer> verifyJarEntriesAgainstManifestAndSigners(DataSource apk, long cdOffsetInApk, Collection<CentralDirectoryRecord> cdRecords, Map<String, ManifestParser.Section> entryNameToManifestSection, List<Signer> signers, int minSdkVersion, int maxSdkVersion, Result result) throws ApkFormatException, IOException, NoSuchAlgorithmException {
        List<CentralDirectoryRecord> cdRecordsSortedByLocalFileHeaderOffset = new ArrayList<>(cdRecords);
        Collections.sort(cdRecordsSortedByLocalFileHeaderOffset, CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
        List<Signer> firstSignedEntrySigners = null;
        String firstSignedEntryName = null;
        for (CentralDirectoryRecord cdRecord : cdRecordsSortedByLocalFileHeaderOffset) {
            String entryName = cdRecord.getName();
            if (isJarEntryDigestNeededInManifest(entryName)) {
                ManifestParser.Section manifestSection = entryNameToManifestSection.get(entryName);
                if (manifestSection == null) {
                    result.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST, new Object[]{entryName});
                } else {
                    List<Signer> entrySigners = new ArrayList<>(signers.size());
                    for (Signer signer : signers) {
                        if (signer.getSigFileEntryNames().contains(entryName)) {
                            entrySigners.add(signer);
                        }
                    }
                    if (entrySigners.isEmpty()) {
                        result.addError(ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_NOT_SIGNED, new Object[]{entryName});
                    } else {
                        if (firstSignedEntrySigners == null) {
                            firstSignedEntrySigners = entrySigners;
                            firstSignedEntryName = entryName;
                        } else if (!entrySigners.equals(firstSignedEntrySigners)) {
                            result.addError(ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_SIGNERS_MISMATCH, new Object[]{firstSignedEntryName, getSignerNames(firstSignedEntrySigners), entryName, getSignerNames(entrySigners)});
                        }
                        List<NamedDigest> expectedDigests = new ArrayList<>(getDigestsToVerify(manifestSection, "-Digest", minSdkVersion, maxSdkVersion));
                        if (expectedDigests.isEmpty()) {
                            result.addError(ApkVerifier.Issue.JAR_SIG_NO_ZIP_ENTRY_DIGEST_IN_MANIFEST, new Object[]{entryName});
                        } else {
                            MessageDigest[] mds = new MessageDigest[expectedDigests.size()];
                            for (int i = 0; i < expectedDigests.size(); i++) {
                                mds[i] = getMessageDigest(expectedDigests.get(i).jcaDigestAlgorithm);
                            }
                            try {
                                LocalFileRecord.outputUncompressedData(apk, cdRecord, cdOffsetInApk, DataSinks.asDataSink(mds));
                                for (int i2 = 0; i2 < expectedDigests.size(); i2++) {
                                    NamedDigest expectedDigest = expectedDigests.get(i2);
                                    byte[] actualDigest = mds[i2].digest();
                                    if (!Arrays.equals(expectedDigest.digest, actualDigest)) {
                                        result.addError(ApkVerifier.Issue.JAR_SIG_ZIP_ENTRY_DIGEST_DID_NOT_VERIFY, new Object[]{entryName, expectedDigest.jcaDigestAlgorithm, "META-INF/MANIFEST.MF", Base64.getEncoder().encodeToString(actualDigest), Base64.getEncoder().encodeToString(expectedDigest.digest)});
                                    }
                                }
                            } catch (ZipFormatException e) {
                                throw new ApkFormatException("Malformed ZIP entry: " + entryName, e);
                            } catch (IOException e2) {
                                throw new IOException("Failed to read entry: " + entryName, e2);
                            }
                        }
                    }
                }
            }
        }
        if (firstSignedEntrySigners != null) {
            return new HashSet(firstSignedEntrySigners);
        }
        result.addError(ApkVerifier.Issue.JAR_SIG_NO_SIGNED_ZIP_ENTRIES, new Object[0]);
        return Collections.emptySet();
    }

    private static List<String> getSignerNames(List<Signer> signers) {
        if (signers.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>(signers.size());
        for (Signer signer : signers) {
            result.add(signer.getName());
        }
        return result;
    }

    private static MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm);
    }

    /* access modifiers changed from: private */
    public static byte[] digest(String algorithm, byte[] data, int offset, int length) throws NoSuchAlgorithmException {
        MessageDigest md = getMessageDigest(algorithm);
        md.update(data, offset, length);
        return md.digest();
    }

    /* access modifiers changed from: private */
    public static byte[] digest(String algorithm, byte[] data) throws NoSuchAlgorithmException {
        return getMessageDigest(algorithm).digest(data);
    }

    public static class NamedDigest {
        public final byte[] digest;
        public final String jcaDigestAlgorithm;

        private NamedDigest(String jcaDigestAlgorithm2, byte[] digest2) {
            this.jcaDigestAlgorithm = jcaDigestAlgorithm2;
            this.digest = digest2;
        }
    }

    public static class Result {
        public final List<SignerInfo> ignoredSigners = new ArrayList();
        private final List<ApkVerifier.IssueWithParams> mErrors = new ArrayList();
        private final List<ApkVerifier.IssueWithParams> mWarnings = new ArrayList();
        public final List<SignerInfo> signers = new ArrayList();
        public boolean verified;

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean containsErrors() {
            if (!this.mErrors.isEmpty()) {
                return true;
            }
            for (SignerInfo signer : this.signers) {
                if (signer.containsErrors()) {
                    return true;
                }
            }
            return false;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addError(ApkVerifier.Issue msg, Object... parameters) {
            this.mErrors.add(new ApkVerifier.IssueWithParams(msg, parameters));
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void addWarning(ApkVerifier.Issue msg, Object... parameters) {
            this.mWarnings.add(new ApkVerifier.IssueWithParams(msg, parameters));
        }

        public List<ApkVerifier.IssueWithParams> getErrors() {
            return this.mErrors;
        }

        public List<ApkVerifier.IssueWithParams> getWarnings() {
            return this.mWarnings;
        }

        public static class SignerInfo {
            public final List<X509Certificate> certChain;
            private final List<ApkVerifier.IssueWithParams> mErrors;
            private final List<ApkVerifier.IssueWithParams> mWarnings;
            public final String name;
            public final String signatureBlockFileName;
            public final String signatureFileName;

            private SignerInfo(String name2, String signatureBlockFileName2, String signatureFileName2) {
                this.certChain = new ArrayList();
                this.mWarnings = new ArrayList();
                this.mErrors = new ArrayList();
                this.name = name2;
                this.signatureBlockFileName = signatureBlockFileName2;
                this.signatureFileName = signatureFileName2;
            }

            /* access modifiers changed from: private */
            /* access modifiers changed from: public */
            private boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            /* access modifiers changed from: private */
            /* access modifiers changed from: public */
            private void addError(ApkVerifier.Issue msg, Object... parameters) {
                this.mErrors.add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            /* access modifiers changed from: private */
            /* access modifiers changed from: public */
            private void addWarning(ApkVerifier.Issue msg, Object... parameters) {
                this.mWarnings.add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            public List<ApkVerifier.IssueWithParams> getErrors() {
                return this.mErrors;
            }

            public List<ApkVerifier.IssueWithParams> getWarnings() {
                return this.mWarnings;
            }
        }
    }

    /* access modifiers changed from: private */
    public static class SignedAttributes {
        private Map<String, List<Asn1OpaqueObject>> mAttrs;

        public SignedAttributes(Collection<Attribute> attrs) throws Pkcs7DecodingException {
            Map<String, List<Asn1OpaqueObject>> result = new HashMap<>(attrs.size());
            for (Attribute attr : attrs) {
                if (result.put(attr.attrType, attr.attrValues) != null) {
                    throw new Pkcs7DecodingException("Duplicate signed attribute: " + attr.attrType);
                }
            }
            this.mAttrs = result;
        }

        private Asn1OpaqueObject getSingleValue(String attrOid) throws Pkcs7DecodingException {
            List<Asn1OpaqueObject> values = this.mAttrs.get(attrOid);
            if (values == null || values.isEmpty()) {
                return null;
            }
            if (values.size() <= 1) {
                return values.get(0);
            }
            throw new Pkcs7DecodingException("Attribute " + attrOid + " has multiple values");
        }

        public String getSingleObjectIdentifierValue(String attrOid) throws Pkcs7DecodingException {
            Asn1OpaqueObject value = getSingleValue(attrOid);
            if (value == null) {
                return null;
            }
            try {
                return ((ObjectIdentifierChoice) Asn1BerParser.parse(value.getEncoded(), ObjectIdentifierChoice.class)).value;
            } catch (Asn1DecodingException e) {
                throw new Pkcs7DecodingException("Failed to decode OBJECT IDENTIFIER", e);
            }
        }

        public byte[] getSingleOctetStringValue(String attrOid) throws Pkcs7DecodingException {
            Asn1OpaqueObject value = getSingleValue(attrOid);
            if (value == null) {
                return null;
            }
            try {
                return ((OctetStringChoice) Asn1BerParser.parse(value.getEncoded(), OctetStringChoice.class)).value;
            } catch (Asn1DecodingException e) {
                throw new Pkcs7DecodingException("Failed to decode OBJECT IDENTIFIER", e);
            }
        }
    }
}
