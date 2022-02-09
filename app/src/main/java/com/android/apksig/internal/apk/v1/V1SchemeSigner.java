package com.android.apksig.internal.apk.v1;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.asn1.Asn1EncodingException;
import com.android.apksig.internal.jar.ManifestWriter;
import com.android.apksig.internal.jar.SignatureFileWriter;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import com.android.apksig.internal.util.Pair;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

public abstract class V1SchemeSigner {
    private static final Attributes.Name ATTRIBUTE_NAME_CREATED_BY = new Attributes.Name("Created-By");
    private static final String ATTRIBUTE_VALUE_MANIFEST_VERSION = "1.0";
    private static final String ATTRIBUTE_VALUE_SIGNATURE_VERSION = "1.0";
    public static final String MANIFEST_ENTRY_NAME = "META-INF/MANIFEST.MF";
    private static final Attributes.Name SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME = new Attributes.Name(V1SchemeConstants.SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME_STR);

    public static class OutputManifestFile {
        public byte[] contents;
        public SortedMap<String, byte[]> individualSectionsContents;
        public Attributes mainSectionAttributes;
    }

    public static class SignerConfig {
        public List<X509Certificate> certificates;
        public String name;
        public PrivateKey privateKey;
        public DigestAlgorithm signatureDigestAlgorithm;
    }

    private V1SchemeSigner() {
    }

    public static DigestAlgorithm getSuggestedSignatureDigestAlgorithm(PublicKey signingKey, int minSdkVersion) throws InvalidKeyException {
        String keyAlgorithm = signingKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            if (minSdkVersion < 18) {
                return DigestAlgorithm.SHA1;
            }
            return DigestAlgorithm.SHA256;
        } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            if (minSdkVersion < 21) {
                return DigestAlgorithm.SHA1;
            }
            return DigestAlgorithm.SHA256;
        } else if (!"EC".equalsIgnoreCase(keyAlgorithm)) {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        } else if (minSdkVersion >= 18) {
            return DigestAlgorithm.SHA256;
        } else {
            throw new InvalidKeyException("ECDSA signatures only supported for minSdkVersion 18 and higher");
        }
    }

    public static String getSafeSignerName(String name) {
        if (name.isEmpty()) {
            throw new IllegalArgumentException("Empty name");
        }
        StringBuilder result = new StringBuilder();
        char[] nameCharsUpperCase = name.toUpperCase(Locale.US).toCharArray();
        for (int i = 0; i < Math.min(nameCharsUpperCase.length, 8); i++) {
            char c = nameCharsUpperCase[i];
            if ((c < 'A' || c > 'Z') && !((c >= '0' && c <= '9') || c == '-' || c == '_')) {
                result.append('_');
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private static MessageDigest getMessageDigestInstance(DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(digestAlgorithm.getJcaMessageDigestAlgorithm());
    }

    public static String getJcaMessageDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        return digestAlgorithm.getJcaMessageDigestAlgorithm();
    }

    public static boolean isJarEntryDigestNeededInManifest(String entryName) {
        if (entryName.endsWith("/")) {
            return false;
        }
        if (!entryName.startsWith("META-INF/")) {
            return true;
        }
        if (entryName.indexOf(47, "META-INF/".length()) != -1) {
            return true;
        }
        String fileNameLowerCase = entryName.substring("META-INF/".length()).toLowerCase(Locale.US);
        return !"manifest.mf".equals(fileNameLowerCase) && !fileNameLowerCase.endsWith(".sf") && !fileNameLowerCase.endsWith(".rsa") && !fileNameLowerCase.endsWith(".dsa") && !fileNameLowerCase.endsWith(".ec") && !fileNameLowerCase.startsWith("sig-");
    }

    public static List<Pair<String, byte[]>> sign(List<SignerConfig> signerConfigs, DigestAlgorithm jarEntryDigestAlgorithm, Map<String, byte[]> jarEntryDigests, List<Integer> apkSigningSchemeIds, byte[] sourceManifestBytes, String createdBy) throws NoSuchAlgorithmException, ApkFormatException, InvalidKeyException, CertificateException, SignatureException {
        if (!signerConfigs.isEmpty()) {
            return signManifest(signerConfigs, jarEntryDigestAlgorithm, apkSigningSchemeIds, createdBy, generateManifestFile(jarEntryDigestAlgorithm, jarEntryDigests, sourceManifestBytes));
        }
        throw new IllegalArgumentException("At least one signer config must be provided");
    }

    public static List<Pair<String, byte[]>> signManifest(List<SignerConfig> signerConfigs, DigestAlgorithm digestAlgorithm, List<Integer> apkSigningSchemeIds, String createdBy, OutputManifestFile manifest) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException {
        if (signerConfigs.isEmpty()) {
            throw new IllegalArgumentException("At least one signer config must be provided");
        }
        List<Pair<String, byte[]>> signatureJarEntries = new ArrayList<>((signerConfigs.size() * 2) + 1);
        byte[] sfBytes = generateSignatureFile(apkSigningSchemeIds, digestAlgorithm, createdBy, manifest);
        for (SignerConfig signerConfig : signerConfigs) {
            String signerName = signerConfig.name;
            try {
                byte[] signatureBlock = generateSignatureBlock(signerConfig, sfBytes);
                signatureJarEntries.add(Pair.of("META-INF/" + signerName + ".SF", sfBytes));
                signatureJarEntries.add(Pair.of("META-INF/" + signerName + "." + signerConfig.certificates.get(0).getPublicKey().getAlgorithm().toUpperCase(Locale.US), signatureBlock));
            } catch (InvalidKeyException e) {
                throw new InvalidKeyException("Failed to sign using signer \"" + signerName + "\"", e);
            } catch (CertificateException e2) {
                throw new CertificateException("Failed to sign using signer \"" + signerName + "\"", e2);
            } catch (SignatureException e3) {
                throw new SignatureException("Failed to sign using signer \"" + signerName + "\"", e3);
            }
        }
        signatureJarEntries.add(Pair.of("META-INF/MANIFEST.MF", manifest.contents));
        return signatureJarEntries;
    }

    public static Set<String> getOutputEntryNames(List<SignerConfig> signerConfigs) {
        Set<String> result = new HashSet<>((signerConfigs.size() * 2) + 1);
        for (SignerConfig signerConfig : signerConfigs) {
            String signerName = signerConfig.name;
            result.add("META-INF/" + signerName + ".SF");
            result.add("META-INF/" + signerName + "." + signerConfig.certificates.get(0).getPublicKey().getAlgorithm().toUpperCase(Locale.US));
        }
        result.add("META-INF/MANIFEST.MF");
        return result;
    }

    public static OutputManifestFile generateManifestFile(DigestAlgorithm jarEntryDigestAlgorithm, Map<String, byte[]> jarEntryDigests, byte[] sourceManifestBytes) throws ApkFormatException {
        Manifest sourceManifest = null;
        if (sourceManifestBytes != null) {
            try {
                sourceManifest = new Manifest(new ByteArrayInputStream(sourceManifestBytes));
            } catch (IOException e) {
                throw new ApkFormatException("Malformed source META-INF/MANIFEST.MF", e);
            }
        }
        ByteArrayOutputStream manifestOut = new ByteArrayOutputStream();
        Attributes mainAttrs = new Attributes();
        if (sourceManifest != null) {
            mainAttrs.putAll(sourceManifest.getMainAttributes());
        } else {
            mainAttrs.put(Attributes.Name.MANIFEST_VERSION, "1.0");
        }
        try {
            ManifestWriter.writeMainSection(manifestOut, mainAttrs);
            List<String> sortedEntryNames = new ArrayList<>(jarEntryDigests.keySet());
            Collections.sort(sortedEntryNames);
            SortedMap<String, byte[]> invidualSectionsContents = new TreeMap<>();
            String entryDigestAttributeName = getEntryDigestAttributeName(jarEntryDigestAlgorithm);
            for (String entryName : sortedEntryNames) {
                checkEntryNameValid(entryName);
                Attributes entryAttrs = new Attributes();
                entryAttrs.putValue(entryDigestAttributeName, Base64.getEncoder().encodeToString(jarEntryDigests.get(entryName)));
                ByteArrayOutputStream sectionOut = new ByteArrayOutputStream();
                try {
                    ManifestWriter.writeIndividualSection(sectionOut, entryName, entryAttrs);
                    byte[] sectionBytes = sectionOut.toByteArray();
                    manifestOut.write(sectionBytes);
                    invidualSectionsContents.put(entryName, sectionBytes);
                } catch (IOException e2) {
                    throw new RuntimeException("Failed to write in-memory MANIFEST.MF", e2);
                }
            }
            OutputManifestFile result = new OutputManifestFile();
            result.contents = manifestOut.toByteArray();
            result.mainSectionAttributes = mainAttrs;
            result.individualSectionsContents = invidualSectionsContents;
            return result;
        } catch (IOException e3) {
            throw new RuntimeException("Failed to write in-memory MANIFEST.MF", e3);
        }
    }

    private static void checkEntryNameValid(String name) throws ApkFormatException {
        char[] charArray = name.toCharArray();
        for (char c : charArray) {
            if (c == '\r' || c == '\n' || c == 0) {
                throw new ApkFormatException(String.format("Unsupported character 0x%1$02x in ZIP entry name \"%2$s\"", Integer.valueOf(c), name));
            }
        }
    }

    private static byte[] generateSignatureFile(List<Integer> apkSignatureSchemeIds, DigestAlgorithm manifestDigestAlgorithm, String createdBy, OutputManifestFile manifest) throws NoSuchAlgorithmException {
        Attributes mainAttrs = new Manifest().getMainAttributes();
        mainAttrs.put(Attributes.Name.SIGNATURE_VERSION, "1.0");
        mainAttrs.put(ATTRIBUTE_NAME_CREATED_BY, createdBy);
        if (!apkSignatureSchemeIds.isEmpty()) {
            StringBuilder attrValue = new StringBuilder();
            for (Integer num : apkSignatureSchemeIds) {
                int id = num.intValue();
                if (attrValue.length() > 0) {
                    attrValue.append(", ");
                }
                attrValue.append(String.valueOf(id));
            }
            mainAttrs.put(SF_ATTRIBUTE_NAME_ANDROID_APK_SIGNED_NAME, attrValue.toString());
        }
        MessageDigest md = getMessageDigestInstance(manifestDigestAlgorithm);
        mainAttrs.putValue(getManifestDigestAttributeName(manifestDigestAlgorithm), Base64.getEncoder().encodeToString(md.digest(manifest.contents)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            SignatureFileWriter.writeMainSection(out, mainAttrs);
            String entryDigestAttributeName = getEntryDigestAttributeName(manifestDigestAlgorithm);
            for (Map.Entry<String, byte[]> manifestSection : manifest.individualSectionsContents.entrySet()) {
                String sectionName = manifestSection.getKey();
                byte[] sectionDigest = md.digest(manifestSection.getValue());
                Attributes attrs = new Attributes();
                attrs.putValue(entryDigestAttributeName, Base64.getEncoder().encodeToString(sectionDigest));
                try {
                    SignatureFileWriter.writeIndividualSection(out, sectionName, attrs);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to write in-memory .SF file", e);
                }
            }
            if (out.size() > 0 && out.size() % 1024 == 0) {
                try {
                    SignatureFileWriter.writeSectionDelimiter(out);
                } catch (IOException e2) {
                    throw new RuntimeException("Failed to write to ByteArrayOutputStream", e2);
                }
            }
            return out.toByteArray();
        } catch (IOException e3) {
            throw new RuntimeException("Failed to write in-memory .SF file", e3);
        }
    }

    private static byte[] generateSignatureBlock(SignerConfig signerConfig, byte[] signatureFileBytes) throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, SignatureException {
        List<X509Certificate> signerCerts = signerConfig.certificates;
        PublicKey publicKey = signerCerts.get(0).getPublicKey();
        DigestAlgorithm digestAlgorithm = signerConfig.signatureDigestAlgorithm;
        Pair<String, AlgorithmIdentifier> signatureAlgs = AlgorithmIdentifier.getSignerInfoSignatureAlgorithm(publicKey, digestAlgorithm);
        String jcaSignatureAlgorithm = signatureAlgs.getFirst();
        try {
            Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
            signature.initSign(signerConfig.privateKey);
            signature.update(signatureFileBytes);
            byte[] signatureBytes = signature.sign();
            try {
                Signature signature2 = Signature.getInstance(jcaSignatureAlgorithm);
                signature2.initVerify(publicKey);
                signature2.update(signatureFileBytes);
                if (!signature2.verify(signatureBytes)) {
                    throw new SignatureException("Signature did not verify");
                }
                try {
                    return ApkSigningBlockUtils.generatePkcs7DerEncodedMessage(signatureBytes, null, signerCerts, AlgorithmIdentifier.getSignerInfoDigestAlgorithmOid(digestAlgorithm), signatureAlgs.getSecond());
                } catch (Asn1EncodingException | CertificateEncodingException e) {
                    throw new SignatureException("Failed to encode signature block");
                }
            } catch (InvalidKeyException e2) {
                throw new InvalidKeyException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using public key from certificate", e2);
            } catch (SignatureException e3) {
                throw new SignatureException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using public key from certificate", e3);
            }
        } catch (InvalidKeyException e4) {
            throw new InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e4);
        } catch (SignatureException e5) {
            throw new SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e5);
        }
    }

    private static String getEntryDigestAttributeName(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA1:
                return "SHA1-Digest";
            case SHA256:
                return "SHA-256-Digest";
            default:
                throw new IllegalArgumentException("Unexpected content digest algorithm: " + digestAlgorithm);
        }
    }

    private static String getManifestDigestAttributeName(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case SHA1:
                return "SHA1-Digest-Manifest";
            case SHA256:
                return "SHA-256-Digest-Manifest";
            default:
                throw new IllegalArgumentException("Unexpected content digest algorithm: " + digestAlgorithm);
        }
    }
}
