package com.android.apksigner;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;
import com.android.apksig.util.DataSources;
import com.android.apksigner.OptionsParser;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.conscrypt.OpenSSLProvider;

public class ApkSignerTool {
    private static final String HELP_PAGE_GENERAL = "help.txt";
    private static final String HELP_PAGE_LINEAGE = "help_lineage.txt";
    private static final String HELP_PAGE_ROTATE = "help_rotate.txt";
    private static final String HELP_PAGE_SIGN = "help_sign.txt";
    private static final String HELP_PAGE_VERIFY = "help_verify.txt";
    private static final String VERSION = "0.9";
    public static final int ZIP_MAGIC = 67324752;
    private static MessageDigest md5 = null;
    private static MessageDigest sha1 = null;
    private static MessageDigest sha256 = null;

    public static void main(String[] params) throws Exception {
        if (params.length == 0 || "--help".equals(params[0]) || "-h".equals(params[0])) {
            printUsage(HELP_PAGE_GENERAL);
        } else if ("--version".equals(params[0])) {
            System.out.println(VERSION);
        } else {
            addProviders();
            String cmd = params[0];
            try {
                if ("sign".equals(cmd)) {
                    sign((String[]) Arrays.copyOfRange(params, 1, params.length));
                } else if ("verify".equals(cmd)) {
                    verify((String[]) Arrays.copyOfRange(params, 1, params.length));
                } else if ("rotate".equals(cmd)) {
                    rotate((String[]) Arrays.copyOfRange(params, 1, params.length));
                } else if ("lineage".equals(cmd)) {
                    lineage((String[]) Arrays.copyOfRange(params, 1, params.length));
                } else if ("help".equals(cmd)) {
                    printUsage(HELP_PAGE_GENERAL);
                } else if ("version".equals(cmd)) {
                    System.out.println(VERSION);
                } else {
                    throw new ParameterException("Unsupported command: " + cmd + ". See --help for supported commands");
                }
            } catch (OptionsParser.OptionsException | ParameterException e) {
                System.err.println(e.getMessage());
                System.exit(1);
            }
        }
    }

    private static void addProviders() {
        try {
            Security.addProvider(new OpenSSLProvider());
        } catch (UnsatisfiedLinkError e) {
        }
    }

    private static void sign(String[] params) throws Exception {
        File tmpOutputApk;
        if (params.length == 0) {
            printUsage(HELP_PAGE_SIGN);
            return;
        }
        File outputApk = null;
        File inputApk = null;
        boolean verbose = false;
        boolean v1SigningEnabled = true;
        boolean v2SigningEnabled = true;
        boolean v3SigningEnabled = true;
        boolean v4SigningEnabled = true;
        boolean forceSourceStampOverwrite = false;
        boolean verityEnabled = false;
        boolean debuggableApkPermitted = true;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
        SigningCertificateLineage lineage = null;
        SignerParams sourceStampSignerParams = new SignerParams();
        SigningCertificateLineage sourceStampLineage = null;
        List<ProviderInstallSpec> providers = new ArrayList<>();
        ProviderInstallSpec providerParams = new ProviderInstallSpec();
        OptionsParser optionsParser = new OptionsParser(params);
        String optionOriginalForm = null;
        boolean v4SigningFlagFound = false;
        boolean sourceStampFlagFound = false;
        while (true) {
            String optionName = optionsParser.nextOption();
            if (optionName != null) {
                optionOriginalForm = optionsParser.getOptionOriginalForm();
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage(HELP_PAGE_SIGN);
                } else if ("out".equals(optionName)) {
                    outputApk = new File(optionsParser.getRequiredValue("Output file name"));
                } else if ("in".equals(optionName)) {
                    inputApk = new File(optionsParser.getRequiredValue("Input file name"));
                } else if ("min-sdk-version".equals(optionName)) {
                    minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                    minSdkVersionSpecified = true;
                } else if ("max-sdk-version".equals(optionName)) {
                    maxSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
                } else if ("v1-signing-enabled".equals(optionName)) {
                    v1SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                } else if ("v2-signing-enabled".equals(optionName)) {
                    v2SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                } else if ("v3-signing-enabled".equals(optionName)) {
                    v3SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                } else if ("v4-signing-enabled".equals(optionName)) {
                    v4SigningEnabled = optionsParser.getOptionalBooleanValue(true);
                    v4SigningFlagFound = true;
                } else if ("force-stamp-overwrite".equals(optionName)) {
                    forceSourceStampOverwrite = optionsParser.getOptionalBooleanValue(true);
                } else if ("verity-enabled".equals(optionName)) {
                    verityEnabled = optionsParser.getOptionalBooleanValue(true);
                } else if ("debuggable-apk-permitted".equals(optionName)) {
                    debuggableApkPermitted = optionsParser.getOptionalBooleanValue(true);
                } else if ("next-signer".equals(optionName)) {
                    if (!signerParams.isEmpty()) {
                        signers.add(signerParams);
                        signerParams = new SignerParams();
                    }
                } else if ("ks".equals(optionName)) {
                    signerParams.setKeystoreFile(optionsParser.getRequiredValue("KeyStore file"));
                } else if ("ks-key-alias".equals(optionName)) {
                    signerParams.setKeystoreKeyAlias(optionsParser.getRequiredValue("KeyStore key alias"));
                } else if ("ks-pass".equals(optionName)) {
                    signerParams.setKeystorePasswordSpec(optionsParser.getRequiredValue("KeyStore password"));
                } else if ("key-pass".equals(optionName)) {
                    signerParams.setKeyPasswordSpec(optionsParser.getRequiredValue("Key password"));
                } else if ("pass-encoding".equals(optionName)) {
                    String charsetName = optionsParser.getRequiredValue("Password character encoding");
                    try {
                        signerParams.setPasswordCharset(PasswordRetriever.getCharsetByName(charsetName));
                    } catch (IllegalArgumentException e) {
                        throw new ParameterException("Unsupported password character encoding requested using --pass-encoding: " + charsetName);
                    }
                } else if ("v1-signer-name".equals(optionName)) {
                    signerParams.setV1SigFileBasename(optionsParser.getRequiredValue("JAR signature file basename"));
                } else if ("ks-type".equals(optionName)) {
                    signerParams.setKeystoreType(optionsParser.getRequiredValue("KeyStore type"));
                } else if ("ks-provider-name".equals(optionName)) {
                    signerParams.setKeystoreProviderName(optionsParser.getRequiredValue("JCA KeyStore Provider name"));
                } else if ("ks-provider-class".equals(optionName)) {
                    signerParams.setKeystoreProviderClass(optionsParser.getRequiredValue("JCA KeyStore Provider class name"));
                } else if ("ks-provider-arg".equals(optionName)) {
                    signerParams.setKeystoreProviderArg(optionsParser.getRequiredValue("JCA KeyStore Provider constructor argument"));
                } else if ("key".equals(optionName)) {
                    signerParams.setKeyFile(optionsParser.getRequiredValue("Private key file"));
                } else if ("cert".equals(optionName)) {
                    signerParams.setCertFile(optionsParser.getRequiredValue("Certificate file"));
                } else if ("lineage".equals(optionName)) {
                    lineage = getLineageFromInputFile(new File(optionsParser.getRequiredValue("Lineage File")));
                } else if ("v".equals(optionName) || "verbose".equals(optionName)) {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                } else if ("next-provider".equals(optionName)) {
                    if (!providerParams.isEmpty()) {
                        providers.add(providerParams);
                        providerParams = new ProviderInstallSpec();
                    }
                } else if ("provider-class".equals(optionName)) {
                    providerParams.className = optionsParser.getRequiredValue("JCA Provider class name");
                } else if ("provider-arg".equals(optionName)) {
                    providerParams.constructorParam = optionsParser.getRequiredValue("JCA Provider constructor argument");
                } else if ("provider-pos".equals(optionName)) {
                    providerParams.position = Integer.valueOf(optionsParser.getRequiredIntValue("JCA Provider position"));
                } else if ("stamp-signer".equals(optionName)) {
                    sourceStampFlagFound = true;
                    sourceStampSignerParams = processSignerParams(optionsParser);
                } else if ("stamp-lineage".equals(optionName)) {
                    sourceStampLineage = getLineageFromInputFile(new File(optionsParser.getRequiredValue("Stamp Lineage File")));
                } else {
                    throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                }
            } else {
                if (!signerParams.isEmpty()) {
                    signers.add(signerParams);
                }
                if (!providerParams.isEmpty()) {
                    providers.add(providerParams);
                }
                if (signers.isEmpty()) {
                    throw new ParameterException("At least one signer must be specified");
                }
                String[] params2 = optionsParser.getRemainingParams();
                if (inputApk != null) {
                    if (params2.length > 0) {
                        throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params2[0]);
                    }
                } else if (params2.length < 1) {
                    throw new ParameterException("Missing input APK");
                } else if (params2.length > 1) {
                    throw new ParameterException("Unexpected parameter(s) after input APK (" + params2[1] + ")");
                } else {
                    inputApk = new File(params2[0]);
                }
                if (!minSdkVersionSpecified || minSdkVersion <= maxSdkVersion) {
                    for (ProviderInstallSpec providerInstallSpec : providers) {
                        providerInstallSpec.installProvider();
                    }
                    ApkSigner.SignerConfig sourceStampSignerConfig = null;
                    List<ApkSigner.SignerConfig> signerConfigs = new ArrayList<>(signers.size());
                    int signerNumber = 0;
                    PasswordRetriever passwordRetriever = new PasswordRetriever();
                    try {
                        for (SignerParams signer : signers) {
                            signerNumber++;
                            signer.setName("signer #" + signerNumber);
                            ApkSigner.SignerConfig signerConfig = getSignerConfig(signer, passwordRetriever);
                            if (signerConfig == null) {
                                passwordRetriever.close();
                                return;
                            }
                            signerConfigs.add(signerConfig);
                        }
                        if (sourceStampFlagFound) {
                            sourceStampSignerParams.setName("stamp signer");
                            sourceStampSignerConfig = getSignerConfig(sourceStampSignerParams, passwordRetriever);
                            if (sourceStampSignerConfig == null) {
                                passwordRetriever.close();
                                return;
                            }
                        }
                        passwordRetriever.close();
                        if (outputApk == null) {
                            outputApk = inputApk;
                        }
                        if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
                            tmpOutputApk = File.createTempFile("apksigner", ".apk");
                            tmpOutputApk.deleteOnExit();
                        } else {
                            tmpOutputApk = outputApk;
                        }
                        ApkSigner.Builder apkSignerBuilder = new ApkSigner.Builder(signerConfigs).setInputApk(inputApk).setOutputApk(tmpOutputApk).setOtherSignersSignaturesPreserved(false).setV1SigningEnabled(v1SigningEnabled).setV2SigningEnabled(v2SigningEnabled).setV3SigningEnabled(v3SigningEnabled).setV4SigningEnabled(v4SigningEnabled).setForceSourceStampOverwrite(forceSourceStampOverwrite).setVerityEnabled(verityEnabled).setV4ErrorReportingEnabled(v4SigningEnabled && v4SigningFlagFound).setDebuggableApkPermitted(debuggableApkPermitted).setSigningCertificateLineage(lineage);
                        if (minSdkVersionSpecified) {
                            apkSignerBuilder.setMinSdkVersion(minSdkVersion);
                        }
                        if (v4SigningEnabled) {
                            File outputV4SignatureFile = new File(outputApk.getCanonicalPath() + ".idsig");
                            Files.deleteIfExists(outputV4SignatureFile.toPath());
                            apkSignerBuilder.setV4SignatureOutputFile(outputV4SignatureFile);
                        }
                        if (sourceStampSignerConfig != null) {
                            apkSignerBuilder.setSourceStampSignerConfig(sourceStampSignerConfig).setSourceStampSigningCertificateLineage(sourceStampLineage);
                        }
                        try {
                            apkSignerBuilder.build().sign();
                            if (!tmpOutputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
                                Files.move(tmpOutputApk.toPath(), outputApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
                            }
                            if (verbose) {
                                System.out.println("Signed");
                                return;
                            }
                            return;
                        } catch (MinSdkVersionException e2) {
                            String msg = e2.getMessage();
                            if (!msg.endsWith(".")) {
                                String msg2 = msg + '.';
                            }
                            throw new MinSdkVersionException("Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override", e2);
                        }
                    } catch (Throwable th) {
                        th.addSuppressed(th);
                    }
                } else {
                    throw new ParameterException("Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion + ")");
                }
            }
        }
        printUsage(HELP_PAGE_SIGN);
        return;
        throw th;
    }

    private static ApkSigner.SignerConfig getSignerConfig(SignerParams signer, PasswordRetriever passwordRetriever) {
        String v1SigBasename;
        try {
            signer.loadPrivateKeyAndCerts(passwordRetriever);
            if (signer.getV1SigFileBasename() != null) {
                v1SigBasename = signer.getV1SigFileBasename();
            } else if (signer.getKeystoreKeyAlias() != null) {
                v1SigBasename = signer.getKeystoreKeyAlias();
            } else if (signer.getKeyFile() != null) {
                String keyFileName = new File(signer.getKeyFile()).getName();
                int delimiterIndex = keyFileName.indexOf(46);
                if (delimiterIndex == -1) {
                    v1SigBasename = keyFileName;
                } else {
                    v1SigBasename = keyFileName.substring(0, delimiterIndex);
                }
            } else {
                throw new RuntimeException("Neither KeyStore key alias nor private key file available");
            }
            return new ApkSigner.SignerConfig.Builder(v1SigBasename, signer.getPrivateKey(), signer.getCerts()).build();
        } catch (ParameterException e) {
            System.err.println("Failed to load signer \"" + signer.getName() + "\": " + e.getMessage());
            System.exit(2);
            return null;
        } catch (Exception e2) {
            System.err.println("Failed to load signer \"" + signer.getName() + "\"");
            e2.printStackTrace();
            System.exit(2);
            return null;
        }
    }

    private static void verify(String[] params) throws Exception {
        ApkVerifier.Result result;
        if (params.length == 0) {
            printUsage(HELP_PAGE_VERIFY);
            return;
        }
        File inputApk = null;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        boolean maxSdkVersionSpecified = false;
        boolean printCerts = false;
        boolean verbose = false;
        boolean warningsTreatedAsErrors = false;
        boolean verifySourceStamp = false;
        File v4SignatureFile = null;
        OptionsParser optionsParser = new OptionsParser(params);
        String optionOriginalForm = null;
        String sourceCertDigest = null;
        while (true) {
            String optionName = optionsParser.nextOption();
            if (optionName != null) {
                optionOriginalForm = optionsParser.getOptionOriginalForm();
                if ("min-sdk-version".equals(optionName)) {
                    minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                    minSdkVersionSpecified = true;
                } else if ("max-sdk-version".equals(optionName)) {
                    maxSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
                    maxSdkVersionSpecified = true;
                } else if ("print-certs".equals(optionName)) {
                    printCerts = optionsParser.getOptionalBooleanValue(true);
                } else if ("v".equals(optionName) || "verbose".equals(optionName)) {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                } else if ("Werr".equals(optionName)) {
                    warningsTreatedAsErrors = optionsParser.getOptionalBooleanValue(true);
                } else if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage(HELP_PAGE_VERIFY);
                } else if ("v4-signature-file".equals(optionName)) {
                    v4SignatureFile = new File(optionsParser.getRequiredValue("Input V4 Signature File"));
                } else if ("in".equals(optionName)) {
                    inputApk = new File(optionsParser.getRequiredValue("Input APK file"));
                } else if ("verify-source-stamp".equals(optionName)) {
                    verifySourceStamp = optionsParser.getOptionalBooleanValue(true);
                } else if ("stamp-cert-digest".equals(optionName)) {
                    sourceCertDigest = optionsParser.getRequiredValue("Expected source stamp certificate digest");
                } else {
                    throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                }
            } else {
                String[] params2 = optionsParser.getRemainingParams();
                if (inputApk != null) {
                    if (params2.length > 0) {
                        throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params2[0]);
                    }
                } else if (params2.length < 1) {
                    throw new ParameterException("Missing APK");
                } else if (params2.length > 1) {
                    throw new ParameterException("Unexpected parameter(s) after APK (" + params2[1] + ")");
                } else {
                    inputApk = new File(params2[0]);
                }
                if (!minSdkVersionSpecified || !maxSdkVersionSpecified || minSdkVersion <= maxSdkVersion) {
                    ApkVerifier.Builder apkVerifierBuilder = new ApkVerifier.Builder(inputApk);
                    if (minSdkVersionSpecified) {
                        apkVerifierBuilder.setMinCheckedPlatformVersion(minSdkVersion);
                    }
                    if (maxSdkVersionSpecified) {
                        apkVerifierBuilder.setMaxCheckedPlatformVersion(maxSdkVersion);
                    }
                    if (v4SignatureFile != null) {
                        if (!v4SignatureFile.exists()) {
                            throw new ParameterException("V4 signature file does not exist: " + v4SignatureFile.getCanonicalPath());
                        }
                        apkVerifierBuilder.setV4SignatureFile(v4SignatureFile);
                    }
                    ApkVerifier apkVerifier = apkVerifierBuilder.build();
                    if (verifySourceStamp) {
                        try {
                            result = apkVerifier.verifySourceStamp(sourceCertDigest);
                        } catch (MinSdkVersionException e) {
                            String msg = e.getMessage();
                            if (!msg.endsWith(".")) {
                                String msg2 = msg + '.';
                            }
                            throw new MinSdkVersionException("Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override", e);
                        }
                    } else {
                        result = apkVerifier.verify();
                    }
                    boolean verified = result.isVerified();
                    ApkVerifier.Result.SourceStampInfo sourceStampInfo = result.getSourceStampInfo();
                    boolean warningsEncountered = false;
                    if (verified) {
                        List<X509Certificate> signerCerts = result.getSignerCertificates();
                        if (verbose) {
                            System.out.println("Verifies");
                            System.out.println("Verified using v1 scheme (JAR signing): " + result.isVerifiedUsingV1Scheme());
                            System.out.println("Verified using v2 scheme (APK Signature Scheme v2): " + result.isVerifiedUsingV2Scheme());
                            System.out.println("Verified using v3 scheme (APK Signature Scheme v3): " + result.isVerifiedUsingV3Scheme());
                            System.out.println("Verified using v4 scheme (APK Signature Scheme v4): " + result.isVerifiedUsingV4Scheme());
                            System.out.println("Verified for SourceStamp: " + result.isSourceStampVerified());
                            if (!verifySourceStamp) {
                                System.out.println("Number of signers: " + signerCerts.size());
                            }
                        }
                        if (printCerts) {
                            int signerNumber = 0;
                            for (X509Certificate signerCert : signerCerts) {
                                signerNumber++;
                                printCertificate(signerCert, "Signer #" + signerNumber, verbose);
                            }
                            if (sourceStampInfo != null) {
                                printCertificate(sourceStampInfo.getCertificate(), "Source Stamp Signer", verbose);
                            }
                        }
                    } else {
                        System.err.println("DOES NOT VERIFY");
                    }
                    Iterator<ApkVerifier.IssueWithParams> it = result.getErrors().iterator();
                    while (it.hasNext()) {
                        System.err.println("ERROR: " + it.next());
                    }
                    PrintStream warningsOut = warningsTreatedAsErrors ? System.err : System.out;
                    Iterator<ApkVerifier.IssueWithParams> it2 = result.getWarnings().iterator();
                    while (it2.hasNext()) {
                        warningsEncountered = true;
                        warningsOut.println("WARNING: " + it2.next());
                    }
                    for (ApkVerifier.Result.V1SchemeSignerInfo signer : result.getV1SchemeSigners()) {
                        String signerName = signer.getName();
                        Iterator<ApkVerifier.IssueWithParams> it3 = signer.getErrors().iterator();
                        while (it3.hasNext()) {
                            System.err.println("ERROR: JAR signer " + signerName + ": " + it3.next());
                        }
                        Iterator<ApkVerifier.IssueWithParams> it4 = signer.getWarnings().iterator();
                        while (it4.hasNext()) {
                            warningsEncountered = true;
                            warningsOut.println("WARNING: JAR signer " + signerName + ": " + it4.next());
                        }
                    }
                    for (ApkVerifier.Result.V2SchemeSignerInfo signer2 : result.getV2SchemeSigners()) {
                        String signerName2 = "signer #" + (signer2.getIndex() + 1);
                        Iterator<ApkVerifier.IssueWithParams> it5 = signer2.getErrors().iterator();
                        while (it5.hasNext()) {
                            System.err.println("ERROR: APK Signature Scheme v2 " + signerName2 + ": " + it5.next());
                        }
                        Iterator<ApkVerifier.IssueWithParams> it6 = signer2.getWarnings().iterator();
                        while (it6.hasNext()) {
                            warningsEncountered = true;
                            warningsOut.println("WARNING: APK Signature Scheme v2 " + signerName2 + ": " + it6.next());
                        }
                    }
                    for (ApkVerifier.Result.V3SchemeSignerInfo signer3 : result.getV3SchemeSigners()) {
                        String signerName3 = "signer #" + (signer3.getIndex() + 1);
                        Iterator<ApkVerifier.IssueWithParams> it7 = signer3.getErrors().iterator();
                        while (it7.hasNext()) {
                            System.err.println("ERROR: APK Signature Scheme v3 " + signerName3 + ": " + it7.next());
                        }
                        Iterator<ApkVerifier.IssueWithParams> it8 = signer3.getWarnings().iterator();
                        while (it8.hasNext()) {
                            warningsEncountered = true;
                            warningsOut.println("WARNING: APK Signature Scheme v3 " + signerName3 + ": " + it8.next());
                        }
                    }
                    if (sourceStampInfo != null) {
                        Iterator<ApkVerifier.IssueWithParams> it9 = sourceStampInfo.getErrors().iterator();
                        while (it9.hasNext()) {
                            System.err.println("ERROR: SourceStamp: " + it9.next());
                        }
                        Iterator<ApkVerifier.IssueWithParams> it10 = sourceStampInfo.getWarnings().iterator();
                        while (it10.hasNext()) {
                            warningsOut.println("WARNING: SourceStamp: " + it10.next());
                        }
                    }
                    if (!verified) {
                        System.exit(1);
                        return;
                    } else if (warningsTreatedAsErrors && warningsEncountered) {
                        System.exit(1);
                        return;
                    } else {
                        return;
                    }
                } else {
                    throw new ParameterException("Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion + ")");
                }
            }
        }
        printUsage(HELP_PAGE_VERIFY);
    }

    private static void rotate(String[] params) throws Exception {
        SigningCertificateLineage lineage;
        if (params.length == 0) {
            printUsage(HELP_PAGE_ROTATE);
            return;
        }
        File outputKeyLineage = null;
        File inputKeyLineage = null;
        boolean verbose = false;
        SignerParams oldSignerParams = null;
        SignerParams newSignerParams = null;
        int minSdkVersion = 0;
        List<ProviderInstallSpec> providers = new ArrayList<>();
        ProviderInstallSpec providerParams = new ProviderInstallSpec();
        OptionsParser optionsParser = new OptionsParser(params);
        String optionOriginalForm = null;
        while (true) {
            String optionName = optionsParser.nextOption();
            if (optionName != null) {
                optionOriginalForm = optionsParser.getOptionOriginalForm();
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage(HELP_PAGE_ROTATE);
                } else if ("out".equals(optionName)) {
                    outputKeyLineage = new File(optionsParser.getRequiredValue("Output file name"));
                } else if ("in".equals(optionName)) {
                    inputKeyLineage = new File(optionsParser.getRequiredValue("Input file name"));
                } else if ("old-signer".equals(optionName)) {
                    oldSignerParams = processSignerParams(optionsParser);
                } else if ("new-signer".equals(optionName)) {
                    newSignerParams = processSignerParams(optionsParser);
                } else if ("min-sdk-version".equals(optionName)) {
                    minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                } else if ("v".equals(optionName) || "verbose".equals(optionName)) {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                } else if ("next-provider".equals(optionName)) {
                    if (!providerParams.isEmpty()) {
                        providers.add(providerParams);
                        providerParams = new ProviderInstallSpec();
                    }
                } else if ("provider-class".equals(optionName)) {
                    providerParams.className = optionsParser.getRequiredValue("JCA Provider class name");
                } else if ("provider-arg".equals(optionName)) {
                    providerParams.constructorParam = optionsParser.getRequiredValue("JCA Provider constructor argument");
                } else if ("provider-pos".equals(optionName)) {
                    providerParams.position = Integer.valueOf(optionsParser.getRequiredIntValue("JCA Provider position"));
                } else {
                    throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                }
            } else {
                if (!providerParams.isEmpty()) {
                    providers.add(providerParams);
                }
                if (oldSignerParams.isEmpty()) {
                    throw new ParameterException("Signer parameters for old signer not present");
                } else if (newSignerParams.isEmpty()) {
                    throw new ParameterException("Signer parameters for new signer not present");
                } else if (outputKeyLineage == null) {
                    throw new ParameterException("Output lineage file parameter not present");
                } else {
                    String[] params2 = optionsParser.getRemainingParams();
                    if (params2.length > 0) {
                        throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params2[0]);
                    }
                    for (ProviderInstallSpec providerInstallSpec : providers) {
                        providerInstallSpec.installProvider();
                    }
                    PasswordRetriever passwordRetriever = new PasswordRetriever();
                    try {
                        oldSignerParams.setName("old signer");
                        loadPrivateKeyAndCerts(oldSignerParams, passwordRetriever);
                        SigningCertificateLineage.SignerConfig oldSignerConfig = new SigningCertificateLineage.SignerConfig.Builder(oldSignerParams.getPrivateKey(), oldSignerParams.getCerts().get(0)).build();
                        newSignerParams.setName("new signer");
                        loadPrivateKeyAndCerts(newSignerParams, passwordRetriever);
                        SigningCertificateLineage.SignerConfig newSignerConfig = new SigningCertificateLineage.SignerConfig.Builder(newSignerParams.getPrivateKey(), newSignerParams.getCerts().get(0)).build();
                        if (inputKeyLineage != null) {
                            SigningCertificateLineage lineage2 = getLineageFromInputFile(inputKeyLineage);
                            lineage2.updateSignerCapabilities(oldSignerConfig, oldSignerParams.getSignerCapabilitiesBuilder().build());
                            lineage = lineage2.spawnDescendant(oldSignerConfig, newSignerConfig, newSignerParams.getSignerCapabilitiesBuilder().build());
                        } else {
                            lineage = new SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig).setMinSdkVersion(minSdkVersion).setOriginalCapabilities(oldSignerParams.getSignerCapabilitiesBuilder().build()).setNewCapabilities(newSignerParams.getSignerCapabilitiesBuilder().build()).build();
                        }
                        lineage.writeToFile(outputKeyLineage);
                        passwordRetriever.close();
                        if (verbose) {
                            System.out.println("Rotation entry generated.");
                            return;
                        }
                        return;
                    } catch (Throwable th) {
                        th.addSuppressed(th);
                    }
                }
            }
        }
        printUsage(HELP_PAGE_ROTATE);
        return;
        throw th;
    }

    public static void lineage(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage(HELP_PAGE_LINEAGE);
            return;
        }
        boolean verbose = false;
        boolean printCerts = false;
        boolean lineageUpdated = false;
        File inputKeyLineage = null;
        File outputKeyLineage = null;
        OptionsParser optionsParser = new OptionsParser(params);
        List<SignerParams> signers = new ArrayList<>(1);
        while (true) {
            String optionName = optionsParser.nextOption();
            if (optionName != null) {
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage(HELP_PAGE_LINEAGE);
                } else if ("in".equals(optionName)) {
                    inputKeyLineage = new File(optionsParser.getRequiredValue("Input file name"));
                } else if ("out".equals(optionName)) {
                    outputKeyLineage = new File(optionsParser.getRequiredValue("Output file name"));
                } else if ("signer".equals(optionName)) {
                    signers.add(processSignerParams(optionsParser));
                } else if ("v".equals(optionName) || "verbose".equals(optionName)) {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                } else if ("print-certs".equals(optionName)) {
                    printCerts = optionsParser.getOptionalBooleanValue(true);
                } else {
                    throw new ParameterException("Unsupported option: " + optionsParser.getOptionOriginalForm() + ". See --help for supported options.");
                }
            } else if (inputKeyLineage == null) {
                throw new ParameterException("Input lineage file parameter not present");
            } else {
                SigningCertificateLineage lineage = getLineageFromInputFile(inputKeyLineage);
                PasswordRetriever passwordRetriever = new PasswordRetriever();
                for (int i = 0; i < signers.size(); i++) {
                    try {
                        SignerParams signerParams = signers.get(i);
                        signerParams.setName("signer #" + (i + 1));
                        loadPrivateKeyAndCerts(signerParams, passwordRetriever);
                        SigningCertificateLineage.SignerConfig signerConfig = new SigningCertificateLineage.SignerConfig.Builder(signerParams.getPrivateKey(), signerParams.getCerts().get(0)).build();
                        try {
                            SigningCertificateLineage.SignerCapabilities origCapabilities = lineage.getSignerCapabilities(signerConfig);
                            lineage.updateSignerCapabilities(signerConfig, signerParams.getSignerCapabilitiesBuilder().build());
                            if (!origCapabilities.equals(lineage.getSignerCapabilities(signerConfig))) {
                                lineageUpdated = true;
                                if (verbose) {
                                    System.out.println("Updated signer capabilities for " + signerParams.getName() + ".");
                                }
                            } else if (verbose) {
                                System.out.println("The provided signer capabilities for " + signerParams.getName() + " are unchanged.");
                            }
                        } catch (IllegalArgumentException e) {
                            throw new ParameterException("The signer " + signerParams.getName() + " was not found in the specified lineage.");
                        }
                    } catch (Throwable th) {
                        th.addSuppressed(th);
                    }
                }
                passwordRetriever.close();
                if (printCerts) {
                    List<X509Certificate> signingCerts = lineage.getCertificatesInLineage();
                    for (int i2 = 0; i2 < signingCerts.size(); i2++) {
                        X509Certificate signerCert = signingCerts.get(i2);
                        SigningCertificateLineage.SignerCapabilities signerCapabilities = lineage.getSignerCapabilities(signerCert);
                        printCertificate(signerCert, "Signer #" + (i2 + 1) + " in lineage", verbose);
                        printCapabilities(signerCapabilities);
                    }
                }
                if (!lineageUpdated) {
                    return;
                }
                if (outputKeyLineage != null) {
                    lineage.writeToFile(outputKeyLineage);
                    if (verbose) {
                        System.out.println("Updated lineage saved to " + outputKeyLineage + ".");
                        return;
                    }
                    return;
                }
                throw new ParameterException("The lineage was modified but an output file for the lineage was not specified");
            }
        }
        printUsage(HELP_PAGE_LINEAGE);
        return;
        throw th;
    }

    private static SigningCertificateLineage getLineageFromInputFile(File inputLineageFile) throws ParameterException {
        try {
            RandomAccessFile f = new RandomAccessFile(inputLineageFile, "r");
            try {
                if (f.length() < 4) {
                    throw new ParameterException("The input file is not a valid lineage file.");
                }
                int magicValue = DataSources.asDataSource(f).getByteBuffer(0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                if (magicValue == 1056913873) {
                    SigningCertificateLineage readFromFile = SigningCertificateLineage.readFromFile(inputLineageFile);
                    f.close();
                    return readFromFile;
                } else if (magicValue == 67324752) {
                    SigningCertificateLineage readFromApkFile = SigningCertificateLineage.readFromApkFile(inputLineageFile);
                    f.close();
                    return readFromApkFile;
                } else {
                    throw new ParameterException("The input file is not a valid lineage file.");
                }
            } catch (Throwable th) {
                th.addSuppressed(th);
            }
            throw th;
        } catch (ApkFormatException | IOException | IllegalArgumentException e) {
            throw new ParameterException(e.getMessage());
        }
    }

    private static SignerParams processSignerParams(OptionsParser optionsParser) throws OptionsParser.OptionsException, ParameterException {
        SignerParams signerParams = new SignerParams();
        while (true) {
            String optionName = optionsParser.nextOption();
            if (optionName != null) {
                if (!"ks".equals(optionName)) {
                    if (!"ks-key-alias".equals(optionName)) {
                        if (!"ks-pass".equals(optionName)) {
                            if (!"key-pass".equals(optionName)) {
                                if (!"pass-encoding".equals(optionName)) {
                                    if (!"ks-type".equals(optionName)) {
                                        if (!"ks-provider-name".equals(optionName)) {
                                            if (!"ks-provider-class".equals(optionName)) {
                                                if (!"ks-provider-arg".equals(optionName)) {
                                                    if (!"key".equals(optionName)) {
                                                        if (!"cert".equals(optionName)) {
                                                            if (!"set-installed-data".equals(optionName)) {
                                                                if (!"set-shared-uid".equals(optionName)) {
                                                                    if (!"set-permission".equals(optionName)) {
                                                                        if (!"set-rollback".equals(optionName)) {
                                                                            if (!"set-auth".equals(optionName)) {
                                                                                optionsParser.putOption();
                                                                                break;
                                                                            }
                                                                            signerParams.getSignerCapabilitiesBuilder().setAuth(optionsParser.getOptionalBooleanValue(true));
                                                                        } else {
                                                                            signerParams.getSignerCapabilitiesBuilder().setRollback(optionsParser.getOptionalBooleanValue(true));
                                                                        }
                                                                    } else {
                                                                        signerParams.getSignerCapabilitiesBuilder().setPermission(optionsParser.getOptionalBooleanValue(true));
                                                                    }
                                                                } else {
                                                                    signerParams.getSignerCapabilitiesBuilder().setSharedUid(optionsParser.getOptionalBooleanValue(true));
                                                                }
                                                            } else {
                                                                signerParams.getSignerCapabilitiesBuilder().setInstalledData(optionsParser.getOptionalBooleanValue(true));
                                                            }
                                                        } else {
                                                            signerParams.setCertFile(optionsParser.getRequiredValue("Certificate file"));
                                                        }
                                                    } else {
                                                        signerParams.setKeyFile(optionsParser.getRequiredValue("Private key file"));
                                                    }
                                                } else {
                                                    signerParams.setKeystoreProviderArg(optionsParser.getRequiredValue("JCA KeyStore Provider constructor argument"));
                                                }
                                            } else {
                                                signerParams.setKeystoreProviderClass(optionsParser.getRequiredValue("JCA KeyStore Provider class name"));
                                            }
                                        } else {
                                            signerParams.setKeystoreProviderName(optionsParser.getRequiredValue("JCA KeyStore Provider name"));
                                        }
                                    } else {
                                        signerParams.setKeystoreType(optionsParser.getRequiredValue("KeyStore type"));
                                    }
                                } else {
                                    String charsetName = optionsParser.getRequiredValue("Password character encoding");
                                    try {
                                        signerParams.setPasswordCharset(PasswordRetriever.getCharsetByName(charsetName));
                                    } catch (IllegalArgumentException e) {
                                        throw new ParameterException("Unsupported password character encoding requested using --pass-encoding: " + charsetName);
                                    }
                                }
                            } else {
                                signerParams.setKeyPasswordSpec(optionsParser.getRequiredValue("Key password"));
                            }
                        } else {
                            signerParams.setKeystorePasswordSpec(optionsParser.getRequiredValue("KeyStore password"));
                        }
                    } else {
                        signerParams.setKeystoreKeyAlias(optionsParser.getRequiredValue("KeyStore key alias"));
                    }
                } else {
                    signerParams.setKeystoreFile(optionsParser.getRequiredValue("KeyStore file"));
                }
            } else {
                break;
            }
        }
        if (!signerParams.isEmpty()) {
            return signerParams;
        }
        throw new ParameterException("Signer specified without arguments");
    }

    private static void printUsage(String page) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(ApkSignerTool.class.getResourceAsStream(page), StandardCharsets.UTF_8));
            while (true) {
                try {
                    String line = in.readLine();
                    if (line != null) {
                        System.out.println(line);
                    } else {
                        in.close();
                        return;
                    }
                } catch (Throwable th) {
                    th.addSuppressed(th);
                }
            }
            throw th;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    public static void printCertificate(X509Certificate cert, String name, boolean verbose) throws NoSuchAlgorithmException, CertificateEncodingException {
        DSAParams dsaParams;
        String str;
        if (cert == null) {
            throw new NullPointerException("cert == null");
        }
        if (sha256 == null || sha1 == null || md5 == null) {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha1 = MessageDigest.getInstance("SHA-1");
            md5 = MessageDigest.getInstance("MD5");
        }
        System.out.println(name + " certificate DN: " + cert.getSubjectDN());
        byte[] encodedCert = cert.getEncoded();
        System.out.println(name + " certificate SHA-256 digest: " + HexEncoding.encode(sha256.digest(encodedCert)));
        System.out.println(name + " certificate SHA-1 digest: " + HexEncoding.encode(sha1.digest(encodedCert)));
        System.out.println(name + " certificate MD5 digest: " + HexEncoding.encode(md5.digest(encodedCert)));
        if (verbose) {
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(name + " key algorithm: " + publicKey.getAlgorithm());
            int keySize = -1;
            if (publicKey instanceof RSAKey) {
                keySize = ((RSAKey) publicKey).getModulus().bitLength();
            } else if (publicKey instanceof ECKey) {
                keySize = ((ECKey) publicKey).getParams().getOrder().bitLength();
            } else if ((publicKey instanceof DSAKey) && (dsaParams = ((DSAKey) publicKey).getParams()) != null) {
                keySize = dsaParams.getP().bitLength();
            }
            PrintStream printStream = System.out;
            StringBuilder append = new StringBuilder().append(name).append(" key size (bits): ");
            if (keySize != -1) {
                str = String.valueOf(keySize);
            } else {
                str = "n/a";
            }
            printStream.println(append.append(str).toString());
            byte[] encodedKey = publicKey.getEncoded();
            System.out.println(name + " public key SHA-256 digest: " + HexEncoding.encode(sha256.digest(encodedKey)));
            System.out.println(name + " public key SHA-1 digest: " + HexEncoding.encode(sha1.digest(encodedKey)));
            System.out.println(name + " public key MD5 digest: " + HexEncoding.encode(md5.digest(encodedKey)));
        }
    }

    public static void printCapabilities(SigningCertificateLineage.SignerCapabilities capabilities) {
        System.out.println("Has installed data capability: " + capabilities.hasInstalledData());
        System.out.println("Has shared UID capability    : " + capabilities.hasSharedUid());
        System.out.println("Has permission capability    : " + capabilities.hasPermission());
        System.out.println("Has rollback capability      : " + capabilities.hasRollback());
        System.out.println("Has auth capability          : " + capabilities.hasAuth());
    }

    /* access modifiers changed from: private */
    public static class ProviderInstallSpec {
        String className;
        String constructorParam;
        Integer position;

        private ProviderInstallSpec() {
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private boolean isEmpty() {
            return this.className == null && this.constructorParam == null && this.position == null;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void installProvider() throws Exception {
            Provider provider;
            if (this.className == null) {
                throw new ParameterException("JCA Provider class name (--provider-class) must be specified");
            }
            Class<?> providerClass = Class.forName(this.className);
            if (!Provider.class.isAssignableFrom(providerClass)) {
                throw new ParameterException("JCA Provider class " + providerClass + " not subclass of " + Provider.class.getName());
            }
            if (this.constructorParam != null) {
                provider = (Provider) providerClass.getConstructor(String.class).newInstance(this.constructorParam);
            } else {
                provider = (Provider) providerClass.getConstructor(new Class[0]).newInstance(new Object[0]);
            }
            if (this.position == null) {
                Security.addProvider(provider);
            } else {
                Security.insertProviderAt(provider, this.position.intValue());
            }
        }
    }

    private static void loadPrivateKeyAndCerts(SignerParams params, PasswordRetriever passwordRetriever) throws ParameterException {
        try {
            params.loadPrivateKeyAndCerts(passwordRetriever);
            if (params.getKeystoreKeyAlias() != null) {
                params.setName(params.getKeystoreKeyAlias());
            } else if (params.getKeyFile() != null) {
                String keyFileName = new File(params.getKeyFile()).getName();
                int delimiterIndex = keyFileName.indexOf(46);
                if (delimiterIndex == -1) {
                    params.setName(keyFileName);
                } else {
                    params.setName(keyFileName.substring(0, delimiterIndex));
                }
            } else {
                throw new RuntimeException("Neither KeyStore key alias nor private key file available for " + params.getName());
            }
        } catch (ParameterException e) {
            throw new ParameterException("Failed to load signer \"" + params.getName() + "\":" + e.getMessage());
        } catch (Exception e2) {
            e2.printStackTrace();
            throw new ParameterException("Failed to load signer \"" + params.getName() + "\"");
        }
    }
}
