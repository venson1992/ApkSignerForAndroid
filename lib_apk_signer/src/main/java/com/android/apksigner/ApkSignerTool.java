//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.android.apksigner;

import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSigner.Builder;
import com.android.apksig.ApkSigner.SignerConfig;
import com.android.apksig.ApkVerifier;
import com.android.apksig.ApkVerifier.IssueWithParams;
import com.android.apksig.ApkVerifier.Result;
import com.android.apksig.ApkVerifier.Result.SourceStampInfo;
import com.android.apksig.ApkVerifier.Result.V1SchemeSignerInfo;
import com.android.apksig.ApkVerifier.Result.V2SchemeSignerInfo;
import com.android.apksig.ApkVerifier.Result.V3SchemeSignerInfo;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.SigningCertificateLineage.SignerCapabilities;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.MinSdkVersionException;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksigner.OptionsParser.OptionsException;

import org.conscrypt.OpenSSLProvider;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
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

public class ApkSignerTool {
    private static final String VERSION = "0.9";
    private static final String HELP_PAGE_GENERAL = "help.txt";
    private static final String HELP_PAGE_SIGN = "help_sign.txt";
    private static final String HELP_PAGE_VERIFY = "help_verify.txt";
    private static final String HELP_PAGE_ROTATE = "help_rotate.txt";
    private static final String HELP_PAGE_LINEAGE = "help_lineage.txt";
    private static MessageDigest sha256 = null;
    private static MessageDigest sha1 = null;
    private static MessageDigest md5 = null;
    public static final int ZIP_MAGIC = 67324752;

    public ApkSignerTool() {
    }

    public static void cmd(String[] params) throws Exception {
        if (params.length != 0 && !"--help".equals(params[0]) && !"-h".equals(params[0])) {
            if ("--version".equals(params[0])) {
                System.out.println("0.9");
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
                        printUsage("help.txt");
                    } else if ("version".equals(cmd)) {
                        System.out.println("0.9");
                    } else {
                        throw new ParameterException("Unsupported command: " + cmd + ". See --help for supported commands");
                    }
                } catch (OptionsException | ParameterException var3) {
                    System.err.println(var3.getMessage());
                    System.exit(1);
                }
            }
        } else {
            printUsage("help.txt");
        }
    }

    private static void addProviders() {
        try {
            Security.addProvider(new OpenSSLProvider());
        } catch (UnsatisfiedLinkError var1) {
        }

    }

    private static void sign(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage("help_sign.txt");
        } else {
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
            int maxSdkVersion = 2147483647;
            List<SignerParams> signers = new ArrayList(1);
            SignerParams signerParams = new SignerParams();
            SigningCertificateLineage lineage = null;
            SignerParams sourceStampSignerParams = new SignerParams();
            SigningCertificateLineage sourceStampLineage = null;
            List<ApkSignerTool.ProviderInstallSpec> providers = new ArrayList();
            ApkSignerTool.ProviderInstallSpec providerParams = new ApkSignerTool.ProviderInstallSpec();
            OptionsParser optionsParser = new OptionsParser(params);
            String optionOriginalForm = null;
            boolean v4SigningFlagFound = false;
            boolean sourceStampFlagFound = false;

            String optionName;
            while ((optionName = optionsParser.nextOption()) != null) {
                optionOriginalForm = optionsParser.getOptionOriginalForm();
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage("help_sign.txt");
                    return;
                }

                if ("out".equals(optionName)) {
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
                    } catch (IllegalArgumentException var35) {
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
                } else {
                    File stampLineageFile;
                    if ("lineage".equals(optionName)) {
                        stampLineageFile = new File(optionsParser.getRequiredValue("Lineage File"));
                        lineage = getLineageFromInputFile(stampLineageFile);
                    } else if (!"v".equals(optionName) && !"verbose".equals(optionName)) {
                        if ("next-provider".equals(optionName)) {
                            if (!providerParams.isEmpty()) {
                                providers.add(providerParams);
                                providerParams = new ApkSignerTool.ProviderInstallSpec();
                            }
                        } else if ("provider-class".equals(optionName)) {
                            providerParams.className = optionsParser.getRequiredValue("JCA Provider class name");
                        } else if ("provider-arg".equals(optionName)) {
                            providerParams.constructorParam = optionsParser.getRequiredValue("JCA Provider constructor argument");
                        } else if ("provider-pos".equals(optionName)) {
                            providerParams.position = optionsParser.getRequiredIntValue("JCA Provider position");
                        } else if ("stamp-signer".equals(optionName)) {
                            sourceStampFlagFound = true;
                            sourceStampSignerParams = processSignerParams(optionsParser);
                        } else {
                            if (!"stamp-lineage".equals(optionName)) {
                                throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                            }

                            stampLineageFile = new File(optionsParser.getRequiredValue("Stamp Lineage File"));
                            sourceStampLineage = getLineageFromInputFile(stampLineageFile);
                        }
                    } else {
                        verbose = optionsParser.getOptionalBooleanValue(true);
                    }
                }
            }

            if (!signerParams.isEmpty()) {
                signers.add(signerParams);
            }

            signerParams = null;
            if (!providerParams.isEmpty()) {
                providers.add(providerParams);
            }

            providerParams = null;
            if (signers.isEmpty()) {
                throw new ParameterException("At least one signer must be specified");
            } else {
                params = optionsParser.getRemainingParams();
                if (inputApk != null) {
                    if (params.length > 0) {
                        throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params[0]);
                    }
                } else {
                    if (params.length < 1) {
                        throw new ParameterException("Missing input APK");
                    }

                    if (params.length > 1) {
                        throw new ParameterException("Unexpected parameter(s) after input APK (" + params[1] + ")");
                    }

                    inputApk = new File(params[0]);
                }

                if (minSdkVersionSpecified && minSdkVersion > maxSdkVersion) {
                    throw new ParameterException("Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion + ")");
                } else {
                    Iterator var39 = providers.iterator();

                    while (var39.hasNext()) {
                        ApkSignerTool.ProviderInstallSpec providerInstallSpec = (ApkSignerTool.ProviderInstallSpec) var39.next();
                        providerInstallSpec.installProvider();
                    }

                    SignerConfig sourceStampSignerConfig = null;
                    List<SignerConfig> signerConfigs = new ArrayList(signers.size());
                    int signerNumber = 0;
                    PasswordRetriever passwordRetriever = new PasswordRetriever();

                    label225:
                    {
                        label334:
                        {
                            try {
                                Iterator var30 = signers.iterator();

                                while (var30.hasNext()) {
                                    SignerParams signer = (SignerParams) var30.next();
                                    ++signerNumber;
                                    signer.setName("signer #" + signerNumber);
                                    SignerConfig signerConfig = getSignerConfig(signer, passwordRetriever);
                                    if (signerConfig == null) {
                                        break label225;
                                    }

                                    signerConfigs.add(signerConfig);
                                }

                                if (sourceStampFlagFound) {
                                    sourceStampSignerParams.setName("stamp signer");
                                    sourceStampSignerConfig = getSignerConfig(sourceStampSignerParams, passwordRetriever);
                                    if (sourceStampSignerConfig == null) {
                                        break label334;
                                    }
                                }
                            } catch (Throwable var37) {
                                try {
                                    passwordRetriever.close();
                                } catch (Throwable var34) {
                                    var37.addSuppressed(var34);
                                }

                                throw var37;
                            }

                            passwordRetriever.close();
                            if (outputApk == null) {
                                outputApk = inputApk;
                            }

                            File tmpOutputApk;
                            if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
                                tmpOutputApk = File.createTempFile("apksigner", ".apk");
                                tmpOutputApk.deleteOnExit();
                            } else {
                                tmpOutputApk = outputApk;
                            }

                            Builder apkSignerBuilder = (new Builder(signerConfigs))
                                    .setInputApk(inputApk)
                                    .setOutputApk(tmpOutputApk)
                                    .setOtherSignersSignaturesPreserved(false)
                                    .setV1SigningEnabled(v1SigningEnabled)
                                    .setV2SigningEnabled(v2SigningEnabled)
                                    .setV3SigningEnabled(v3SigningEnabled)
                                    .setV4SigningEnabled(v4SigningEnabled)
                                    /*.setForceSourceStampOverwrite(forceSourceStampOverwrite)*/
                                    /*.setVerityEnabled(verityEnabled)*/
                                    .setV4ErrorReportingEnabled(v4SigningEnabled && v4SigningFlagFound)
                                    .setDebuggableApkPermitted(debuggableApkPermitted)
                                    .setSigningCertificateLineage(lineage);
                            if (minSdkVersionSpecified) {
                                apkSignerBuilder.setMinSdkVersion(minSdkVersion);
                            }

//                            if (v4SigningEnabled) {
//                                File outputV4SignatureFile = new File(outputApk.getCanonicalPath() + ".idsig");
//                                Files.deleteIfExists(outputV4SignatureFile.toPath());
//                                apkSignerBuilder.setV4SignatureOutputFile(outputV4SignatureFile);
//                            }

                            if (sourceStampSignerConfig != null) {
                                apkSignerBuilder
                                        .setSourceStampSignerConfig(sourceStampSignerConfig)
                                /*.setSourceStampSigningCertificateLineage(sourceStampLineage)*/;
                            }

                            ApkSigner apkSigner = apkSignerBuilder.build();

                            try {
                                apkSigner.sign();
                            } catch (MinSdkVersionException var36) {
                                String msg = var36.getMessage();
                                if (!msg.endsWith(".")) {
                                    msg = msg + '.';
                                }

                                throw new MinSdkVersionException("Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override", var36);
                            }

//                            if (!tmpOutputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
//                                Files.move(tmpOutputApk.toPath(), outputApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
//                            }

                            if (verbose) {
                                System.out.println("Signed");
                            }

                            return;
                        }

                        passwordRetriever.close();
                        return;
                    }

                    passwordRetriever.close();
                }
            }
        }
    }

    private static SignerConfig getSignerConfig(SignerParams signer, PasswordRetriever passwordRetriever) {
        try {
            signer.loadPrivateKeyAndCerts(passwordRetriever);
        } catch (ParameterException var5) {
            System.err.println("Failed to load signer \"" + signer.getName() + "\": " + var5.getMessage());
            System.exit(2);
            return null;
        } catch (Exception var6) {
            System.err.println("Failed to load signer \"" + signer.getName() + "\"");
            var6.printStackTrace();
            System.exit(2);
            return null;
        }

        String v1SigBasename;
        if (signer.getV1SigFileBasename() != null) {
            v1SigBasename = signer.getV1SigFileBasename();
        } else if (signer.getKeystoreKeyAlias() != null) {
            v1SigBasename = signer.getKeystoreKeyAlias();
        } else {
            if (signer.getKeyFile() == null) {
                throw new RuntimeException("Neither KeyStore key alias nor private key file available");
            }

            String keyFileName = (new File(signer.getKeyFile())).getName();
            int delimiterIndex = keyFileName.indexOf(46);
            if (delimiterIndex == -1) {
                v1SigBasename = keyFileName;
            } else {
                v1SigBasename = keyFileName.substring(0, delimiterIndex);
            }
        }

        SignerConfig signerConfig = (new com.android.apksig.ApkSigner.SignerConfig.Builder(v1SigBasename, signer.getPrivateKey(), signer.getCerts())).build();
        return signerConfig;
    }

    private static void verify(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage("help_verify.txt");
        } else {
            File inputApk = null;
            int minSdkVersion = 1;
            boolean minSdkVersionSpecified = false;
            int maxSdkVersion = 2147483647;
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
                while (true) {
                    while (true) {
                        while (true) {
                            while (true) {
                                String optionName;
                                while ((optionName = optionsParser.nextOption()) != null) {
                                    optionOriginalForm = optionsParser.getOptionOriginalForm();
                                    if (!"min-sdk-version".equals(optionName)) {
                                        if (!"max-sdk-version".equals(optionName)) {
                                            if (!"print-certs".equals(optionName)) {
                                                if (!"v".equals(optionName) && !"verbose".equals(optionName)) {
                                                    if (!"Werr".equals(optionName)) {
                                                        if ("help".equals(optionName) || "h".equals(optionName)) {
                                                            printUsage("help_verify.txt");
                                                            return;
                                                        }

                                                        if ("v4-signature-file".equals(optionName)) {
                                                            v4SignatureFile = new File(optionsParser.getRequiredValue("Input V4 Signature File"));
                                                        } else if ("in".equals(optionName)) {
                                                            inputApk = new File(optionsParser.getRequiredValue("Input APK file"));
                                                        } else if ("verify-source-stamp".equals(optionName)) {
                                                            verifySourceStamp = optionsParser.getOptionalBooleanValue(true);
                                                        } else {
                                                            if (!"stamp-cert-digest".equals(optionName)) {
                                                                throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                                                            }

                                                            sourceCertDigest = optionsParser.getRequiredValue("Expected source stamp certificate digest");
                                                        }
                                                    } else {
                                                        warningsTreatedAsErrors = optionsParser.getOptionalBooleanValue(true);
                                                    }
                                                } else {
                                                    verbose = optionsParser.getOptionalBooleanValue(true);
                                                }
                                            } else {
                                                printCerts = optionsParser.getOptionalBooleanValue(true);
                                            }
                                        } else {
                                            maxSdkVersion = optionsParser.getRequiredIntValue("Maximum API Level");
                                            maxSdkVersionSpecified = true;
                                        }
                                    } else {
                                        minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                                        minSdkVersionSpecified = true;
                                    }
                                }

                                params = optionsParser.getRemainingParams();
                                if (inputApk != null) {
                                    if (params.length > 0) {
                                        throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params[0]);
                                    }
                                } else {
                                    if (params.length < 1) {
                                        throw new ParameterException("Missing APK");
                                    }

                                    if (params.length > 1) {
                                        throw new ParameterException("Unexpected parameter(s) after APK (" + params[1] + ")");
                                    }

                                    inputApk = new File(params[0]);
                                }

                                if (minSdkVersionSpecified && maxSdkVersionSpecified && minSdkVersion > maxSdkVersion) {
                                    throw new ParameterException("Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion + ")");
                                }

                                com.android.apksig.ApkVerifier.Builder apkVerifierBuilder = new com.android.apksig.ApkVerifier.Builder(inputApk);
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

                                Result result;
                                try {
                                    result = /*verifySourceStamp ? apkVerifier.verifySourceStamp(sourceCertDigest) :*/ apkVerifier.verify();
                                } catch (MinSdkVersionException var27) {
                                    String msg = var27.getMessage();
                                    if (!msg.endsWith(".")) {
                                        msg = msg + '.';
                                    }

                                    throw new MinSdkVersionException("Failed to determine APK's minimum supported platform version. Use --min-sdk-version to override", var27);
                                }

                                boolean verified = result.isVerified();
                                SourceStampInfo sourceStampInfo = result.getSourceStampInfo();
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
                                        Iterator var23 = signerCerts.iterator();

                                        while (var23.hasNext()) {
                                            X509Certificate signerCert = (X509Certificate) var23.next();
                                            ++signerNumber;
                                            printCertificate(signerCert, "Signer #" + signerNumber, verbose);
                                        }

                                        if (sourceStampInfo != null) {
                                            printCertificate(sourceStampInfo.getCertificate(), "Source Stamp Signer", verbose);
                                        }
                                    }
                                } else {
                                    System.err.println("DOES NOT VERIFY");
                                }

                                Iterator var29 = result.getErrors().iterator();

                                while (var29.hasNext()) {
                                    IssueWithParams error = (IssueWithParams) var29.next();
                                    System.err.println("ERROR: " + error);
                                }

                                PrintStream warningsOut = warningsTreatedAsErrors ? System.err : System.out;
                                Iterator var32 = result.getWarnings().iterator();

                                IssueWithParams warning;
                                while (var32.hasNext()) {
                                    warning = (IssueWithParams) var32.next();
                                    warningsEncountered = true;
                                    warningsOut.println("WARNING: " + warning);
                                }

                                var32 = result.getV1SchemeSigners().iterator();

                                Iterator var25;
                                String signerName;
                                while (var32.hasNext()) {
                                    V1SchemeSignerInfo signer = (V1SchemeSignerInfo) var32.next();
                                    signerName = signer.getName();
                                    var25 = signer.getErrors().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        System.err.println("ERROR: JAR signer " + signerName + ": " + warning);
                                    }

                                    var25 = signer.getWarnings().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        warningsEncountered = true;
                                        warningsOut.println("WARNING: JAR signer " + signerName + ": " + warning);
                                    }
                                }

                                var32 = result.getV2SchemeSigners().iterator();

                                while (var32.hasNext()) {
                                    V2SchemeSignerInfo signer = (V2SchemeSignerInfo) var32.next();
                                    signerName = "signer #" + (signer.getIndex() + 1);
                                    var25 = signer.getErrors().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        System.err.println("ERROR: APK Signature Scheme v2 " + signerName + ": " + warning);
                                    }

                                    var25 = signer.getWarnings().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        warningsEncountered = true;
                                        warningsOut.println("WARNING: APK Signature Scheme v2 " + signerName + ": " + warning);
                                    }
                                }

                                var32 = result.getV3SchemeSigners().iterator();

                                while (var32.hasNext()) {
                                    V3SchemeSignerInfo signer = (V3SchemeSignerInfo) var32.next();
                                    signerName = "signer #" + (signer.getIndex() + 1);
                                    var25 = signer.getErrors().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        System.err.println("ERROR: APK Signature Scheme v3 " + signerName + ": " + warning);
                                    }

                                    var25 = signer.getWarnings().iterator();

                                    while (var25.hasNext()) {
                                        warning = (IssueWithParams) var25.next();
                                        warningsEncountered = true;
                                        warningsOut.println("WARNING: APK Signature Scheme v3 " + signerName + ": " + warning);
                                    }
                                }

                                if (sourceStampInfo != null) {
                                    var32 = sourceStampInfo.getErrors().iterator();

                                    while (var32.hasNext()) {
                                        warning = (IssueWithParams) var32.next();
                                        System.err.println("ERROR: SourceStamp: " + warning);
                                    }

                                    var32 = sourceStampInfo.getWarnings().iterator();

                                    while (var32.hasNext()) {
                                        warning = (IssueWithParams) var32.next();
                                        warningsOut.println("WARNING: SourceStamp: " + warning);
                                    }
                                }

                                if (!verified) {
                                    System.exit(1);
                                    return;
                                }

                                if (warningsTreatedAsErrors && warningsEncountered) {
                                    System.exit(1);
                                    return;
                                }

                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    private static void rotate(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage("help_rotate.txt");
        } else {
            File outputKeyLineage = null;
            File inputKeyLineage = null;
            boolean verbose = false;
            SignerParams oldSignerParams = null;
            SignerParams newSignerParams = null;
            int minSdkVersion = 0;
            List<ApkSignerTool.ProviderInstallSpec> providers = new ArrayList();
            ApkSignerTool.ProviderInstallSpec providerParams = new ApkSignerTool.ProviderInstallSpec();
            OptionsParser optionsParser = new OptionsParser(params);
            String optionOriginalForm = null;

            String optionName;
            while ((optionName = optionsParser.nextOption()) != null) {
                optionOriginalForm = optionsParser.getOptionOriginalForm();
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage("help_rotate.txt");
                    return;
                }

                if ("out".equals(optionName)) {
                    outputKeyLineage = new File(optionsParser.getRequiredValue("Output file name"));
                } else if ("in".equals(optionName)) {
                    inputKeyLineage = new File(optionsParser.getRequiredValue("Input file name"));
                } else if ("old-signer".equals(optionName)) {
                    oldSignerParams = processSignerParams(optionsParser);
                } else if ("new-signer".equals(optionName)) {
                    newSignerParams = processSignerParams(optionsParser);
                } else if ("min-sdk-version".equals(optionName)) {
                    minSdkVersion = optionsParser.getRequiredIntValue("Mininimum API Level");
                } else if (!"v".equals(optionName) && !"verbose".equals(optionName)) {
                    if ("next-provider".equals(optionName)) {
                        if (!providerParams.isEmpty()) {
                            providers.add(providerParams);
                            providerParams = new ApkSignerTool.ProviderInstallSpec();
                        }
                    } else if ("provider-class".equals(optionName)) {
                        providerParams.className = optionsParser.getRequiredValue("JCA Provider class name");
                    } else if ("provider-arg".equals(optionName)) {
                        providerParams.constructorParam = optionsParser.getRequiredValue("JCA Provider constructor argument");
                    } else {
                        if (!"provider-pos".equals(optionName)) {
                            throw new ParameterException("Unsupported option: " + optionOriginalForm + ". See --help for supported options.");
                        }

                        providerParams.position = optionsParser.getRequiredIntValue("JCA Provider position");
                    }
                } else {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                }
            }

            if (!providerParams.isEmpty()) {
                providers.add(providerParams);
            }

            providerParams = null;
            if (oldSignerParams.isEmpty()) {
                throw new ParameterException("Signer parameters for old signer not present");
            } else if (newSignerParams.isEmpty()) {
                throw new ParameterException("Signer parameters for new signer not present");
            } else if (outputKeyLineage == null) {
                throw new ParameterException("Output lineage file parameter not present");
            } else {
                params = optionsParser.getRemainingParams();
                if (params.length > 0) {
                    throw new ParameterException("Unexpected parameter(s) after " + optionOriginalForm + ": " + params[0]);
                } else {
                    Iterator var12 = providers.iterator();

                    while (var12.hasNext()) {
                        ApkSignerTool.ProviderInstallSpec providerInstallSpec = (ApkSignerTool.ProviderInstallSpec) var12.next();
                        providerInstallSpec.installProvider();
                    }

                    PasswordRetriever passwordRetriever = new PasswordRetriever();

                    try {
                        oldSignerParams.setName("old signer");
                        loadPrivateKeyAndCerts(oldSignerParams, passwordRetriever);
                        com.android.apksig.SigningCertificateLineage.SignerConfig oldSignerConfig = (new com.android.apksig.SigningCertificateLineage.SignerConfig.Builder(oldSignerParams.getPrivateKey(), (X509Certificate) oldSignerParams.getCerts().get(0))).build();
                        newSignerParams.setName("new signer");
                        loadPrivateKeyAndCerts(newSignerParams, passwordRetriever);
                        com.android.apksig.SigningCertificateLineage.SignerConfig newSignerConfig = (new com.android.apksig.SigningCertificateLineage.SignerConfig.Builder(newSignerParams.getPrivateKey(), (X509Certificate) newSignerParams.getCerts().get(0))).build();
                        SigningCertificateLineage lineage;
                        if (inputKeyLineage != null) {
                            lineage = getLineageFromInputFile(inputKeyLineage);
                            lineage.updateSignerCapabilities(oldSignerConfig, oldSignerParams.getSignerCapabilitiesBuilder().build());
                            lineage = lineage.spawnDescendant(oldSignerConfig, newSignerConfig, newSignerParams.getSignerCapabilitiesBuilder().build());
                        } else {
                            lineage = (new com.android.apksig.SigningCertificateLineage.Builder(oldSignerConfig, newSignerConfig)).setMinSdkVersion(minSdkVersion).setOriginalCapabilities(oldSignerParams.getSignerCapabilitiesBuilder().build()).setNewCapabilities(newSignerParams.getSignerCapabilitiesBuilder().build()).build();
                        }

                        lineage.writeToFile(outputKeyLineage);
                    } catch (Throwable var17) {
                        try {
                            passwordRetriever.close();
                        } catch (Throwable var16) {
                            var17.addSuppressed(var16);
                        }

                        throw var17;
                    }

                    passwordRetriever.close();
                    if (verbose) {
                        System.out.println("Rotation entry generated.");
                    }

                }
            }
        }
    }

    public static void lineage(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage("help_lineage.txt");
        } else {
            boolean verbose = false;
            boolean printCerts = false;
            boolean lineageUpdated = false;
            File inputKeyLineage = null;
            File outputKeyLineage = null;
            OptionsParser optionsParser = new OptionsParser(params);
            ArrayList signers = new ArrayList(1);

            String optionName;
            while ((optionName = optionsParser.nextOption()) != null) {
                if ("help".equals(optionName) || "h".equals(optionName)) {
                    printUsage("help_lineage.txt");
                    return;
                }

                if ("in".equals(optionName)) {
                    inputKeyLineage = new File(optionsParser.getRequiredValue("Input file name"));
                } else if ("out".equals(optionName)) {
                    outputKeyLineage = new File(optionsParser.getRequiredValue("Output file name"));
                } else if ("signer".equals(optionName)) {
                    SignerParams signerParams = processSignerParams(optionsParser);
                    signers.add(signerParams);
                } else if (!"v".equals(optionName) && !"verbose".equals(optionName)) {
                    if (!"print-certs".equals(optionName)) {
                        throw new ParameterException("Unsupported option: " + optionsParser.getOptionOriginalForm() + ". See --help for supported options.");
                    }

                    printCerts = optionsParser.getOptionalBooleanValue(true);
                } else {
                    verbose = optionsParser.getOptionalBooleanValue(true);
                }
            }

            if (inputKeyLineage == null) {
                throw new ParameterException("Input lineage file parameter not present");
            } else {
                SigningCertificateLineage lineage = getLineageFromInputFile(inputKeyLineage);
                PasswordRetriever passwordRetriever = new PasswordRetriever();

                int i;
                try {
                    for (i = 0; i < signers.size(); ++i) {
                        SignerParams signerParams = (SignerParams) signers.get(i);
                        signerParams.setName("signer #" + (i + 1));
                        loadPrivateKeyAndCerts(signerParams, passwordRetriever);
                        com.android.apksig.SigningCertificateLineage.SignerConfig signerConfig = (new com.android.apksig.SigningCertificateLineage.SignerConfig.Builder(signerParams.getPrivateKey(), (X509Certificate) signerParams.getCerts().get(0))).build();

                        try {
                            SignerCapabilities origCapabilities = lineage.getSignerCapabilities(signerConfig);
                            lineage.updateSignerCapabilities(signerConfig, signerParams.getSignerCapabilitiesBuilder().build());
                            SignerCapabilities newCapabilities = lineage.getSignerCapabilities(signerConfig);
                            if (origCapabilities.equals(newCapabilities)) {
                                if (verbose) {
                                    System.out.println("The provided signer capabilities for " + signerParams.getName() + " are unchanged.");
                                }
                            } else {
                                lineageUpdated = true;
                                if (verbose) {
                                    System.out.println("Updated signer capabilities for " + signerParams.getName() + ".");
                                }
                            }
                        } catch (IllegalArgumentException var17) {
                            throw new ParameterException("The signer " + signerParams.getName() + " was not found in the specified lineage.");
                        }
                    }
                } catch (Throwable var18) {
                    try {
                        passwordRetriever.close();
                    } catch (Throwable var16) {
                        var18.addSuppressed(var16);
                    }

                    throw var18;
                }

                passwordRetriever.close();
                if (printCerts) {
                    List<X509Certificate> signingCerts = lineage.getCertificatesInLineage();

                    for (i = 0; i < signingCerts.size(); ++i) {
                        X509Certificate signerCert = (X509Certificate) signingCerts.get(i);
                        SignerCapabilities signerCapabilities = lineage.getSignerCapabilities(signerCert);
                        printCertificate(signerCert, "Signer #" + (i + 1) + " in lineage", verbose);
                        printCapabilities(signerCapabilities);
                    }
                }

                if (lineageUpdated) {
                    if (outputKeyLineage == null) {
                        throw new ParameterException("The lineage was modified but an output file for the lineage was not specified");
                    }

                    lineage.writeToFile(outputKeyLineage);
                    if (verbose) {
                        System.out.println("Updated lineage saved to " + outputKeyLineage + ".");
                    }
                }

            }
        }
    }

    private static SigningCertificateLineage getLineageFromInputFile(File inputLineageFile) throws ParameterException {
        try {
            RandomAccessFile f = new RandomAccessFile(inputLineageFile, "r");

            SigningCertificateLineage var4;
            label44:
            {
                try {
                    if (f.length() < 4L) {
                        throw new ParameterException("The input file is not a valid lineage file.");
                    }

                    DataSource apk = DataSources.asDataSource(f);
                    int magicValue = apk.getByteBuffer(0L, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    if (magicValue == 1056913873) {
                        var4 = SigningCertificateLineage.readFromFile(inputLineageFile);
                        break label44;
                    }

                    if (magicValue != 67324752) {
                        throw new ParameterException("The input file is not a valid lineage file.");
                    }

                    var4 = SigningCertificateLineage.readFromApkFile(inputLineageFile);
                } catch (Throwable var6) {
                    try {
                        f.close();
                    } catch (Throwable var5) {
                        var6.addSuppressed(var5);
                    }

                    throw var6;
                }

                f.close();
                return var4;
            }

            f.close();
            return var4;
        } catch (ApkFormatException | IllegalArgumentException | IOException var7) {
            throw new ParameterException(var7.getMessage());
        }
    }

    private static SignerParams processSignerParams(OptionsParser optionsParser) throws OptionsException, ParameterException {
        SignerParams signerParams = new SignerParams();

        String optionName;
        while ((optionName = optionsParser.nextOption()) != null) {
            if ("ks".equals(optionName)) {
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
                } catch (IllegalArgumentException var5) {
                    throw new ParameterException("Unsupported password character encoding requested using --pass-encoding: " + charsetName);
                }
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
            } else if ("set-installed-data".equals(optionName)) {
                signerParams.getSignerCapabilitiesBuilder().setInstalledData(optionsParser.getOptionalBooleanValue(true));
            } else if ("set-shared-uid".equals(optionName)) {
                signerParams.getSignerCapabilitiesBuilder().setSharedUid(optionsParser.getOptionalBooleanValue(true));
            } else if ("set-permission".equals(optionName)) {
                signerParams.getSignerCapabilitiesBuilder().setPermission(optionsParser.getOptionalBooleanValue(true));
            } else if ("set-rollback".equals(optionName)) {
                signerParams.getSignerCapabilitiesBuilder().setRollback(optionsParser.getOptionalBooleanValue(true));
            } else {
                if (!"set-auth".equals(optionName)) {
                    optionsParser.putOption();
                    break;
                }

                signerParams.getSignerCapabilitiesBuilder().setAuth(optionsParser.getOptionalBooleanValue(true));
            }
        }

        if (signerParams.isEmpty()) {
            throw new ParameterException("Signer specified without arguments");
        } else {
            return signerParams;
        }
    }

    private static void printUsage(String page) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(ApkSignerTool.class.getResourceAsStream(page), StandardCharsets.UTF_8));

            String line;
            try {
                while ((line = in.readLine()) != null) {
                    System.out.println(line);
                }
            } catch (Throwable var5) {
                try {
                    in.close();
                } catch (Throwable var4) {
                    var5.addSuppressed(var4);
                }

                throw var5;
            }

            in.close();
        } catch (IOException var6) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    public static void printCertificate(X509Certificate cert, String name, boolean verbose) throws NoSuchAlgorithmException, CertificateEncodingException {
        if (cert == null) {
            throw new NullPointerException("cert == null");
        } else {
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
                } else if (publicKey instanceof DSAKey) {
                    DSAParams dsaParams = ((DSAKey) publicKey).getParams();
                    if (dsaParams != null) {
                        keySize = dsaParams.getP().bitLength();
                    }
                }

                System.out.println(name + " key size (bits): " + (keySize != -1 ? String.valueOf(keySize) : "n/a"));
                byte[] encodedKey = publicKey.getEncoded();
                System.out.println(name + " public key SHA-256 digest: " + HexEncoding.encode(sha256.digest(encodedKey)));
                System.out.println(name + " public key SHA-1 digest: " + HexEncoding.encode(sha1.digest(encodedKey)));
                System.out.println(name + " public key MD5 digest: " + HexEncoding.encode(md5.digest(encodedKey)));
            }

        }
    }

    public static void printCapabilities(SignerCapabilities capabilities) {
        System.out.println("Has installed data capability: " + capabilities.hasInstalledData());
        System.out.println("Has shared UID capability    : " + capabilities.hasSharedUid());
        System.out.println("Has permission capability    : " + capabilities.hasPermission());
        System.out.println("Has rollback capability      : " + capabilities.hasRollback());
        System.out.println("Has auth capability          : " + capabilities.hasAuth());
    }

    private static void loadPrivateKeyAndCerts(SignerParams params, PasswordRetriever passwordRetriever) throws ParameterException {
        try {
            params.loadPrivateKeyAndCerts(passwordRetriever);
            if (params.getKeystoreKeyAlias() != null) {
                params.setName(params.getKeystoreKeyAlias());
            } else {
                if (params.getKeyFile() == null) {
                    throw new RuntimeException("Neither KeyStore key alias nor private key file available for " + params.getName());
                }

                String keyFileName = (new File(params.getKeyFile())).getName();
                int delimiterIndex = keyFileName.indexOf(46);
                if (delimiterIndex == -1) {
                    params.setName(keyFileName);
                } else {
                    params.setName(keyFileName.substring(0, delimiterIndex));
                }
            }

        } catch (ParameterException var4) {
            throw new ParameterException("Failed to load signer \"" + params.getName() + "\":" + var4.getMessage());
        } catch (Exception var5) {
            var5.printStackTrace();
            throw new ParameterException("Failed to load signer \"" + params.getName() + "\"");
        }
    }

    public static class ProviderInstallSpec {
        String className;
        String constructorParam;
        Integer position;

        public ProviderInstallSpec() {
        }

        private boolean isEmpty() {
            return this.className == null && this.constructorParam == null && this.position == null;
        }

        private void installProvider() throws Exception {
            if (this.className == null) {
                throw new ParameterException("JCA Provider class name (--provider-class) must be specified");
            } else {
                Class<?> providerClass = Class.forName(this.className);
                if (!Provider.class.isAssignableFrom(providerClass)) {
                    throw new ParameterException("JCA Provider class " + providerClass + " not subclass of " + Provider.class.getName());
                } else {
                    Provider provider;
                    if (this.constructorParam != null) {
                        provider = (Provider) providerClass.getConstructor(String.class).newInstance(this.constructorParam);
                    } else {
                        provider = (Provider) providerClass.getConstructor().newInstance();
                    }

                    if (this.position == null) {
                        Security.addProvider(provider);
                    } else {
                        Security.insertProviderAt(provider, this.position);
                    }

                }
            }
        }
    }
}
