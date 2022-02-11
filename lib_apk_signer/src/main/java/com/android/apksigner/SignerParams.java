//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.android.apksigner;

import com.android.apksig.SigningCertificateLineage.SignerCapabilities.Builder;
import com.android.apksig.internal.util.X509CertificateUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SignerParams {
    private String name;
    private String keystoreFile;
    private String keystoreKeyAlias;
    private String keystorePasswordSpec;
    private String keyPasswordSpec;
    private Charset passwordCharset;
    private String keystoreType;
    private String keystoreProviderName;
    private String keystoreProviderClass;
    private String keystoreProviderArg;
    private String keyFile;
    private String certFile;
    private String v1SigFileBasename;
    private PrivateKey privateKey;
    private List<X509Certificate> certs;
    private final Builder signerCapabilitiesBuilder = new Builder();

    public SignerParams() {
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setKeystoreFile(String keystoreFile) {
        this.keystoreFile = keystoreFile;
    }

    public String getKeystoreKeyAlias() {
        return this.keystoreKeyAlias;
    }

    public void setKeystoreKeyAlias(String keystoreKeyAlias) {
        this.keystoreKeyAlias = keystoreKeyAlias;
    }

    public void setKeystorePasswordSpec(String keystorePasswordSpec) {
        this.keystorePasswordSpec = keystorePasswordSpec;
    }

    public void setKeyPasswordSpec(String keyPasswordSpec) {
        this.keyPasswordSpec = keyPasswordSpec;
    }

    public void setPasswordCharset(Charset passwordCharset) {
        this.passwordCharset = passwordCharset;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public void setKeystoreProviderName(String keystoreProviderName) {
        this.keystoreProviderName = keystoreProviderName;
    }

    public void setKeystoreProviderClass(String keystoreProviderClass) {
        this.keystoreProviderClass = keystoreProviderClass;
    }

    public void setKeystoreProviderArg(String keystoreProviderArg) {
        this.keystoreProviderArg = keystoreProviderArg;
    }

    public String getKeyFile() {
        return this.keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }

    public String getV1SigFileBasename() {
        return this.v1SigFileBasename;
    }

    public void setV1SigFileBasename(String v1SigFileBasename) {
        this.v1SigFileBasename = v1SigFileBasename;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public List<X509Certificate> getCerts() {
        return this.certs;
    }

    public Builder getSignerCapabilitiesBuilder() {
        return this.signerCapabilitiesBuilder;
    }

    public boolean isEmpty() {
        return this.name == null && this.keystoreFile == null && this.keystoreKeyAlias == null && this.keystorePasswordSpec == null && this.keyPasswordSpec == null && this.passwordCharset == null && this.keystoreType == null && this.keystoreProviderName == null && this.keystoreProviderClass == null && this.keystoreProviderArg == null && this.keyFile == null && this.certFile == null && this.v1SigFileBasename == null && this.privateKey == null && this.certs == null;
    }

    /**
     * 获取私钥和证书
     *
     * @param passwordRetriever
     * @throws Exception
     */
    public void loadPrivateKeyAndCerts(PasswordRetriever passwordRetriever) throws Exception {
        if (this.keystoreFile != null) {
            if (this.keyFile != null) {
                throw new ParameterException("--ks and --key may not be specified at the same time");
            }

            if (this.certFile != null) {
                throw new ParameterException("--ks and --cert may not be specified at the same time");
            }

            this.loadPrivateKeyAndCertsFromKeyStore(passwordRetriever);
        } else {
            if (this.keyFile == null) {
                throw new ParameterException("KeyStore (--ks) or private key file (--key) must be specified");
            }

            this.loadPrivateKeyAndCertsFromFiles(passwordRetriever);
        }

    }

    /**
     * 从keystore获取私钥和证书
     *
     * @param passwordRetriever
     * @throws Exception
     */
    private void loadPrivateKeyAndCertsFromKeyStore(PasswordRetriever passwordRetriever) throws Exception {
        if (this.keystoreFile == null) {
            throw new ParameterException("KeyStore (--ks) must be specified");
        } else {
            String ksType = this.keystoreType != null ? this.keystoreType : KeyStore.getDefaultType();
            KeyStore ks;
            if (this.keystoreProviderName != null) {
                ks = KeyStore.getInstance(ksType, this.keystoreProviderName);
            } else if (this.keystoreProviderClass != null) {
                Class<?> ksProviderClass = Class.forName(this.keystoreProviderClass);
                if (!Provider.class.isAssignableFrom(ksProviderClass)) {
                    throw new ParameterException("Keystore Provider class " + this.keystoreProviderClass + " not subclass of " + Provider.class.getName());
                }

                Provider ksProvider;
                if (this.keystoreProviderArg != null) {
                    ksProvider = (Provider) ksProviderClass.getConstructor(String.class).newInstance(this.keystoreProviderArg);
                } else {
                    ksProvider = (Provider) ksProviderClass.getConstructor().newInstance();
                }

                ks = KeyStore.getInstance(ksType, ksProvider);
            } else {
                ks = KeyStore.getInstance(ksType);
            }
            String keyAlias = this.keystorePasswordSpec != null ? this.keystorePasswordSpec : "stdin";
            Charset[] additionalPasswordEncodings = this.passwordCharset != null ? new Charset[]{this.passwordCharset} : new Charset[0];
            List<char[]> keystorePasswords = passwordRetriever.getPasswords(keyAlias, "Keystore password for " + this.name, additionalPasswordEncodings);
            loadKeyStoreFromFile(ks, "NONE".equals(this.keystoreFile) ? null : this.keystoreFile, keystorePasswords);
            keyAlias = null;
            PrivateKey key = null;

            try {
                if (this.keystoreKeyAlias == null) {
                    Enumeration<String> aliases = ks.aliases();
                    if (aliases != null) {
                        while (aliases.hasMoreElements()) {
                            String entryAlias = (String) aliases.nextElement();
                            if (ks.isKeyEntry(entryAlias)) {
                                if (this.keystoreKeyAlias != null) {
                                    throw new ParameterException(this.keystoreFile + " contains multiple key entries. --ks-key-alias option must be used to specify which entry to use.");
                                }

                                this.keystoreKeyAlias = entryAlias;
                            }
                        }
                    }

                    if (this.keystoreKeyAlias == null) {
                        throw new ParameterException(this.keystoreFile + " does not contain key entries");
                    }
                }

                keyAlias = this.keystoreKeyAlias;
                if (!ks.isKeyEntry(keyAlias)) {
                    throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
                }

                Key entryKey;
                if (this.keyPasswordSpec != null) {
                    List<char[]> keyPasswords = passwordRetriever.getPasswords(this.keyPasswordSpec, "Key \"" + keyAlias + "\" password for " + this.name, additionalPasswordEncodings);
                    entryKey = getKeyStoreKey(ks, keyAlias, keyPasswords);
                } else {
                    try {
                        entryKey = getKeyStoreKey(ks, keyAlias, keystorePasswords);
                    } catch (UnrecoverableKeyException var13) {
                        List<char[]> keyPasswords = passwordRetriever.getPasswords("stdin", "Key \"" + keyAlias + "\" password for " + this.name, additionalPasswordEncodings);
                        entryKey = getKeyStoreKey(ks, keyAlias, keyPasswords);
                    }
                }

                if (entryKey == null) {
                    throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
                }

                if (!(entryKey instanceof PrivateKey)) {
                    throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a private key. It contains a key of algorithm: " + entryKey.getAlgorithm());
                }

                key = (PrivateKey) entryKey;
            } catch (UnrecoverableKeyException var14) {
                throw new IOException("Failed to obtain key with alias \"" + keyAlias + "\" from " + this.keystoreFile + ". Wrong password?", var14);
            }

            this.privateKey = key;
            Certificate[] certChain = ks.getCertificateChain(keyAlias);
            if (certChain != null && certChain.length != 0) {
                this.certs = new ArrayList(certChain.length);
                Certificate[] var20 = certChain;
                int var21 = certChain.length;

                for (int var11 = 0; var11 < var21; ++var11) {
                    Certificate cert = var20[var11];
                    this.certs.add((X509Certificate) cert);
                }

            } else {
                throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain certificates");
            }
        }
    }

    /**
     * 加载签名
     *
     * @param ks        签名
     * @param file      签名文件
     * @param passwords 密码
     * @throws Exception
     */
    private static void loadKeyStoreFromFile(KeyStore ks, String file, List<char[]> passwords) throws Exception {
        Exception lastFailure = null;
        Iterator var4 = passwords.iterator();

        while (var4.hasNext()) {
            char[] password = (char[]) var4.next();

            try {
                if (file != null) {
                    FileInputStream in = new FileInputStream(file);

                    try {
                        ks.load(in, password);
                    } catch (Throwable var10) {
                        try {
                            in.close();
                        } catch (Throwable var9) {
                            var10.addSuppressed(var9);
                        }

                        throw var10;
                    }

                    in.close();
                } else {
                    ks.load((InputStream) null, password);
                }

                return;
            } catch (Exception var11) {
                lastFailure = var11;
            }
        }

        if (lastFailure == null) {
            throw new RuntimeException("No keystore passwords");
        } else {
            throw lastFailure;
        }
    }

    private static Key getKeyStoreKey(KeyStore ks, String keyAlias, List<char[]> passwords) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        UnrecoverableKeyException lastFailure = null;
        Iterator var4 = passwords.iterator();

        while (var4.hasNext()) {
            char[] password = (char[]) var4.next();

            try {
                return ks.getKey(keyAlias, password);
            } catch (UnrecoverableKeyException var7) {
                lastFailure = var7;
            }
        }

        if (lastFailure == null) {
            throw new RuntimeException("No key passwords");
        } else {
            throw lastFailure;
        }
    }

    private void loadPrivateKeyAndCertsFromFiles(PasswordRetriever passwordRetriever) throws Exception {
        if (this.keyFile == null) {
            throw new ParameterException("Private key file (--key) must be specified");
        } else if (this.certFile == null) {
            throw new ParameterException("Certificate file (--cert) must be specified");
        } else {
            byte[] privateKeyBlob = readFully(new File(this.keyFile));

            PKCS8EncodedKeySpec keySpec;
            try {
                EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(privateKeyBlob);
                String passwordSpec = this.keyPasswordSpec != null ? this.keyPasswordSpec : "stdin";
                Charset[] additionalPasswordEncodings = this.passwordCharset != null ? new Charset[]{this.passwordCharset} : new Charset[0];
                List<char[]> keyPasswords = passwordRetriever.getPasswords(passwordSpec, "Private key password for " + this.name, additionalPasswordEncodings);
                keySpec = decryptPkcs8EncodedKey(encryptedPrivateKeyInfo, keyPasswords);
            } catch (IOException var11) {
                if (this.keyPasswordSpec != null) {
                    throw new InvalidKeySpecException("Failed to parse encrypted private key blob " + this.keyFile, var11);
                }

                keySpec = new PKCS8EncodedKeySpec(privateKeyBlob);
            }

            try {
                this.privateKey = loadPkcs8EncodedPrivateKey(keySpec);
            } catch (InvalidKeySpecException var10) {
                throw new InvalidKeySpecException("Failed to load PKCS #8 encoded private key from " + this.keyFile, var10);
            }

            FileInputStream in = new FileInputStream(this.certFile);

            Collection certs;
            try {
                certs = X509CertificateUtils.generateCertificates(in);
            } catch (Throwable var9) {
                try {
                    in.close();
                } catch (Throwable var8) {
                    var9.addSuppressed(var8);
                }

                throw var9;
            }

            in.close();
            ArrayList certList = new ArrayList(certs.size());
            Iterator var15 = certs.iterator();

            while (var15.hasNext()) {
                Certificate cert = (Certificate) var15.next();
                certList.add((X509Certificate) cert);
            }

            this.certs = certList;
        }
    }

    private static PKCS8EncodedKeySpec decryptPkcs8EncodedKey(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, List<char[]> passwords) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        InvalidKeySpecException lastKeySpecException = null;
        InvalidKeyException lastKeyException = null;
        Iterator var5 = passwords.iterator();

        while (var5.hasNext()) {
            char[] password = (char[]) var5.next();
            PBEKeySpec decryptionKeySpec = new PBEKeySpec(password);

            try {
                SecretKey decryptionKey = keyFactory.generateSecret(decryptionKeySpec);
                return encryptedPrivateKeyInfo.getKeySpec(decryptionKey);
            } catch (InvalidKeySpecException var9) {
                lastKeySpecException = var9;
            } catch (InvalidKeyException var10) {
                lastKeyException = var10;
            }
        }

        if (lastKeyException == null && lastKeySpecException == null) {
            throw new RuntimeException("No passwords");
        } else if (lastKeyException != null) {
            throw lastKeyException;
        } else {
            throw lastKeySpecException;
        }
    }

    private static PrivateKey loadPkcs8EncodedPrivateKey(PKCS8EncodedKeySpec spec) throws InvalidKeySpecException, NoSuchAlgorithmException {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException var4) {
            try {
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            } catch (InvalidKeySpecException var3) {
                try {
                    return KeyFactory.getInstance("DSA").generatePrivate(spec);
                } catch (InvalidKeySpecException var2) {
                    throw new InvalidKeySpecException("Not an RSA, EC, or DSA private key");
                }
            }
        }
    }

    private static byte[] readFully(File file) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(file);

        try {
            drain(in, result);
        } catch (Throwable var6) {
            try {
                in.close();
            } catch (Throwable var5) {
                var6.addSuppressed(var5);
            }

            throw var6;
        }

        in.close();
        return result.toByteArray();
    }

    private static void drain(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[65536];

        int chunkSize;
        while ((chunkSize = in.read(buf)) != -1) {
            out.write(buf, 0, chunkSize);
        }

    }
}
