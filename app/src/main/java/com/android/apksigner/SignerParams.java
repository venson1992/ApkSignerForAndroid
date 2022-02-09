package com.android.apksigner;

import com.android.apksig.SigningCertificateLineage;
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
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SignerParams {
    private String certFile;
    private List<X509Certificate> certs;
    private String keyFile;
    private String keyPasswordSpec;
    private String keystoreFile;
    private String keystoreKeyAlias;
    private String keystorePasswordSpec;
    private String keystoreProviderArg;
    private String keystoreProviderClass;
    private String keystoreProviderName;
    private String keystoreType;
    private String name;
    private Charset passwordCharset;
    private PrivateKey privateKey;
    private final SigningCertificateLineage.SignerCapabilities.Builder signerCapabilitiesBuilder = new SigningCertificateLineage.SignerCapabilities.Builder();
    private String v1SigFileBasename;

    public String getName() {
        return this.name;
    }

    public void setName(String name2) {
        this.name = name2;
    }

    public void setKeystoreFile(String keystoreFile2) {
        this.keystoreFile = keystoreFile2;
    }

    public String getKeystoreKeyAlias() {
        return this.keystoreKeyAlias;
    }

    public void setKeystoreKeyAlias(String keystoreKeyAlias2) {
        this.keystoreKeyAlias = keystoreKeyAlias2;
    }

    public void setKeystorePasswordSpec(String keystorePasswordSpec2) {
        this.keystorePasswordSpec = keystorePasswordSpec2;
    }

    public void setKeyPasswordSpec(String keyPasswordSpec2) {
        this.keyPasswordSpec = keyPasswordSpec2;
    }

    public void setPasswordCharset(Charset passwordCharset2) {
        this.passwordCharset = passwordCharset2;
    }

    public void setKeystoreType(String keystoreType2) {
        this.keystoreType = keystoreType2;
    }

    public void setKeystoreProviderName(String keystoreProviderName2) {
        this.keystoreProviderName = keystoreProviderName2;
    }

    public void setKeystoreProviderClass(String keystoreProviderClass2) {
        this.keystoreProviderClass = keystoreProviderClass2;
    }

    public void setKeystoreProviderArg(String keystoreProviderArg2) {
        this.keystoreProviderArg = keystoreProviderArg2;
    }

    public String getKeyFile() {
        return this.keyFile;
    }

    public void setKeyFile(String keyFile2) {
        this.keyFile = keyFile2;
    }

    public void setCertFile(String certFile2) {
        this.certFile = certFile2;
    }

    public String getV1SigFileBasename() {
        return this.v1SigFileBasename;
    }

    public void setV1SigFileBasename(String v1SigFileBasename2) {
        this.v1SigFileBasename = v1SigFileBasename2;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public List<X509Certificate> getCerts() {
        return this.certs;
    }

    public SigningCertificateLineage.SignerCapabilities.Builder getSignerCapabilitiesBuilder() {
        return this.signerCapabilitiesBuilder;
    }

    /* access modifiers changed from: package-private */
    public boolean isEmpty() {
        return this.name == null && this.keystoreFile == null && this.keystoreKeyAlias == null && this.keystorePasswordSpec == null && this.keyPasswordSpec == null && this.passwordCharset == null && this.keystoreType == null && this.keystoreProviderName == null && this.keystoreProviderClass == null && this.keystoreProviderArg == null && this.keyFile == null && this.certFile == null && this.v1SigFileBasename == null && this.privateKey == null && this.certs == null;
    }

    public void loadPrivateKeyAndCerts(PasswordRetriever passwordRetriever) throws Exception {
        if (this.keystoreFile != null) {
            if (this.keyFile != null) {
                throw new ParameterException("--ks and --key may not be specified at the same time");
            } else if (this.certFile != null) {
                throw new ParameterException("--ks and --cert may not be specified at the same time");
            } else {
                loadPrivateKeyAndCertsFromKeyStore(passwordRetriever);
            }
        } else if (this.keyFile != null) {
            loadPrivateKeyAndCertsFromFiles(passwordRetriever);
        } else {
            throw new ParameterException("KeyStore (--ks) or private key file (--key) must be specified");
        }
    }

    private void loadPrivateKeyAndCertsFromKeyStore(PasswordRetriever passwordRetriever) throws Exception {
        KeyStore ks;
        Provider ksProvider;
        String keystorePasswordSpec2;
        String str;
        Key entryKey;
        if (this.keystoreFile == null) {
            throw new ParameterException("KeyStore (--ks) must be specified");
        }
        String ksType = this.keystoreType != null ? this.keystoreType : KeyStore.getDefaultType();
        if (this.keystoreProviderName != null) {
            ks = KeyStore.getInstance(ksType, this.keystoreProviderName);
        } else if (this.keystoreProviderClass != null) {
            Class<?> ksProviderClass = Class.forName(this.keystoreProviderClass);
            if (!Provider.class.isAssignableFrom(ksProviderClass)) {
                throw new ParameterException("Keystore Provider class " + this.keystoreProviderClass + " not subclass of " + Provider.class.getName());
            }
            if (this.keystoreProviderArg != null) {
                ksProvider = (Provider) ksProviderClass.getConstructor(String.class).newInstance(this.keystoreProviderArg);
            } else {
                ksProvider = (Provider) ksProviderClass.getConstructor(new Class[0]).newInstance(new Object[0]);
            }
            ks = KeyStore.getInstance(ksType, ksProvider);
        } else {
            ks = KeyStore.getInstance(ksType);
        }
        if (this.keystorePasswordSpec != null) {
            keystorePasswordSpec2 = this.keystorePasswordSpec;
        } else {
            keystorePasswordSpec2 = PasswordRetriever.SPEC_STDIN;
        }
        Charset[] additionalPasswordEncodings = this.passwordCharset != null ? new Charset[]{this.passwordCharset} : new Charset[0];
        List<char[]> keystorePasswords = passwordRetriever.getPasswords(keystorePasswordSpec2, "Keystore password for " + this.name, additionalPasswordEncodings);
        if ("NONE".equals(this.keystoreFile)) {
            str = null;
        } else {
            str = this.keystoreFile;
        }
        loadKeyStoreFromFile(ks, str, keystorePasswords);
        try {
            if (this.keystoreKeyAlias == null) {
                Enumeration<String> aliases = ks.aliases();
                if (aliases != null) {
                    while (aliases.hasMoreElements()) {
                        String entryAlias = aliases.nextElement();
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
            String keyAlias = this.keystoreKeyAlias;
            if (!ks.isKeyEntry(keyAlias)) {
                throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
            }
            if (this.keyPasswordSpec != null) {
                entryKey = getKeyStoreKey(ks, keyAlias, passwordRetriever.getPasswords(this.keyPasswordSpec, "Key \"" + keyAlias + "\" password for " + this.name, additionalPasswordEncodings));
            } else {
                try {
                    entryKey = getKeyStoreKey(ks, keyAlias, keystorePasswords);
                } catch (UnrecoverableKeyException e) {
                    entryKey = getKeyStoreKey(ks, keyAlias, passwordRetriever.getPasswords(PasswordRetriever.SPEC_STDIN, "Key \"" + keyAlias + "\" password for " + this.name, additionalPasswordEncodings));
                }
            }
            if (entryKey == null) {
                throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a key");
            } else if (!(entryKey instanceof PrivateKey)) {
                throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain a private key. It contains a key of algorithm: " + entryKey.getAlgorithm());
            } else {
                this.privateKey = (PrivateKey) entryKey;
                Certificate[] certChain = ks.getCertificateChain(keyAlias);
                if (certChain == null || certChain.length == 0) {
                    throw new ParameterException(this.keystoreFile + " entry \"" + keyAlias + "\" does not contain certificates");
                }
                this.certs = new ArrayList(certChain.length);
                int length = certChain.length;
                for (int i = 0; i < length; i++) {
                    this.certs.add((X509Certificate) certChain[i]);
                }
            }
        } catch (UnrecoverableKeyException e2) {
            throw new IOException("Failed to obtain key with alias \"" + ((String) null) + "\" from " + this.keystoreFile + ". Wrong password?", e2);
        }
    }

    private static void loadKeyStoreFromFile(KeyStore ks, String file, List<char[]> passwords) throws Exception {
        Exception lastFailure = null;
        for (char[] password : passwords) {
            if (file != null) {
                try {
                    FileInputStream in = new FileInputStream(file);
                    try {
                        ks.load(in, password);
                        in.close();
                        return;
                    } catch (Throwable th) {
                        th.addSuppressed(th);
                    }
                } catch (Exception e) {
                    lastFailure = e;
                }
            } else {
                ks.load(null, password);
                return;
            }
        }
        if (lastFailure == null) {
            throw new RuntimeException("No keystore passwords");
        }
        throw lastFailure;
        throw th;
    }

    private static Key getKeyStoreKey(KeyStore ks, String keyAlias, List<char[]> passwords) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        UnrecoverableKeyException lastFailure = null;
        Iterator<char[]> it = passwords.iterator();
        while (it.hasNext()) {
            try {
                return ks.getKey(keyAlias, it.next());
            } catch (UnrecoverableKeyException e) {
                lastFailure = e;
            }
        }
        if (lastFailure == null) {
            throw new RuntimeException("No key passwords");
        }
        throw lastFailure;
    }

    private void loadPrivateKeyAndCertsFromFiles(PasswordRetriever passwordRetriever) throws Exception {
        PKCS8EncodedKeySpec keySpec;
        if (this.keyFile == null) {
            throw new ParameterException("Private key file (--key) must be specified");
        } else if (this.certFile == null) {
            throw new ParameterException("Certificate file (--cert) must be specified");
        } else {
            byte[] privateKeyBlob = readFully(new File(this.keyFile));
            try {
                keySpec = decryptPkcs8EncodedKey(new EncryptedPrivateKeyInfo(privateKeyBlob), passwordRetriever.getPasswords(this.keyPasswordSpec != null ? this.keyPasswordSpec : PasswordRetriever.SPEC_STDIN, "Private key password for " + this.name, this.passwordCharset != null ? new Charset[]{this.passwordCharset} : new Charset[0]));
            } catch (IOException e) {
                if (this.keyPasswordSpec == null) {
                    keySpec = new PKCS8EncodedKeySpec(privateKeyBlob);
                } else {
                    throw new InvalidKeySpecException("Failed to parse encrypted private key blob " + this.keyFile, e);
                }
            }
            try {
                this.privateKey = loadPkcs8EncodedPrivateKey(keySpec);
                FileInputStream in = new FileInputStream(this.certFile);
                try {
                    Collection<? extends Certificate> certs2 = X509CertificateUtils.generateCertificates(in);
                    in.close();
                    List<X509Certificate> certList = new ArrayList<>(certs2.size());
                    for (Certificate cert : certs2) {
                        certList.add((X509Certificate) cert);
                    }
                    this.certs = certList;
                    return;
                } catch (Throwable th) {
                    th.addSuppressed(th);
                }
            } catch (InvalidKeySpecException e2) {
                throw new InvalidKeySpecException("Failed to load PKCS #8 encoded private key from " + this.keyFile, e2);
            }
        }
        throw th;
    }

    private static PKCS8EncodedKeySpec decryptPkcs8EncodedKey(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, List<char[]> passwords) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        InvalidKeySpecException lastKeySpecException = null;
        InvalidKeyException lastKeyException = null;
        Iterator<char[]> it = passwords.iterator();
        while (it.hasNext()) {
            try {
                return encryptedPrivateKeyInfo.getKeySpec(keyFactory.generateSecret(new PBEKeySpec(it.next())));
            } catch (InvalidKeySpecException e) {
                lastKeySpecException = e;
            } catch (InvalidKeyException e2) {
                lastKeyException = e2;
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
        } catch (InvalidKeySpecException e) {
            try {
                return KeyFactory.getInstance("EC").generatePrivate(spec);
            } catch (InvalidKeySpecException e2) {
                try {
                    return KeyFactory.getInstance("DSA").generatePrivate(spec);
                } catch (InvalidKeySpecException e3) {
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
            in.close();
            return result.toByteArray();
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    }

    private static void drain(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[65536];
        while (true) {
            int chunkSize = in.read(buf);
            if (chunkSize != -1) {
                out.write(buf, 0, chunkSize);
            } else {
                return;
            }
        }
    }
}
