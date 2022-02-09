package org.conscrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import org.conscrypt.io.IoUtils;

public class KeyManagerFactoryImpl extends KeyManagerFactorySpi {
    private KeyStore keyStore;
    private char[] pwd;

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.KeyManagerFactorySpi
    public void engineInit(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        CertificateException e;
        IOException e2;
        Throwable th;
        FileNotFoundException e3;
        if (ks != null) {
            this.keyStore = ks;
            if (password != null) {
                this.pwd = (char[]) password.clone();
            } else {
                this.pwd = EmptyArray.CHAR;
            }
        } else {
            this.keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            String keyStoreName = System.getProperty("javax.net.ssl.keyStore");
            if (keyStoreName == null || keyStoreName.equalsIgnoreCase("NONE") || keyStoreName.isEmpty()) {
                try {
                    this.keyStore.load(null, null);
                } catch (IOException e4) {
                    throw new KeyStoreException(e4);
                } catch (CertificateException e5) {
                    throw new KeyStoreException(e5);
                }
            } else {
                String keyStorePwd = System.getProperty("javax.net.ssl.keyStorePassword");
                if (keyStorePwd == null) {
                    this.pwd = EmptyArray.CHAR;
                } else {
                    this.pwd = keyStorePwd.toCharArray();
                }
                FileInputStream fis = null;
                try {
                    FileInputStream fis2 = new FileInputStream(new File(keyStoreName));
                    try {
                        this.keyStore.load(fis2, this.pwd);
                        IoUtils.closeQuietly(fis2);
                    } catch (FileNotFoundException e6) {
                        e3 = e6;
                        fis = fis2;
                        try {
                            throw new KeyStoreException(e3);
                        } catch (Throwable th2) {
                            th = th2;
                            IoUtils.closeQuietly(fis);
                            throw th;
                        }
                    } catch (IOException e7) {
                        e2 = e7;
                        throw new KeyStoreException(e2);
                    } catch (CertificateException e8) {
                        e = e8;
                        throw new KeyStoreException(e);
                    } catch (Throwable th3) {
                        th = th3;
                        fis = fis2;
                        IoUtils.closeQuietly(fis);
                        throw th;
                    }
                } catch (FileNotFoundException e9) {
                    e3 = e9;
                    throw new KeyStoreException(e3);
                } catch (IOException e10) {
                    e2 = e10;
                    throw new KeyStoreException(e2);
                } catch (CertificateException e11) {
                    e = e11;
                    throw new KeyStoreException(e);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    @Override // javax.net.ssl.KeyManagerFactorySpi
    public void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("ManagerFactoryParameters not supported");
    }

    /* access modifiers changed from: protected */
    public KeyManager[] engineGetKeyManagers() {
        if (this.keyStore == null) {
            throw new IllegalStateException("KeyManagerFactory is not initialized");
        }
        return new KeyManager[]{new KeyManagerImpl(this.keyStore, this.pwd)};
    }
}
