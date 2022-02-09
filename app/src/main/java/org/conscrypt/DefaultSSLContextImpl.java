package org.conscrypt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

public class DefaultSSLContextImpl extends OpenSSLContextImpl {
    private static KeyManager[] KEY_MANAGERS;
    private static TrustManager[] TRUST_MANAGERS;

    private DefaultSSLContextImpl(String[] protocols) throws GeneralSecurityException, IOException {
        super(protocols, true);
    }

    /* access modifiers changed from: package-private */
    /* JADX WARNING: Removed duplicated region for block: B:18:0x004f  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public javax.net.ssl.KeyManager[] getKeyManagers() throws java.security.GeneralSecurityException, java.io.IOException {
        /*
            r9 = this;
            r7 = 0
            javax.net.ssl.KeyManager[] r8 = org.conscrypt.DefaultSSLContextImpl.KEY_MANAGERS
            if (r8 == 0) goto L_0x0008
            javax.net.ssl.KeyManager[] r7 = org.conscrypt.DefaultSSLContextImpl.KEY_MANAGERS
        L_0x0007:
            return r7
        L_0x0008:
            java.lang.String r8 = "javax.net.ssl.keyStore"
            java.lang.String r2 = java.lang.System.getProperty(r8)
            if (r2 == 0) goto L_0x0007
            java.lang.String r8 = "javax.net.ssl.keyStorePassword"
            java.lang.String r3 = java.lang.System.getProperty(r8)
            if (r3 != 0) goto L_0x0047
        L_0x0018:
            java.lang.String r8 = java.security.KeyStore.getDefaultType()
            java.security.KeyStore r6 = java.security.KeyStore.getInstance(r8)
            r0 = 0
            java.io.BufferedInputStream r1 = new java.io.BufferedInputStream     // Catch:{ all -> 0x004c }
            java.io.FileInputStream r8 = new java.io.FileInputStream     // Catch:{ all -> 0x004c }
            r8.<init>(r2)     // Catch:{ all -> 0x004c }
            r1.<init>(r8)     // Catch:{ all -> 0x004c }
            r6.load(r1, r7)     // Catch:{ all -> 0x0053 }
            if (r1 == 0) goto L_0x0033
            r1.close()
        L_0x0033:
            java.lang.String r5 = javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()
            javax.net.ssl.KeyManagerFactory r4 = javax.net.ssl.KeyManagerFactory.getInstance(r5)
            r4.init(r6, r7)
            javax.net.ssl.KeyManager[] r8 = r4.getKeyManagers()
            org.conscrypt.DefaultSSLContextImpl.KEY_MANAGERS = r8
            javax.net.ssl.KeyManager[] r7 = org.conscrypt.DefaultSSLContextImpl.KEY_MANAGERS
            goto L_0x0007
        L_0x0047:
            char[] r7 = r3.toCharArray()
            goto L_0x0018
        L_0x004c:
            r8 = move-exception
        L_0x004d:
            if (r0 == 0) goto L_0x0052
            r0.close()
        L_0x0052:
            throw r8
        L_0x0053:
            r8 = move-exception
            r0 = r1
            goto L_0x004d
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.DefaultSSLContextImpl.getKeyManagers():javax.net.ssl.KeyManager[]");
    }

    /* access modifiers changed from: package-private */
    /* JADX WARNING: Removed duplicated region for block: B:18:0x004f  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public javax.net.ssl.TrustManager[] getTrustManagers() throws java.security.GeneralSecurityException, java.io.IOException {
        /*
            r9 = this;
            r5 = 0
            javax.net.ssl.TrustManager[] r8 = org.conscrypt.DefaultSSLContextImpl.TRUST_MANAGERS
            if (r8 == 0) goto L_0x0008
            javax.net.ssl.TrustManager[] r5 = org.conscrypt.DefaultSSLContextImpl.TRUST_MANAGERS
        L_0x0007:
            return r5
        L_0x0008:
            java.lang.String r8 = "javax.net.ssl.trustStore"
            java.lang.String r2 = java.lang.System.getProperty(r8)
            if (r2 == 0) goto L_0x0007
            java.lang.String r8 = "javax.net.ssl.trustStorePassword"
            java.lang.String r3 = java.lang.System.getProperty(r8)
            if (r3 != 0) goto L_0x0047
        L_0x0018:
            java.lang.String r8 = java.security.KeyStore.getDefaultType()
            java.security.KeyStore r4 = java.security.KeyStore.getInstance(r8)
            r0 = 0
            java.io.BufferedInputStream r1 = new java.io.BufferedInputStream     // Catch:{ all -> 0x004c }
            java.io.FileInputStream r8 = new java.io.FileInputStream     // Catch:{ all -> 0x004c }
            r8.<init>(r2)     // Catch:{ all -> 0x004c }
            r1.<init>(r8)     // Catch:{ all -> 0x004c }
            r4.load(r1, r5)     // Catch:{ all -> 0x0053 }
            if (r1 == 0) goto L_0x0033
            r1.close()
        L_0x0033:
            java.lang.String r7 = javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
            javax.net.ssl.TrustManagerFactory r6 = javax.net.ssl.TrustManagerFactory.getInstance(r7)
            r6.init(r4)
            javax.net.ssl.TrustManager[] r8 = r6.getTrustManagers()
            org.conscrypt.DefaultSSLContextImpl.TRUST_MANAGERS = r8
            javax.net.ssl.TrustManager[] r5 = org.conscrypt.DefaultSSLContextImpl.TRUST_MANAGERS
            goto L_0x0007
        L_0x0047:
            char[] r5 = r3.toCharArray()
            goto L_0x0018
        L_0x004c:
            r8 = move-exception
        L_0x004d:
            if (r0 == 0) goto L_0x0052
            r0.close()
        L_0x0052:
            throw r8
        L_0x0053:
            r8 = move-exception
            r0 = r1
            goto L_0x004d
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.DefaultSSLContextImpl.getTrustManagers():javax.net.ssl.TrustManager[]");
    }

    @Override // org.conscrypt.OpenSSLContextImpl, javax.net.ssl.SSLContextSpi
    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        throw new KeyManagementException("Do not init() the default SSLContext ");
    }

    public static final class TLSv13 extends DefaultSSLContextImpl {
        public TLSv13() throws GeneralSecurityException, IOException {
            super(NativeCrypto.TLSV13_PROTOCOLS);
        }
    }

    public static final class TLSv12 extends DefaultSSLContextImpl {
        public TLSv12() throws GeneralSecurityException, IOException {
            super(NativeCrypto.TLSV12_PROTOCOLS);
        }
    }
}
