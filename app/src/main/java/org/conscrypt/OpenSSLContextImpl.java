package org.conscrypt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public abstract class OpenSSLContextImpl extends SSLContextSpi {
    private static DefaultSSLContextImpl defaultSslContextImpl;
    private final ClientSessionContext clientSessionContext;
    private final String[] protocols;
    private final ServerSessionContext serverSessionContext;
    SSLParametersImpl sslParameters;

    static OpenSSLContextImpl getPreferred() {
        return new TLSv13();
    }

    OpenSSLContextImpl(String[] protocols2) {
        this.protocols = protocols2;
        this.clientSessionContext = new ClientSessionContext();
        this.serverSessionContext = new ServerSessionContext();
    }

    private OpenSSLContextImpl() throws GeneralSecurityException, IOException {
        this(NativeCrypto.TLSV13_PROTOCOLS, true);
    }

    OpenSSLContextImpl(String[] protocols2, boolean unused) throws GeneralSecurityException, IOException {
        synchronized (DefaultSSLContextImpl.class) {
            this.protocols = null;
            if (defaultSslContextImpl == null) {
                this.clientSessionContext = new ClientSessionContext();
                this.serverSessionContext = new ServerSessionContext();
                defaultSslContextImpl = (DefaultSSLContextImpl) this;
            } else {
                this.clientSessionContext = (ClientSessionContext) defaultSslContextImpl.engineGetClientSessionContext();
                this.serverSessionContext = (ServerSessionContext) defaultSslContextImpl.engineGetServerSessionContext();
            }
            this.sslParameters = new SSLParametersImpl(defaultSslContextImpl.getKeyManagers(), defaultSslContextImpl.getTrustManagers(), (SecureRandom) null, this.clientSessionContext, this.serverSessionContext, protocols2);
        }
    }

    @Override // javax.net.ssl.SSLContextSpi
    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        this.sslParameters = new SSLParametersImpl(kms, tms, sr, this.clientSessionContext, this.serverSessionContext, this.protocols);
    }

    public SSLSocketFactory engineGetSocketFactory() {
        if (this.sslParameters != null) {
            return Platform.wrapSocketFactoryIfNeeded(new OpenSSLSocketFactoryImpl(this.sslParameters));
        }
        throw new IllegalStateException("SSLContext is not initialized.");
    }

    public SSLServerSocketFactory engineGetServerSocketFactory() {
        if (this.sslParameters != null) {
            return new OpenSSLServerSocketFactoryImpl(this.sslParameters);
        }
        throw new IllegalStateException("SSLContext is not initialized.");
    }

    public SSLEngine engineCreateSSLEngine(String host, int port) {
        if (this.sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParametersImpl p = (SSLParametersImpl) this.sslParameters.clone();
        p.setUseClientMode(false);
        return Platform.wrapEngine(new ConscryptEngine(host, port, p));
    }

    public SSLEngine engineCreateSSLEngine() {
        if (this.sslParameters == null) {
            throw new IllegalStateException("SSLContext is not initialized.");
        }
        SSLParametersImpl p = (SSLParametersImpl) this.sslParameters.clone();
        p.setUseClientMode(false);
        return Platform.wrapEngine(new ConscryptEngine(p));
    }

    public SSLSessionContext engineGetServerSessionContext() {
        return this.serverSessionContext;
    }

    public SSLSessionContext engineGetClientSessionContext() {
        return this.clientSessionContext;
    }

    public static final class TLSv13 extends OpenSSLContextImpl {
        public TLSv13() {
            super(NativeCrypto.TLSV13_PROTOCOLS);
        }
    }

    public static final class TLSv12 extends OpenSSLContextImpl {
        public TLSv12() {
            super(NativeCrypto.TLSV12_PROTOCOLS);
        }
    }

    public static final class TLSv11 extends OpenSSLContextImpl {
        public TLSv11() {
            super(NativeCrypto.TLSV11_PROTOCOLS);
        }
    }

    public static final class TLSv1 extends OpenSSLContextImpl {
        public TLSv1() {
            super(NativeCrypto.TLSV1_PROTOCOLS);
        }
    }
}
