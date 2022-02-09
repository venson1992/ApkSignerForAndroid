package org.conscrypt;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Properties;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.io.IoUtils;

public final class Conscrypt {
    private static final Version VERSION;

    private Conscrypt() {
    }

    public static boolean isAvailable() {
        try {
            checkAvailability();
            return true;
        } catch (Throwable th) {
            return false;
        }
    }

    public static class Version {
        private final int major;
        private final int minor;
        private final int patch;

        private Version(int major2, int minor2, int patch2) {
            this.major = major2;
            this.minor = minor2;
            this.patch = patch2;
        }

        public int major() {
            return this.major;
        }

        public int minor() {
            return this.minor;
        }

        public int patch() {
            return this.patch;
        }
    }

    static {
        int major = -1;
        int minor = -1;
        int patch = -1;
        InputStream stream = null;
        try {
            stream = Conscrypt.class.getResourceAsStream("conscrypt.properties");
            if (stream != null) {
                Properties props = new Properties();
                props.load(stream);
                major = Integer.parseInt(props.getProperty("org.conscrypt.version.major", "-1"));
                minor = Integer.parseInt(props.getProperty("org.conscrypt.version.minor", "-1"));
                patch = Integer.parseInt(props.getProperty("org.conscrypt.version.patch", "-1"));
            }
        } catch (IOException e) {
        } finally {
            IoUtils.closeQuietly(stream);
        }
        if (major < 0 || minor < 0 || patch < 0) {
            VERSION = null;
        } else {
            VERSION = new Version(major, minor, patch);
        }
    }

    public static Version version() {
        return VERSION;
    }

    public static void checkAvailability() {
        NativeCrypto.checkAvailability();
    }

    public static boolean isConscrypt(Provider provider) {
        return provider instanceof OpenSSLProvider;
    }

    public static Provider newProvider() {
        checkAvailability();
        return new OpenSSLProvider();
    }

    @Deprecated
    public static Provider newProvider(String providerName) {
        checkAvailability();
        return newProviderBuilder().setName(providerName).build();
    }

    public static class ProviderBuilder {
        private String defaultTlsProtocol;
        private String name;
        private boolean provideTrustManager;

        private ProviderBuilder() {
            this.name = Platform.getDefaultProviderName();
            this.provideTrustManager = Platform.provideTrustManagerByDefault();
            this.defaultTlsProtocol = "TLSv1.3";
        }

        public ProviderBuilder setName(String name2) {
            this.name = name2;
            return this;
        }

        @Deprecated
        public ProviderBuilder provideTrustManager() {
            return provideTrustManager(true);
        }

        public ProviderBuilder provideTrustManager(boolean provide) {
            this.provideTrustManager = provide;
            return this;
        }

        public ProviderBuilder defaultTlsProtocol(String defaultTlsProtocol2) {
            this.defaultTlsProtocol = defaultTlsProtocol2;
            return this;
        }

        public Provider build() {
            return new OpenSSLProvider(this.name, this.provideTrustManager, this.defaultTlsProtocol);
        }
    }

    public static ProviderBuilder newProviderBuilder() {
        return new ProviderBuilder();
    }

    public static int maxEncryptedPacketLength() {
        return 16709;
    }

    public static X509TrustManager getDefaultX509TrustManager() throws KeyManagementException {
        checkAvailability();
        return SSLParametersImpl.getDefaultX509TrustManager();
    }

    public static boolean isConscrypt(SSLContext context) {
        return context.getProvider() instanceof OpenSSLProvider;
    }

    public static SSLContextSpi newPreferredSSLContextSpi() {
        checkAvailability();
        return OpenSSLContextImpl.getPreferred();
    }

    public static void setClientSessionCache(SSLContext context, SSLClientSessionCache cache) {
        SSLSessionContext clientContext = context.getClientSessionContext();
        if (!(clientContext instanceof ClientSessionContext)) {
            throw new IllegalArgumentException("Not a conscrypt client context: " + clientContext.getClass().getName());
        }
        ((ClientSessionContext) clientContext).setPersistentCache(cache);
    }

    public static void setServerSessionCache(SSLContext context, SSLServerSessionCache cache) {
        SSLSessionContext serverContext = context.getServerSessionContext();
        if (!(serverContext instanceof ServerSessionContext)) {
            throw new IllegalArgumentException("Not a conscrypt client context: " + serverContext.getClass().getName());
        }
        ((ServerSessionContext) serverContext).setPersistentCache(cache);
    }

    public static boolean isConscrypt(SSLSocketFactory factory) {
        return factory instanceof OpenSSLSocketFactoryImpl;
    }

    private static OpenSSLSocketFactoryImpl toConscrypt(SSLSocketFactory factory) {
        if (isConscrypt(factory)) {
            return (OpenSSLSocketFactoryImpl) factory;
        }
        throw new IllegalArgumentException("Not a conscrypt socket factory: " + factory.getClass().getName());
    }

    public static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        OpenSSLSocketFactoryImpl.setUseEngineSocketByDefault(useEngineSocket);
        OpenSSLServerSocketFactoryImpl.setUseEngineSocketByDefault(useEngineSocket);
    }

    public static void setUseEngineSocket(SSLSocketFactory factory, boolean useEngineSocket) {
        toConscrypt(factory).setUseEngineSocket(useEngineSocket);
    }

    public static boolean isConscrypt(SSLServerSocketFactory factory) {
        return factory instanceof OpenSSLServerSocketFactoryImpl;
    }

    private static OpenSSLServerSocketFactoryImpl toConscrypt(SSLServerSocketFactory factory) {
        if (isConscrypt(factory)) {
            return (OpenSSLServerSocketFactoryImpl) factory;
        }
        throw new IllegalArgumentException("Not a conscrypt server socket factory: " + factory.getClass().getName());
    }

    public static void setUseEngineSocket(SSLServerSocketFactory factory, boolean useEngineSocket) {
        toConscrypt(factory).setUseEngineSocket(useEngineSocket);
    }

    public static boolean isConscrypt(SSLSocket socket) {
        return socket instanceof AbstractConscryptSocket;
    }

    private static AbstractConscryptSocket toConscrypt(SSLSocket socket) {
        if (isConscrypt(socket)) {
            return (AbstractConscryptSocket) socket;
        }
        throw new IllegalArgumentException("Not a conscrypt socket: " + socket.getClass().getName());
    }

    public static void setHostname(SSLSocket socket, String hostname) {
        toConscrypt(socket).setHostname(hostname);
    }

    public static String getHostname(SSLSocket socket) {
        return toConscrypt(socket).getHostname();
    }

    public static String getHostnameOrIP(SSLSocket socket) {
        return toConscrypt(socket).getHostnameOrIP();
    }

    public static void setUseSessionTickets(SSLSocket socket, boolean useSessionTickets) {
        toConscrypt(socket).setUseSessionTickets(useSessionTickets);
    }

    public static void setChannelIdEnabled(SSLSocket socket, boolean enabled) {
        toConscrypt(socket).setChannelIdEnabled(enabled);
    }

    public static byte[] getChannelId(SSLSocket socket) throws SSLException {
        return toConscrypt(socket).getChannelId();
    }

    public static void setChannelIdPrivateKey(SSLSocket socket, PrivateKey privateKey) {
        toConscrypt(socket).setChannelIdPrivateKey(privateKey);
    }

    public static String getApplicationProtocol(SSLSocket socket) {
        return toConscrypt(socket).getApplicationProtocol();
    }

    public static void setApplicationProtocolSelector(SSLSocket socket, ApplicationProtocolSelector selector) {
        toConscrypt(socket).setApplicationProtocolSelector(selector);
    }

    public static void setApplicationProtocols(SSLSocket socket, String[] protocols) {
        toConscrypt(socket).setApplicationProtocols(protocols);
    }

    public static String[] getApplicationProtocols(SSLSocket socket) {
        return toConscrypt(socket).getApplicationProtocols();
    }

    public static byte[] getTlsUnique(SSLSocket socket) {
        return toConscrypt(socket).getTlsUnique();
    }

    public static byte[] exportKeyingMaterial(SSLSocket socket, String label, byte[] context, int length) throws SSLException {
        return toConscrypt(socket).exportKeyingMaterial(label, context, length);
    }

    public static boolean isConscrypt(SSLEngine engine) {
        return engine instanceof AbstractConscryptEngine;
    }

    private static AbstractConscryptEngine toConscrypt(SSLEngine engine) {
        if (isConscrypt(engine)) {
            return (AbstractConscryptEngine) engine;
        }
        throw new IllegalArgumentException("Not a conscrypt engine: " + engine.getClass().getName());
    }

    public static void setBufferAllocator(SSLEngine engine, BufferAllocator bufferAllocator) {
        toConscrypt(engine).setBufferAllocator(bufferAllocator);
    }

    public static void setBufferAllocator(SSLSocket socket, BufferAllocator bufferAllocator) {
        AbstractConscryptSocket s = toConscrypt(socket);
        if (s instanceof ConscryptEngineSocket) {
            ((ConscryptEngineSocket) s).setBufferAllocator(bufferAllocator);
        }
    }

    public static void setDefaultBufferAllocator(BufferAllocator bufferAllocator) {
        ConscryptEngine.setDefaultBufferAllocator(bufferAllocator);
    }

    public static void setHostname(SSLEngine engine, String hostname) {
        toConscrypt(engine).setHostname(hostname);
    }

    public static String getHostname(SSLEngine engine) {
        return toConscrypt(engine).getHostname();
    }

    public static int maxSealOverhead(SSLEngine engine) {
        return toConscrypt(engine).maxSealOverhead();
    }

    public static void setHandshakeListener(SSLEngine engine, HandshakeListener handshakeListener) {
        toConscrypt(engine).setHandshakeListener(handshakeListener);
    }

    public static void setChannelIdEnabled(SSLEngine engine, boolean enabled) {
        toConscrypt(engine).setChannelIdEnabled(enabled);
    }

    public static byte[] getChannelId(SSLEngine engine) throws SSLException {
        return toConscrypt(engine).getChannelId();
    }

    public static void setChannelIdPrivateKey(SSLEngine engine, PrivateKey privateKey) {
        toConscrypt(engine).setChannelIdPrivateKey(privateKey);
    }

    public static SSLEngineResult unwrap(SSLEngine engine, ByteBuffer[] srcs, ByteBuffer[] dsts) throws SSLException {
        return toConscrypt(engine).unwrap(srcs, dsts);
    }

    public static SSLEngineResult unwrap(SSLEngine engine, ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength) throws SSLException {
        return toConscrypt(engine).unwrap(srcs, srcsOffset, srcsLength, dsts, dstsOffset, dstsLength);
    }

    public static void setUseSessionTickets(SSLEngine engine, boolean useSessionTickets) {
        toConscrypt(engine).setUseSessionTickets(useSessionTickets);
    }

    public static void setApplicationProtocols(SSLEngine engine, String[] protocols) {
        toConscrypt(engine).setApplicationProtocols(protocols);
    }

    public static String[] getApplicationProtocols(SSLEngine engine) {
        return toConscrypt(engine).getApplicationProtocols();
    }

    public static void setApplicationProtocolSelector(SSLEngine engine, ApplicationProtocolSelector selector) {
        toConscrypt(engine).setApplicationProtocolSelector(selector);
    }

    public static String getApplicationProtocol(SSLEngine engine) {
        return toConscrypt(engine).getApplicationProtocol();
    }

    public static byte[] getTlsUnique(SSLEngine engine) {
        return toConscrypt(engine).getTlsUnique();
    }

    public static byte[] exportKeyingMaterial(SSLEngine engine, String label, byte[] context, int length) throws SSLException {
        return toConscrypt(engine).exportKeyingMaterial(label, context, length);
    }

    public static boolean isConscrypt(TrustManager trustManager) {
        return trustManager instanceof TrustManagerImpl;
    }

    private static TrustManagerImpl toConscrypt(TrustManager trustManager) {
        if (isConscrypt(trustManager)) {
            return (TrustManagerImpl) trustManager;
        }
        throw new IllegalArgumentException("Not a Conscrypt trust manager: " + trustManager.getClass().getName());
    }

    public static synchronized void setDefaultHostnameVerifier(ConscryptHostnameVerifier verifier) {
        synchronized (Conscrypt.class) {
            TrustManagerImpl.setDefaultHostnameVerifier(verifier);
        }
    }

    public static synchronized ConscryptHostnameVerifier getDefaultHostnameVerifier(TrustManager trustManager) {
        ConscryptHostnameVerifier defaultHostnameVerifier;
        synchronized (Conscrypt.class) {
            defaultHostnameVerifier = TrustManagerImpl.getDefaultHostnameVerifier();
        }
        return defaultHostnameVerifier;
    }

    public static void setHostnameVerifier(TrustManager trustManager, ConscryptHostnameVerifier verifier) {
        toConscrypt(trustManager).setHostnameVerifier(verifier);
    }

    public static ConscryptHostnameVerifier getHostnameVerifier(TrustManager trustManager) {
        return toConscrypt(trustManager).getHostnameVerifier();
    }
}
