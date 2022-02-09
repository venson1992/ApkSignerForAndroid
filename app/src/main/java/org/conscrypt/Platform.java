package org.conscrypt;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketImpl;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.AccessController;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.conscrypt.ct.CTLogStore;
import org.conscrypt.ct.CTPolicy;
import sun.security.x509.AlgorithmId;

/* access modifiers changed from: package-private */
public final class Platform {
    static final /* synthetic */ boolean $assertionsDisabled;
    private static final Method GET_CURVE_NAME_METHOD;
    private static final int JAVA_VERSION = javaVersion0();

    static {
        boolean z = true;
        if (Platform.class.desiredAssertionStatus()) {
            z = false;
        }
        $assertionsDisabled = z;
        Method getCurveNameMethod = null;
        try {
            getCurveNameMethod = ECParameterSpec.class.getDeclaredMethod("getCurveName", new Class[0]);
            getCurveNameMethod.setAccessible(true);
        } catch (Exception e) {
        }
        GET_CURVE_NAME_METHOD = getCurveNameMethod;
    }

    private Platform() {
    }

    static void setup() {
    }

    static File createTempFile(String prefix, String suffix, File directory) throws IOException {
        if (directory == null) {
            throw new NullPointerException();
        }
        long time = System.currentTimeMillis();
        String prefix2 = new File(prefix).getName();
        IOException suppressed = null;
        for (int i = 0; i < 10000; i++) {
            String tempName = String.format(Locale.US, "%s%d%04d%s", prefix2, Long.valueOf(time), Integer.valueOf(i), suffix);
            File tempFile = new File(directory, tempName);
            if (!tempName.equals(tempFile.getName())) {
                throw new IOException("Unable to create temporary file: " + tempFile);
            }
            try {
                if (tempFile.createNewFile()) {
                    return tempFile.getCanonicalFile();
                }
            } catch (IOException e) {
                suppressed = e;
            }
        }
        if (suppressed != null) {
            throw suppressed;
        }
        throw new IOException("Unable to create temporary file");
    }

    static String getDefaultProviderName() {
        return "Conscrypt";
    }

    static boolean provideTrustManagerByDefault() {
        return true;
    }

    static boolean canExecuteExecutable(File file) throws IOException {
        if (file.canExecute()) {
            return true;
        }
        Set<PosixFilePermission> existingFilePermissions = Files.getPosixFilePermissions(file.toPath(), new LinkOption[0]);
        Collection<? extends PosixFilePermission> of = EnumSet.of(PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_EXECUTE);
        if (existingFilePermissions.containsAll(of)) {
            return false;
        }
        Set<PosixFilePermission> newPermissions = EnumSet.copyOf(existingFilePermissions);
        newPermissions.addAll(of);
        Files.setPosixFilePermissions(file.toPath(), newPermissions);
        return file.canExecute();
    }

    static FileDescriptor getFileDescriptor(Socket s) {
        try {
            SocketChannel channel = s.getChannel();
            if (channel != null) {
                Field f_fd = channel.getClass().getDeclaredField("fd");
                f_fd.setAccessible(true);
                return (FileDescriptor) f_fd.get(channel);
            }
        } catch (Exception e) {
        }
        try {
            Field f_impl = Socket.class.getDeclaredField("impl");
            f_impl.setAccessible(true);
            Object socketImpl = f_impl.get(s);
            Field f_fd2 = SocketImpl.class.getDeclaredField("fd");
            f_fd2.setAccessible(true);
            return (FileDescriptor) f_fd2.get(socketImpl);
        } catch (Exception e2) {
            throw new RuntimeException("Can't get FileDescriptor from socket", e2);
        }
    }

    static FileDescriptor getFileDescriptorFromSSLSocket(AbstractConscryptSocket socket) {
        return getFileDescriptor(socket);
    }

    static String getCurveName(ECParameterSpec spec) {
        if (GET_CURVE_NAME_METHOD != null) {
            try {
                return (String) GET_CURVE_NAME_METHOD.invoke(spec, new Object[0]);
            } catch (Exception e) {
            }
        }
        return null;
    }

    static void setCurveName(ECParameterSpec spec, String curveName) {
    }

    static void setSocketWriteTimeout(Socket s, long timeoutMillis) throws SocketException {
    }

    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.setSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, socket);
        } else {
            impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        }
    }

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, socket);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, socket);
        } else {
            params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        }
    }

    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.setSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.setSSLParameters(params, impl, engine);
        } else {
            impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        }
    }

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        if (JAVA_VERSION >= 9) {
            Java9PlatformUtil.getSSLParameters(params, impl, engine);
        } else if (JAVA_VERSION >= 8) {
            Java8PlatformUtil.getSSLParameters(params, impl, engine);
        } else {
            params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        }
    }

    static void setEndpointIdentificationAlgorithm(SSLParameters params, String endpointIdentificationAlgorithm) {
        params.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
    }

    static String getEndpointIdentificationAlgorithm(SSLParameters params) {
        return params.getEndpointIdentificationAlgorithm();
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType, AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) tm).checkClientTrusted(chain, authType, socket);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType, AbstractConscryptSocket socket) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) tm).checkServerTrusted(chain, authType, socket);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static void checkClientTrusted(X509TrustManager tm, X509Certificate[] chain, String authType, ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) tm).checkClientTrusted(chain, authType, engine);
        } else {
            tm.checkClientTrusted(chain, authType);
        }
    }

    static void checkServerTrusted(X509TrustManager tm, X509Certificate[] chain, String authType, ConscryptEngine engine) throws CertificateException {
        if (tm instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) tm).checkServerTrusted(chain, authType, engine);
        } else {
            tm.checkServerTrusted(chain, authType);
        }
    }

    static OpenSSLKey wrapRsaKey(PrivateKey javaKey) {
        return null;
    }

    static void logEvent(String message) {
    }

    static boolean isSniEnabledByDefault() {
        return true;
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.wrapEngine(engine);
        }
        return engine;
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.unwrapEngine(engine);
        }
        return engine;
    }

    static ConscryptEngineSocket createEngineSocket(SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(sslParameters);
        }
        return new ConscryptEngineSocket(sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(hostname, port, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(address, port, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(String hostname, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptEngineSocket(address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptEngineSocket createEngineSocket(Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8EngineSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptEngineSocket(socket, hostname, port, autoClose, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(sslParameters);
        }
        return new ConscryptFileDescriptorSocket(sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(hostname, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(hostname, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(address, port, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(address, port, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(String hostname, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(hostname, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(hostname, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(address, port, clientAddress, clientPort, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(address, port, clientAddress, clientPort, sslParameters);
    }

    static ConscryptFileDescriptorSocket createFileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        if (JAVA_VERSION >= 8) {
            return new Java8FileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
        }
        return new ConscryptFileDescriptorSocket(socket, hostname, port, autoClose, sslParameters);
    }

    static SSLSocketFactory wrapSocketFactoryIfNeeded(OpenSSLSocketFactoryImpl factory) {
        return factory;
    }

    static GCMParameters fromGCMParameterSpec(AlgorithmParameterSpec params) {
        if (!(params instanceof GCMParameterSpec)) {
            return null;
        }
        GCMParameterSpec gcmParams = (GCMParameterSpec) params;
        return new GCMParameters(gcmParams.getTLen(), gcmParams.getIV());
    }

    static AlgorithmParameterSpec fromGCMParameters(AlgorithmParameters params) {
        try {
            return params.getParameterSpec(GCMParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    static AlgorithmParameterSpec toGCMParameterSpec(int tagLenInBits, byte[] iv) {
        return new GCMParameterSpec(tagLenInBits, iv);
    }

    static Object closeGuardGet() {
        return null;
    }

    static void closeGuardOpen(Object guardObj, String message) {
    }

    static void closeGuardClose(Object guardObj) {
    }

    static void closeGuardWarnIfOpen(Object guardObj) {
    }

    static void blockGuardOnNetwork() {
    }

    static String oidToAlgorithmName(String oid) {
        try {
            return AlgorithmId.get(oid).getName();
        } catch (Exception | IllegalAccessError e) {
            return oid;
        }
    }

    static SSLSession wrapSSLSession(ExternalSession sslSession) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.wrapSSLSession(sslSession);
        }
        return new Java7ExtendedSSLSession(sslSession);
    }

    public static String getOriginalHostNameFromInetAddress(InetAddress addr) {
        try {
            Method getHolder = InetAddress.class.getDeclaredMethod("holder", new Class[0]);
            getHolder.setAccessible(true);
            Method getOriginalHostName = Class.forName("java.net.InetAddress$InetAddressHolder").getDeclaredMethod("getOriginalHostName", new Class[0]);
            getOriginalHostName.setAccessible(true);
            String originalHostName = (String) getOriginalHostName.invoke(getHolder.invoke(addr, new Object[0]), new Object[0]);
            if (originalHostName == null) {
                return addr.getHostAddress();
            }
            return originalHostName;
        } catch (InvocationTargetException e) {
            throw new RuntimeException("Failed to get originalHostName", e);
        } catch (ClassNotFoundException | IllegalAccessException | NoSuchMethodException e2) {
            return addr.getHostAddress();
        }
    }

    static String getHostStringFromInetSocketAddress(InetSocketAddress addr) {
        return addr.getHostString();
    }

    static boolean supportsX509ExtendedTrustManager() {
        return true;
    }

    static boolean isCTVerificationRequired(String hostname) {
        String property;
        if (hostname == null || (property = Security.getProperty("conscrypt.ct.enable")) == null || !Boolean.valueOf(property.toLowerCase()).booleanValue()) {
            return false;
        }
        List<String> parts = Arrays.asList(hostname.split("\\."));
        Collections.reverse(parts);
        boolean enable = false;
        StringBuilder propertyName = new StringBuilder("conscrypt.ct.enforce");
        for (String part : parts) {
            String property2 = Security.getProperty(((Object) propertyName) + ".*");
            if (property2 != null) {
                enable = Boolean.valueOf(property2.toLowerCase()).booleanValue();
            }
            propertyName.append(".").append(part);
        }
        String property3 = Security.getProperty(propertyName.toString());
        if (property3 != null) {
            return Boolean.valueOf(property3.toLowerCase()).booleanValue();
        }
        return enable;
    }

    static boolean supportsConscryptCertStore() {
        return false;
    }

    static KeyStore getDefaultCertKeyStore() throws KeyStoreException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(null, null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
        }
        Provider[] providers = Security.getProviders("TrustManagerFactory.PKIX");
        for (Provider p : providers) {
            if (!Conscrypt.isConscrypt(p)) {
                try {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", p);
                    tmf.init((KeyStore) null);
                    TrustManager[] tms = tmf.getTrustManagers();
                    if (tms.length > 0) {
                        int certNum = 1;
                        for (TrustManager tm : tms) {
                            if (tm instanceof X509TrustManager) {
                                for (X509Certificate cert : ((X509TrustManager) tm).getAcceptedIssuers()) {
                                    certNum++;
                                    ks.setCertificateEntry(Integer.toString(certNum), cert);
                                }
                                certNum = certNum;
                            }
                        }
                        if (certNum > 1) {
                            break;
                        }
                    } else {
                        continue;
                    }
                } catch (NoSuchAlgorithmException e2) {
                }
            }
        }
        return ks;
    }

    static ConscryptCertStore newDefaultCertStore() {
        return null;
    }

    static CertBlacklist newDefaultBlacklist() {
        return null;
    }

    static CTLogStore newDefaultLogStore() {
        return null;
    }

    static CTPolicy newDefaultPolicy(CTLogStore logStore) {
        return null;
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
        if (JAVA_VERSION >= 8) {
            return Java8PlatformUtil.serverNamePermitted(parameters, serverName);
        }
        return true;
    }

    private static boolean isAndroid() {
        try {
            Class.forName("android.app.Application", false, getSystemClassLoader());
            return true;
        } catch (Throwable th) {
            return false;
        }
    }

    static int javaVersion() {
        return JAVA_VERSION;
    }

    private static int javaVersion0() {
        if (isAndroid()) {
            return 6;
        }
        return majorVersionFromJavaSpecificationVersion();
    }

    private static int majorVersionFromJavaSpecificationVersion() {
        return majorVersion(System.getProperty("java.specification.version", "1.6"));
    }

    private static int majorVersion(String javaSpecVersion) {
        String[] components = javaSpecVersion.split("\\.", -1);
        int[] version = new int[components.length];
        for (int i = 0; i < components.length; i++) {
            version[i] = Integer.parseInt(components[i]);
        }
        if (version[0] != 1) {
            return version[0];
        }
        if ($assertionsDisabled || version[1] >= 6) {
            return version[1];
        }
        throw new AssertionError();
    }

    private static ClassLoader getSystemClassLoader() {
        if (System.getSecurityManager() == null) {
            return ClassLoader.getSystemClassLoader();
        }
        return (ClassLoader) AccessController.doPrivileged(new PrivilegedAction<ClassLoader>() {
            /* class org.conscrypt.Platform.AnonymousClass1 */

            @Override // java.security.PrivilegedAction
            public ClassLoader run() {
                return ClassLoader.getSystemClassLoader();
            }
        });
    }
}
