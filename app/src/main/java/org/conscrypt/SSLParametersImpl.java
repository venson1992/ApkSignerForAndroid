package org.conscrypt;

import java.security.AlgorithmConstraints;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/* access modifiers changed from: package-private */
public final class SSLParametersImpl implements Cloneable {
    private static final String[] EMPTY_STRING_ARRAY = new String[0];
    private static volatile SSLParametersImpl defaultParameters;
    private static volatile X509KeyManager defaultX509KeyManager;
    private static volatile X509TrustManager defaultX509TrustManager;
    private AlgorithmConstraints algorithmConstraints;
    ApplicationProtocolSelectorAdapter applicationProtocolSelector;
    byte[] applicationProtocols = EmptyArray.BYTE;
    boolean channelIdEnabled;
    private final ClientSessionContext clientSessionContext;
    private boolean client_mode = true;
    private boolean ctVerificationEnabled;
    private boolean enable_session_creation = true;
    String[] enabledCipherSuites;
    String[] enabledProtocols;
    private String endpointIdentificationAlgorithm;
    boolean isEnabledProtocolsFiltered;
    private boolean need_client_auth = false;
    byte[] ocspResponse;
    private final PSKKeyManager pskKeyManager;
    byte[] sctExtension;
    private final ServerSessionContext serverSessionContext;
    private Collection<SNIMatcher> sniMatchers;
    private boolean useCipherSuitesOrder;
    boolean useSessionTickets;
    private Boolean useSni;
    private boolean want_client_auth = false;
    private final X509KeyManager x509KeyManager;
    private final X509TrustManager x509TrustManager;

    /* access modifiers changed from: package-private */
    public interface AliasChooser {
        String chooseClientAlias(X509KeyManager x509KeyManager, X500Principal[] x500PrincipalArr, String[] strArr);

        String chooseServerAlias(X509KeyManager x509KeyManager, String str);
    }

    /* access modifiers changed from: package-private */
    public interface PSKCallbacks {
        String chooseClientPSKIdentity(PSKKeyManager pSKKeyManager, String str);

        String chooseServerPSKIdentityHint(PSKKeyManager pSKKeyManager);

        SecretKey getPSKKey(PSKKeyManager pSKKeyManager, String str, String str2);
    }

    SSLParametersImpl(KeyManager[] kms, TrustManager[] tms, SecureRandom sr, ClientSessionContext clientSessionContext2, ServerSessionContext serverSessionContext2, String[] protocols) throws KeyManagementException {
        boolean x509CipherSuitesNeeded;
        boolean pskCipherSuitesNeeded;
        this.serverSessionContext = serverSessionContext2;
        this.clientSessionContext = clientSessionContext2;
        if (kms == null) {
            this.x509KeyManager = getDefaultX509KeyManager();
            this.pskKeyManager = null;
        } else {
            this.x509KeyManager = findFirstX509KeyManager(kms);
            this.pskKeyManager = findFirstPSKKeyManager(kms);
        }
        if (tms == null) {
            this.x509TrustManager = getDefaultX509TrustManager();
        } else {
            this.x509TrustManager = findFirstX509TrustManager(tms);
        }
        this.enabledProtocols = (String[]) NativeCrypto.checkEnabledProtocols(protocols == null ? NativeCrypto.DEFAULT_PROTOCOLS : protocols).clone();
        if (this.x509KeyManager == null && this.x509TrustManager == null) {
            x509CipherSuitesNeeded = false;
        } else {
            x509CipherSuitesNeeded = true;
        }
        if (this.pskKeyManager != null) {
            pskCipherSuitesNeeded = true;
        } else {
            pskCipherSuitesNeeded = false;
        }
        this.enabledCipherSuites = getDefaultCipherSuites(x509CipherSuitesNeeded, pskCipherSuitesNeeded);
    }

    private SSLParametersImpl(ClientSessionContext clientSessionContext2, ServerSessionContext serverSessionContext2, X509KeyManager x509KeyManager2, PSKKeyManager pskKeyManager2, X509TrustManager x509TrustManager2, SSLParametersImpl sslParams) {
        byte[] bArr = null;
        this.clientSessionContext = clientSessionContext2;
        this.serverSessionContext = serverSessionContext2;
        this.x509KeyManager = x509KeyManager2;
        this.pskKeyManager = pskKeyManager2;
        this.x509TrustManager = x509TrustManager2;
        this.enabledProtocols = sslParams.enabledProtocols == null ? null : (String[]) sslParams.enabledProtocols.clone();
        this.isEnabledProtocolsFiltered = sslParams.isEnabledProtocolsFiltered;
        this.enabledCipherSuites = sslParams.enabledCipherSuites == null ? null : (String[]) sslParams.enabledCipherSuites.clone();
        this.client_mode = sslParams.client_mode;
        this.need_client_auth = sslParams.need_client_auth;
        this.want_client_auth = sslParams.want_client_auth;
        this.enable_session_creation = sslParams.enable_session_creation;
        this.endpointIdentificationAlgorithm = sslParams.endpointIdentificationAlgorithm;
        this.useCipherSuitesOrder = sslParams.useCipherSuitesOrder;
        this.ctVerificationEnabled = sslParams.ctVerificationEnabled;
        this.sctExtension = sslParams.sctExtension == null ? null : (byte[]) sslParams.sctExtension.clone();
        this.ocspResponse = sslParams.ocspResponse == null ? null : (byte[]) sslParams.ocspResponse.clone();
        this.applicationProtocols = sslParams.applicationProtocols != null ? (byte[]) sslParams.applicationProtocols.clone() : bArr;
        this.applicationProtocolSelector = sslParams.applicationProtocolSelector;
        this.useSessionTickets = sslParams.useSessionTickets;
        this.useSni = sslParams.useSni;
        this.channelIdEnabled = sslParams.channelIdEnabled;
    }

    static SSLParametersImpl getDefault() throws KeyManagementException {
        SSLParametersImpl result = defaultParameters;
        if (result == null) {
            result = new SSLParametersImpl((KeyManager[]) null, (TrustManager[]) null, (SecureRandom) null, new ClientSessionContext(), new ServerSessionContext(), (String[]) null);
            defaultParameters = result;
        }
        return (SSLParametersImpl) result.clone();
    }

    /* access modifiers changed from: package-private */
    public AbstractSessionContext getSessionContext() {
        return this.client_mode ? this.clientSessionContext : this.serverSessionContext;
    }

    /* access modifiers changed from: package-private */
    public ClientSessionContext getClientSessionContext() {
        return this.clientSessionContext;
    }

    /* access modifiers changed from: package-private */
    public X509KeyManager getX509KeyManager() {
        return this.x509KeyManager;
    }

    /* access modifiers changed from: package-private */
    public PSKKeyManager getPSKKeyManager() {
        return this.pskKeyManager;
    }

    /* access modifiers changed from: package-private */
    public X509TrustManager getX509TrustManager() {
        return this.x509TrustManager;
    }

    /* access modifiers changed from: package-private */
    public String[] getEnabledCipherSuites() {
        if (!Arrays.asList(this.enabledProtocols).contains("TLSv1.3")) {
            return (String[]) this.enabledCipherSuites.clone();
        }
        return SSLUtils.concat(NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES, this.enabledCipherSuites);
    }

    /* access modifiers changed from: package-private */
    public void setEnabledCipherSuites(String[] cipherSuites) {
        this.enabledCipherSuites = NativeCrypto.checkEnabledCipherSuites(filterFromCipherSuites(cipherSuites, NativeCrypto.SUPPORTED_TLS_1_3_CIPHER_SUITES_SET));
    }

    /* access modifiers changed from: package-private */
    public String[] getEnabledProtocols() {
        return (String[]) this.enabledProtocols.clone();
    }

    /* access modifiers changed from: package-private */
    public void setEnabledProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols == null");
        }
        String[] filteredProtocols = filterFromProtocols(protocols, "SSLv3");
        this.isEnabledProtocolsFiltered = protocols.length != filteredProtocols.length;
        this.enabledProtocols = (String[]) NativeCrypto.checkEnabledProtocols(filteredProtocols).clone();
    }

    /* access modifiers changed from: package-private */
    public void setApplicationProtocols(String[] protocols) {
        this.applicationProtocols = SSLUtils.encodeProtocols(protocols);
    }

    /* access modifiers changed from: package-private */
    public String[] getApplicationProtocols() {
        return SSLUtils.decodeProtocols(this.applicationProtocols);
    }

    /* access modifiers changed from: package-private */
    public void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter applicationProtocolSelector2) {
        this.applicationProtocolSelector = applicationProtocolSelector2;
    }

    /* access modifiers changed from: package-private */
    public ApplicationProtocolSelectorAdapter getApplicationProtocolSelector() {
        return this.applicationProtocolSelector;
    }

    /* access modifiers changed from: package-private */
    public void setUseClientMode(boolean mode) {
        this.client_mode = mode;
    }

    /* access modifiers changed from: package-private */
    public boolean getUseClientMode() {
        return this.client_mode;
    }

    /* access modifiers changed from: package-private */
    public void setNeedClientAuth(boolean need) {
        this.need_client_auth = need;
        this.want_client_auth = false;
    }

    /* access modifiers changed from: package-private */
    public boolean getNeedClientAuth() {
        return this.need_client_auth;
    }

    /* access modifiers changed from: package-private */
    public void setWantClientAuth(boolean want) {
        this.want_client_auth = want;
        this.need_client_auth = false;
    }

    /* access modifiers changed from: package-private */
    public boolean getWantClientAuth() {
        return this.want_client_auth;
    }

    /* access modifiers changed from: package-private */
    public void setEnableSessionCreation(boolean flag) {
        this.enable_session_creation = flag;
    }

    /* access modifiers changed from: package-private */
    public boolean getEnableSessionCreation() {
        return this.enable_session_creation;
    }

    /* access modifiers changed from: package-private */
    public void setUseSessionTickets(boolean useSessionTickets2) {
        this.useSessionTickets = useSessionTickets2;
    }

    /* access modifiers changed from: package-private */
    public void setUseSni(boolean flag) {
        this.useSni = Boolean.valueOf(flag);
    }

    /* access modifiers changed from: package-private */
    public boolean getUseSni() {
        return this.useSni != null ? this.useSni.booleanValue() : isSniEnabledByDefault();
    }

    /* access modifiers changed from: package-private */
    public void setCTVerificationEnabled(boolean enabled) {
        this.ctVerificationEnabled = enabled;
    }

    /* access modifiers changed from: package-private */
    public void setSCTExtension(byte[] extension) {
        this.sctExtension = extension;
    }

    /* access modifiers changed from: package-private */
    public void setOCSPResponse(byte[] response) {
        this.ocspResponse = response;
    }

    /* access modifiers changed from: package-private */
    public byte[] getOCSPResponse() {
        return this.ocspResponse;
    }

    private static String[] filterFromProtocols(String[] protocols, String obsoleteProtocol) {
        if (protocols.length == 1 && obsoleteProtocol.equals(protocols[0])) {
            return EMPTY_STRING_ARRAY;
        }
        ArrayList<String> newProtocols = new ArrayList<>();
        for (String protocol : protocols) {
            if (!obsoleteProtocol.equals(protocol)) {
                newProtocols.add(protocol);
            }
        }
        return (String[]) newProtocols.toArray(EMPTY_STRING_ARRAY);
    }

    private static String[] filterFromCipherSuites(String[] cipherSuites, Set<String> toRemove) {
        if (cipherSuites == null || cipherSuites.length == 0) {
            return cipherSuites;
        }
        ArrayList<String> newCipherSuites = new ArrayList<>(cipherSuites.length);
        for (String cipherSuite : cipherSuites) {
            if (!toRemove.contains(cipherSuite)) {
                newCipherSuites.add(cipherSuite);
            }
        }
        return (String[]) newCipherSuites.toArray(EMPTY_STRING_ARRAY);
    }

    private boolean isSniEnabledByDefault() {
        try {
            String enableSNI = System.getProperty("jsse.enableSNIExtension", "true");
            if ("true".equalsIgnoreCase(enableSNI)) {
                return true;
            }
            if ("false".equalsIgnoreCase(enableSNI)) {
                return false;
            }
            throw new RuntimeException("Can only set \"jsse.enableSNIExtension\" to \"true\" or \"false\"");
        } catch (SecurityException e) {
            return true;
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.lang.Object
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    /* access modifiers changed from: package-private */
    public SSLParametersImpl cloneWithTrustManager(X509TrustManager newTrustManager) {
        return new SSLParametersImpl(this.clientSessionContext, this.serverSessionContext, this.x509KeyManager, this.pskKeyManager, newTrustManager, this);
    }

    private static X509KeyManager getDefaultX509KeyManager() throws KeyManagementException {
        X509KeyManager result = defaultX509KeyManager;
        if (result != null) {
            return result;
        }
        X509KeyManager result2 = createDefaultX509KeyManager();
        defaultX509KeyManager = result2;
        return result2;
    }

    private static X509KeyManager createDefaultX509KeyManager() throws KeyManagementException {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(null, null);
            KeyManager[] kms = kmf.getKeyManagers();
            X509KeyManager result = findFirstX509KeyManager(kms);
            if (result != null) {
                return result;
            }
            throw new KeyManagementException("No X509KeyManager among default KeyManagers: " + Arrays.toString(kms));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagementException(e);
        } catch (KeyStoreException e2) {
            throw new KeyManagementException(e2);
        } catch (UnrecoverableKeyException e3) {
            throw new KeyManagementException(e3);
        }
    }

    private static X509KeyManager findFirstX509KeyManager(KeyManager[] kms) {
        for (KeyManager km : kms) {
            if (km instanceof X509KeyManager) {
                return (X509KeyManager) km;
            }
        }
        return null;
    }

    private static PSKKeyManager findFirstPSKKeyManager(KeyManager[] kms) {
        for (KeyManager km : kms) {
            if (km instanceof PSKKeyManager) {
                return (PSKKeyManager) km;
            }
            if (km != null) {
                try {
                    return DuckTypedPSKKeyManager.getInstance(km);
                } catch (NoSuchMethodException e) {
                }
            }
        }
        return null;
    }

    static X509TrustManager getDefaultX509TrustManager() throws KeyManagementException {
        X509TrustManager result = defaultX509TrustManager;
        if (result != null) {
            return result;
        }
        X509TrustManager result2 = createDefaultX509TrustManager();
        defaultX509TrustManager = result2;
        return result2;
    }

    private static X509TrustManager createDefaultX509TrustManager() throws KeyManagementException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            TrustManager[] tms = tmf.getTrustManagers();
            X509TrustManager trustManager = findFirstX509TrustManager(tms);
            if (trustManager != null) {
                return trustManager;
            }
            throw new KeyManagementException("No X509TrustManager in among default TrustManagers: " + Arrays.toString(tms));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyManagementException(e);
        } catch (KeyStoreException e2) {
            throw new KeyManagementException(e2);
        }
    }

    private static X509TrustManager findFirstX509TrustManager(TrustManager[] tms) {
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public String getEndpointIdentificationAlgorithm() {
        return this.endpointIdentificationAlgorithm;
    }

    /* access modifiers changed from: package-private */
    public void setEndpointIdentificationAlgorithm(String endpointIdentificationAlgorithm2) {
        this.endpointIdentificationAlgorithm = endpointIdentificationAlgorithm2;
    }

    /* access modifiers changed from: package-private */
    public boolean getUseCipherSuitesOrder() {
        return this.useCipherSuitesOrder;
    }

    /* access modifiers changed from: package-private */
    public Collection<SNIMatcher> getSNIMatchers() {
        if (this.sniMatchers == null) {
            return null;
        }
        return new ArrayList(this.sniMatchers);
    }

    /* access modifiers changed from: package-private */
    public void setSNIMatchers(Collection<SNIMatcher> sniMatchers2) {
        this.sniMatchers = sniMatchers2 != null ? new ArrayList(sniMatchers2) : null;
    }

    /* access modifiers changed from: package-private */
    public AlgorithmConstraints getAlgorithmConstraints() {
        return this.algorithmConstraints;
    }

    /* access modifiers changed from: package-private */
    public void setAlgorithmConstraints(AlgorithmConstraints algorithmConstraints2) {
        this.algorithmConstraints = algorithmConstraints2;
    }

    /* access modifiers changed from: package-private */
    public void setUseCipherSuitesOrder(boolean useCipherSuitesOrder2) {
        this.useCipherSuitesOrder = useCipherSuitesOrder2;
    }

    private static String[] getDefaultCipherSuites(boolean x509CipherSuitesNeeded, boolean pskCipherSuitesNeeded) {
        if (x509CipherSuitesNeeded) {
            if (pskCipherSuitesNeeded) {
                return SSLUtils.concat(NativeCrypto.DEFAULT_PSK_CIPHER_SUITES, NativeCrypto.DEFAULT_X509_CIPHER_SUITES, new String[]{"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"});
            }
            return SSLUtils.concat(NativeCrypto.DEFAULT_X509_CIPHER_SUITES, new String[]{"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"});
        } else if (pskCipherSuitesNeeded) {
            return SSLUtils.concat(NativeCrypto.DEFAULT_PSK_CIPHER_SUITES, new String[]{"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"});
        } else {
            return new String[]{"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"};
        }
    }

    /* access modifiers changed from: package-private */
    public boolean isCTVerificationEnabled(String hostname) {
        if (hostname == null) {
            return false;
        }
        if (this.ctVerificationEnabled) {
            return true;
        }
        return Platform.isCTVerificationRequired(hostname);
    }
}
