package org.conscrypt;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

final class ActiveSession implements ConscryptSession {
    private String applicationProtocol;
    private long creationTime;
    private byte[] id;
    private long lastAccessedTime = 0;
    private X509Certificate[] localCertificates;
    private volatile javax.security.cert.X509Certificate[] peerCertificateChain;
    private byte[] peerCertificateOcspData;
    private X509Certificate[] peerCertificates;
    private String peerHost;
    private int peerPort = -1;
    private byte[] peerTlsSctData;
    private String protocol;
    private AbstractSessionContext sessionContext;
    private final NativeSsl ssl;

    ActiveSession(NativeSsl ssl2, AbstractSessionContext sessionContext2) {
        this.ssl = (NativeSsl) Preconditions.checkNotNull(ssl2, "ssl");
        this.sessionContext = (AbstractSessionContext) Preconditions.checkNotNull(sessionContext2, "sessionContext");
    }

    public byte[] getId() {
        if (this.id == null) {
            synchronized (this.ssl) {
                this.id = this.ssl.getSessionId();
            }
        }
        return this.id != null ? (byte[]) this.id.clone() : EmptyArray.BYTE;
    }

    public SSLSessionContext getSessionContext() {
        if (isValid()) {
            return this.sessionContext;
        }
        return null;
    }

    public long getCreationTime() {
        if (this.creationTime == 0) {
            synchronized (this.ssl) {
                this.creationTime = this.ssl.getTime();
            }
        }
        return this.creationTime;
    }

    public long getLastAccessedTime() {
        return this.lastAccessedTime == 0 ? getCreationTime() : this.lastAccessedTime;
    }

    /* access modifiers changed from: package-private */
    public void setLastAccessedTime(long accessTimeMillis) {
        this.lastAccessedTime = accessTimeMillis;
    }

    @Override // org.conscrypt.ConscryptSession
    public List<byte[]> getStatusResponses() {
        if (this.peerCertificateOcspData == null) {
            return Collections.emptyList();
        }
        return Collections.singletonList(this.peerCertificateOcspData.clone());
    }

    @Override // org.conscrypt.ConscryptSession
    public byte[] getPeerSignedCertificateTimestamp() {
        if (this.peerTlsSctData == null) {
            return null;
        }
        return (byte[]) this.peerTlsSctData.clone();
    }

    @Override // org.conscrypt.ConscryptSession
    public String getRequestedServerName() {
        String requestedServerName;
        synchronized (this.ssl) {
            requestedServerName = this.ssl.getRequestedServerName();
        }
        return requestedServerName;
    }

    public void invalidate() {
        synchronized (this.ssl) {
            this.ssl.setTimeout(0);
        }
    }

    public boolean isValid() {
        boolean z;
        synchronized (this.ssl) {
            z = System.currentTimeMillis() - this.ssl.getTimeout() < this.ssl.getTime();
        }
        return z;
    }

    public void putValue(String name, Object value) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public Object getValue(String name) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public void removeValue(String name) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public String[] getValueNames() {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    @Override // org.conscrypt.ConscryptSession, javax.net.ssl.SSLSession
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        return (X509Certificate[]) this.peerCertificates.clone();
    }

    public Certificate[] getLocalCertificates() {
        if (this.localCertificates == null) {
            synchronized (this.ssl) {
                this.localCertificates = this.ssl.getLocalCertificates();
            }
        }
        if (this.localCertificates == null) {
            return null;
        }
        return (X509Certificate[]) this.localCertificates.clone();
    }

    @Override // javax.net.ssl.SSLSession
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        javax.security.cert.X509Certificate[] result = this.peerCertificateChain;
        if (result != null) {
            return result;
        }
        javax.security.cert.X509Certificate[] result2 = SSLUtils.toCertificateChain(this.peerCertificates);
        this.peerCertificateChain = result2;
        return result2;
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        checkPeerCertificatesPresent();
        return this.peerCertificates[0].getSubjectX500Principal();
    }

    public Principal getLocalPrincipal() {
        X509Certificate[] certs = (X509Certificate[]) getLocalCertificates();
        if (certs == null || certs.length <= 0) {
            return null;
        }
        return certs[0].getSubjectX500Principal();
    }

    public String getCipherSuite() {
        String cipher;
        synchronized (this.ssl) {
            cipher = this.ssl.getCipherSuite();
        }
        return cipher == null ? "SSL_NULL_WITH_NULL_NULL" : cipher;
    }

    public String getProtocol() {
        String protocol2 = this.protocol;
        if (protocol2 == null) {
            synchronized (this.ssl) {
                protocol2 = this.ssl.getVersion();
            }
            this.protocol = protocol2;
        }
        return protocol2;
    }

    public String getPeerHost() {
        return this.peerHost;
    }

    public int getPeerPort() {
        return this.peerPort;
    }

    public int getPacketBufferSize() {
        return 16709;
    }

    public int getApplicationBufferSize() {
        return 16384;
    }

    @Override // org.conscrypt.ConscryptSession
    public String getApplicationProtocol() {
        String applicationProtocol2 = this.applicationProtocol;
        if (applicationProtocol2 == null) {
            synchronized (this.ssl) {
                applicationProtocol2 = SSLUtils.toProtocolString(this.ssl.getApplicationProtocol());
            }
            this.applicationProtocol = applicationProtocol2;
        }
        return applicationProtocol2;
    }

    /* access modifiers changed from: package-private */
    public void onPeerCertificatesReceived(String peerHost2, int peerPort2, X509Certificate[] peerCertificates2) {
        configurePeer(peerHost2, peerPort2, peerCertificates2);
    }

    private void configurePeer(String peerHost2, int peerPort2, X509Certificate[] peerCertificates2) {
        this.peerHost = peerHost2;
        this.peerPort = peerPort2;
        this.peerCertificates = peerCertificates2;
        synchronized (this.ssl) {
            this.peerCertificateOcspData = this.ssl.getPeerCertificateOcspData();
            this.peerTlsSctData = this.ssl.getPeerTlsSctData();
        }
    }

    /* access modifiers changed from: package-private */
    public void onPeerCertificateAvailable(String peerHost2, int peerPort2) throws CertificateException {
        synchronized (this.ssl) {
            this.id = null;
            if (this.localCertificates == null) {
                this.localCertificates = this.ssl.getLocalCertificates();
            }
            if (this.peerCertificates == null) {
                configurePeer(peerHost2, peerPort2, this.ssl.getPeerCertificates());
            }
        }
    }

    private void checkPeerCertificatesPresent() throws SSLPeerUnverifiedException {
        if (this.peerCertificates == null || this.peerCertificates.length == 0) {
            throw new SSLPeerUnverifiedException("No peer certificates");
        }
    }
}
