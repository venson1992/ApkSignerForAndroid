package org.conscrypt;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

/* access modifiers changed from: package-private */
public final class SessionSnapshot implements ConscryptSession {
    private final String applicationProtocol;
    private final String cipherSuite;
    private final long creationTime;
    private final byte[] id;
    private final long lastAccessedTime;
    private final String peerHost;
    private final int peerPort;
    private final byte[] peerTlsSctData;
    private final String protocol;
    private final String requestedServerName;
    private final SSLSessionContext sessionContext;
    private final List<byte[]> statusResponses;

    SessionSnapshot(ConscryptSession session) {
        this.sessionContext = session.getSessionContext();
        this.id = session.getId();
        this.requestedServerName = session.getRequestedServerName();
        this.statusResponses = session.getStatusResponses();
        this.peerTlsSctData = session.getPeerSignedCertificateTimestamp();
        this.creationTime = session.getCreationTime();
        this.lastAccessedTime = session.getLastAccessedTime();
        this.cipherSuite = session.getCipherSuite();
        this.protocol = session.getProtocol();
        this.peerHost = session.getPeerHost();
        this.peerPort = session.getPeerPort();
        this.applicationProtocol = session.getApplicationProtocol();
    }

    @Override // org.conscrypt.ConscryptSession
    public String getRequestedServerName() {
        return this.requestedServerName;
    }

    @Override // org.conscrypt.ConscryptSession
    public List<byte[]> getStatusResponses() {
        ArrayList arrayList = new ArrayList(this.statusResponses.size());
        for (byte[] resp : this.statusResponses) {
            arrayList.add(resp.clone());
        }
        return arrayList;
    }

    @Override // org.conscrypt.ConscryptSession
    public byte[] getPeerSignedCertificateTimestamp() {
        if (this.peerTlsSctData != null) {
            return (byte[]) this.peerTlsSctData.clone();
        }
        return null;
    }

    public byte[] getId() {
        return this.id;
    }

    public SSLSessionContext getSessionContext() {
        return this.sessionContext;
    }

    public long getCreationTime() {
        return this.creationTime;
    }

    public long getLastAccessedTime() {
        return this.lastAccessedTime;
    }

    public void invalidate() {
    }

    public boolean isValid() {
        return false;
    }

    public void putValue(String s, Object o) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public Object getValue(String s) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public void removeValue(String s) {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    public String[] getValueNames() {
        throw new UnsupportedOperationException("All calls to this method should be intercepted by ExternalSession.");
    }

    @Override // org.conscrypt.ConscryptSession, javax.net.ssl.SSLSession
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    public Certificate[] getLocalCertificates() {
        return null;
    }

    @Override // javax.net.ssl.SSLSession
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        throw new SSLPeerUnverifiedException("No peer certificates");
    }

    public Principal getLocalPrincipal() {
        return null;
    }

    public String getCipherSuite() {
        return this.cipherSuite;
    }

    public String getProtocol() {
        return this.protocol;
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
        return this.applicationProtocol;
    }
}
