package org.conscrypt;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;

/* access modifiers changed from: package-private */
public final class ExternalSession implements ConscryptSession {
    private final Provider provider;
    private final HashMap<String, Object> values = new HashMap<>(2);

    /* access modifiers changed from: package-private */
    public interface Provider {
        ConscryptSession provideSession();
    }

    public ExternalSession(Provider provider2) {
        this.provider = provider2;
    }

    @Override // org.conscrypt.ConscryptSession
    public String getRequestedServerName() {
        return this.provider.provideSession().getRequestedServerName();
    }

    @Override // org.conscrypt.ConscryptSession
    public List<byte[]> getStatusResponses() {
        return this.provider.provideSession().getStatusResponses();
    }

    @Override // org.conscrypt.ConscryptSession
    public byte[] getPeerSignedCertificateTimestamp() {
        return this.provider.provideSession().getPeerSignedCertificateTimestamp();
    }

    public byte[] getId() {
        return this.provider.provideSession().getId();
    }

    public SSLSessionContext getSessionContext() {
        return this.provider.provideSession().getSessionContext();
    }

    public long getCreationTime() {
        return this.provider.provideSession().getCreationTime();
    }

    public long getLastAccessedTime() {
        return this.provider.provideSession().getLastAccessedTime();
    }

    public void invalidate() {
        this.provider.provideSession().invalidate();
    }

    public boolean isValid() {
        return this.provider.provideSession().isValid();
    }

    @Override // org.conscrypt.ConscryptSession, javax.net.ssl.SSLSession
    public X509Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return this.provider.provideSession().getPeerCertificates();
    }

    public Certificate[] getLocalCertificates() {
        return this.provider.provideSession().getLocalCertificates();
    }

    @Override // javax.net.ssl.SSLSession
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return this.provider.provideSession().getPeerCertificateChain();
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return this.provider.provideSession().getPeerPrincipal();
    }

    public Principal getLocalPrincipal() {
        return this.provider.provideSession().getLocalPrincipal();
    }

    public String getCipherSuite() {
        return this.provider.provideSession().getCipherSuite();
    }

    public String getProtocol() {
        return this.provider.provideSession().getProtocol();
    }

    public String getPeerHost() {
        return this.provider.provideSession().getPeerHost();
    }

    public int getPeerPort() {
        return this.provider.provideSession().getPeerPort();
    }

    public int getPacketBufferSize() {
        return this.provider.provideSession().getPacketBufferSize();
    }

    public int getApplicationBufferSize() {
        return this.provider.provideSession().getApplicationBufferSize();
    }

    @Override // org.conscrypt.ConscryptSession
    public String getApplicationProtocol() {
        return this.provider.provideSession().getApplicationProtocol();
    }

    public Object getValue(String name) {
        if (name != null) {
            return this.values.get(name);
        }
        throw new IllegalArgumentException("name == null");
    }

    public String[] getValueNames() {
        return (String[]) this.values.keySet().toArray(new String[this.values.size()]);
    }

    public void putValue(String name, Object value) {
        putValue(this, name, value);
    }

    /* access modifiers changed from: package-private */
    public void putValue(SSLSession session, String name, Object value) {
        if (name == null || value == null) {
            throw new IllegalArgumentException("name == null || value == null");
        }
        Object old = this.values.put(name, value);
        if (value instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) value).valueBound(new SSLSessionBindingEvent(session, name));
        }
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(session, name));
        }
    }

    public void removeValue(String name) {
        removeValue(this, name);
    }

    /* access modifiers changed from: package-private */
    public void removeValue(SSLSession session, String name) {
        if (name == null) {
            throw new IllegalArgumentException("name == null");
        }
        Object old = this.values.remove(name);
        if (old instanceof SSLSessionBindingListener) {
            ((SSLSessionBindingListener) old).valueUnbound(new SSLSessionBindingEvent(session, name));
        }
    }
}
