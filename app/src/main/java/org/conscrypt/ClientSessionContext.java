package org.conscrypt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ClientSessionContext extends AbstractSessionContext {
    private SSLClientSessionCache persistentCache;
    private final Map<HostAndPort, List<NativeSslSession>> sessionsByHostAndPort = new HashMap();

    ClientSessionContext() {
        super(10);
    }

    public void setPersistentCache(SSLClientSessionCache persistentCache2) {
        this.persistentCache = persistentCache2;
    }

    /* access modifiers changed from: package-private */
    public synchronized NativeSslSession getCachedSession(String hostName, int port, SSLParametersImpl sslParameters) {
        NativeSslSession session;
        if (hostName == null) {
            session = null;
        } else {
            session = getSession(hostName, port);
            if (session == null) {
                session = null;
            } else {
                String protocol = session.getProtocol();
                boolean protocolFound = false;
                String[] strArr = sslParameters.enabledProtocols;
                int length = strArr.length;
                int i = 0;
                while (true) {
                    if (i >= length) {
                        break;
                    } else if (protocol.equals(strArr[i])) {
                        protocolFound = true;
                        break;
                    } else {
                        i++;
                    }
                }
                if (!protocolFound) {
                    session = null;
                } else {
                    String cipherSuite = session.getCipherSuite();
                    boolean cipherSuiteFound = false;
                    String[] enabledCipherSuites = sslParameters.getEnabledCipherSuites();
                    int length2 = enabledCipherSuites.length;
                    int i2 = 0;
                    while (true) {
                        if (i2 >= length2) {
                            break;
                        } else if (cipherSuite.equals(enabledCipherSuites[i2])) {
                            cipherSuiteFound = true;
                            break;
                        } else {
                            i2++;
                        }
                    }
                    if (!cipherSuiteFound) {
                        session = null;
                    } else if (session.isSingleUse()) {
                        removeSession(session);
                    }
                }
            }
        }
        return session;
    }

    /* access modifiers changed from: package-private */
    public int size() {
        int size = 0;
        synchronized (this.sessionsByHostAndPort) {
            for (List<NativeSslSession> sessions : this.sessionsByHostAndPort.values()) {
                size += sessions.size();
            }
        }
        return size;
    }

    private NativeSslSession getSession(String host, int port) {
        byte[] data;
        NativeSslSession session;
        if (host == null) {
            return null;
        }
        HostAndPort key = new HostAndPort(host, port);
        NativeSslSession session2 = null;
        synchronized (this.sessionsByHostAndPort) {
            List<NativeSslSession> sessions = this.sessionsByHostAndPort.get(key);
            if (sessions != null && sessions.size() > 0) {
                session2 = sessions.get(0);
            }
        }
        if (session2 != null && session2.isValid()) {
            return session2;
        }
        if (this.persistentCache == null || (data = this.persistentCache.getSessionData(host, port)) == null || (session = NativeSslSession.newInstance(this, data, host, port)) == null || !session.isValid()) {
            return null;
        }
        putSession(key, session);
        return session;
    }

    private void putSession(HostAndPort key, NativeSslSession session) {
        synchronized (this.sessionsByHostAndPort) {
            List<NativeSslSession> sessions = this.sessionsByHostAndPort.get(key);
            if (sessions == null) {
                sessions = new ArrayList<>();
                this.sessionsByHostAndPort.put(key, sessions);
            }
            if (sessions.size() > 0 && sessions.get(0).isSingleUse() != session.isSingleUse()) {
                while (!sessions.isEmpty()) {
                    removeSession(sessions.get(0));
                }
                this.sessionsByHostAndPort.put(key, sessions);
            }
            sessions.add(session);
        }
    }

    private void removeSession(HostAndPort key, NativeSslSession session) {
        synchronized (this.sessionsByHostAndPort) {
            List<NativeSslSession> sessions = this.sessionsByHostAndPort.get(key);
            if (sessions != null) {
                sessions.remove(session);
                if (sessions.isEmpty()) {
                    this.sessionsByHostAndPort.remove(key);
                }
            }
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public void onBeforeAddSession(NativeSslSession session) {
        byte[] data;
        String host = session.getPeerHost();
        int port = session.getPeerPort();
        if (host != null) {
            putSession(new HostAndPort(host, port), session);
            if (this.persistentCache != null && !session.isSingleUse() && (data = session.toBytes()) != null) {
                this.persistentCache.putSessionData(session.toSSLSession(), data);
            }
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public void onBeforeRemoveSession(NativeSslSession session) {
        String host = session.getPeerHost();
        if (host != null) {
            removeSession(new HostAndPort(host, session.getPeerPort()), session);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public NativeSslSession getSessionFromPersistentCache(byte[] sessionId) {
        return null;
    }

    /* access modifiers changed from: private */
    public static final class HostAndPort {
        final String host;
        final int port;

        HostAndPort(String host2, int port2) {
            this.host = host2;
            this.port = port2;
        }

        public int hashCode() {
            return (this.host.hashCode() * 31) + this.port;
        }

        public boolean equals(Object o) {
            if (!(o instanceof HostAndPort)) {
                return false;
            }
            HostAndPort lhs = (HostAndPort) o;
            if (!this.host.equals(lhs.host) || this.port != lhs.port) {
                return false;
            }
            return true;
        }
    }
}
