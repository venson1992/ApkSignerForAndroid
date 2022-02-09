package org.conscrypt;

import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/* access modifiers changed from: package-private */
public abstract class AbstractSessionContext implements SSLSessionContext {
    private static final int DEFAULT_SESSION_TIMEOUT_SECONDS = 28800;
    private volatile int maximumSize;
    private final Map<ByteArray, NativeSslSession> sessions = new LinkedHashMap<ByteArray, NativeSslSession>() {
        /* class org.conscrypt.AbstractSessionContext.AnonymousClass1 */

        /* access modifiers changed from: protected */
        @Override // java.util.LinkedHashMap
        public boolean removeEldestEntry(Map.Entry<ByteArray, NativeSslSession> eldest) {
            if (AbstractSessionContext.this.maximumSize <= 0 || size() <= AbstractSessionContext.this.maximumSize) {
                return false;
            }
            AbstractSessionContext.this.onBeforeRemoveSession(eldest.getValue());
            return true;
        }
    };
    final long sslCtxNativePointer = NativeCrypto.SSL_CTX_new();
    private volatile int timeout = DEFAULT_SESSION_TIMEOUT_SECONDS;

    /* access modifiers changed from: package-private */
    public abstract NativeSslSession getSessionFromPersistentCache(byte[] bArr);

    /* access modifiers changed from: package-private */
    public abstract void onBeforeAddSession(NativeSslSession nativeSslSession);

    /* access modifiers changed from: package-private */
    public abstract void onBeforeRemoveSession(NativeSslSession nativeSslSession);

    AbstractSessionContext(int maximumSize2) {
        this.maximumSize = maximumSize2;
    }

    @Override // javax.net.ssl.SSLSessionContext
    public final Enumeration<byte[]> getIds() {
        final Iterator<NativeSslSession> iter;
        synchronized (this.sessions) {
            iter = Arrays.asList(this.sessions.values().toArray(new NativeSslSession[this.sessions.size()])).iterator();
        }
        return new Enumeration<byte[]>() {
            /* class org.conscrypt.AbstractSessionContext.AnonymousClass2 */
            private NativeSslSession next;

            public boolean hasMoreElements() {
                if (this.next != null) {
                    return true;
                }
                while (iter.hasNext()) {
                    NativeSslSession session = (NativeSslSession) iter.next();
                    if (session.isValid()) {
                        this.next = session;
                        return true;
                    }
                }
                this.next = null;
                return false;
            }

            @Override // java.util.Enumeration
            public byte[] nextElement() {
                if (hasMoreElements()) {
                    byte[] id = this.next.getId();
                    this.next = null;
                    return id;
                }
                throw new NoSuchElementException();
            }
        };
    }

    public final SSLSession getSession(byte[] sessionId) {
        NativeSslSession session;
        if (sessionId == null) {
            throw new NullPointerException("sessionId");
        }
        ByteArray key = new ByteArray(sessionId);
        synchronized (this.sessions) {
            session = this.sessions.get(key);
        }
        if (session == null || !session.isValid()) {
            return null;
        }
        return session.toSSLSession();
    }

    public final int getSessionCacheSize() {
        return this.maximumSize;
    }

    public final int getSessionTimeout() {
        return this.timeout;
    }

    @Override // javax.net.ssl.SSLSessionContext
    public final void setSessionTimeout(int seconds) throws IllegalArgumentException {
        if (seconds < 0) {
            throw new IllegalArgumentException("seconds < 0");
        }
        synchronized (this.sessions) {
            this.timeout = seconds;
            if (seconds > 0) {
                NativeCrypto.SSL_CTX_set_timeout(this.sslCtxNativePointer, this, (long) seconds);
            } else {
                NativeCrypto.SSL_CTX_set_timeout(this.sslCtxNativePointer, this, 2147483647L);
            }
            Iterator<NativeSslSession> i = this.sessions.values().iterator();
            while (i.hasNext()) {
                NativeSslSession session = i.next();
                if (!session.isValid()) {
                    onBeforeRemoveSession(session);
                    i.remove();
                }
            }
        }
    }

    @Override // javax.net.ssl.SSLSessionContext
    public final void setSessionCacheSize(int size) throws IllegalArgumentException {
        if (size < 0) {
            throw new IllegalArgumentException("size < 0");
        }
        int oldMaximum = this.maximumSize;
        this.maximumSize = size;
        if (size < oldMaximum) {
            trimToSize();
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.lang.Object
    public void finalize() throws Throwable {
        try {
            NativeCrypto.SSL_CTX_free(this.sslCtxNativePointer, this);
        } finally {
            super.finalize();
        }
    }

    /* access modifiers changed from: package-private */
    public final void cacheSession(NativeSslSession session) {
        byte[] id = session.getId();
        if (id != null && id.length != 0) {
            synchronized (this.sessions) {
                ByteArray key = new ByteArray(id);
                if (this.sessions.containsKey(key)) {
                    removeSession(this.sessions.get(key));
                }
                onBeforeAddSession(session);
                this.sessions.put(key, session);
            }
        }
    }

    /* access modifiers changed from: package-private */
    public final void removeSession(NativeSslSession session) {
        byte[] id = session.getId();
        if (id != null && id.length != 0) {
            onBeforeRemoveSession(session);
            ByteArray key = new ByteArray(id);
            synchronized (this.sessions) {
                this.sessions.remove(key);
            }
        }
    }

    /* access modifiers changed from: package-private */
    public final NativeSslSession getSessionFromCache(byte[] sessionId) {
        NativeSslSession session;
        if (sessionId == null) {
            return null;
        }
        synchronized (this.sessions) {
            session = this.sessions.get(new ByteArray(sessionId));
        }
        if (session == null || !session.isValid()) {
            return getSessionFromPersistentCache(sessionId);
        }
        if (!session.isSingleUse()) {
            return session;
        }
        removeSession(session);
        return session;
    }

    private void trimToSize() {
        synchronized (this.sessions) {
            int size = this.sessions.size();
            if (size > this.maximumSize) {
                int removals = size - this.maximumSize;
                Iterator<NativeSslSession> i = this.sessions.values().iterator();
                int removals2 = removals;
                while (true) {
                    int removals3 = removals2 - 1;
                    if (removals2 <= 0) {
                        break;
                    }
                    onBeforeRemoveSession(i.next());
                    i.remove();
                    removals2 = removals3;
                }
            }
        }
    }
}
