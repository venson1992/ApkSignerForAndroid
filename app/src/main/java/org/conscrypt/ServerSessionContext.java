package org.conscrypt;

public final class ServerSessionContext extends AbstractSessionContext {
    private SSLServerSessionCache persistentCache;

    ServerSessionContext() {
        super(100);
        NativeCrypto.SSL_CTX_set_session_id_context(this.sslCtxNativePointer, this, new byte[]{32});
    }

    public void setPersistentCache(SSLServerSessionCache persistentCache2) {
        this.persistentCache = persistentCache2;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public NativeSslSession getSessionFromPersistentCache(byte[] sessionId) {
        byte[] data;
        NativeSslSession session;
        if (this.persistentCache == null || (data = this.persistentCache.getSessionData(sessionId)) == null || (session = NativeSslSession.newInstance(this, data, null, -1)) == null || !session.isValid()) {
            return null;
        }
        cacheSession(session);
        return session;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public void onBeforeAddSession(NativeSslSession session) {
        byte[] data;
        if (this.persistentCache != null && (data = session.toBytes()) != null) {
            this.persistentCache.putSessionData(session.toSSLSession(), data);
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractSessionContext
    public void onBeforeRemoveSession(NativeSslSession session) {
    }
}
