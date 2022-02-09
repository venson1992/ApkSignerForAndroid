package org.conscrypt;

import java.lang.reflect.Method;
import java.net.Socket;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngine;

/* access modifiers changed from: package-private */
@Deprecated
public final class DuckTypedPSKKeyManager implements PSKKeyManager {
    private final Object mDelegate;

    private DuckTypedPSKKeyManager(Object delegate) {
        this.mDelegate = delegate;
    }

    static DuckTypedPSKKeyManager getInstance(Object obj) throws NoSuchMethodException {
        Class<?> sourceClass = obj.getClass();
        Method[] methods = PSKKeyManager.class.getMethods();
        for (Method targetMethod : methods) {
            if (!targetMethod.isSynthetic()) {
                Method sourceMethod = sourceClass.getMethod(targetMethod.getName(), targetMethod.getParameterTypes());
                Class<?> sourceReturnType = sourceMethod.getReturnType();
                Class<?> targetReturnType = targetMethod.getReturnType();
                if (!targetReturnType.isAssignableFrom(sourceReturnType)) {
                    throw new NoSuchMethodException(sourceMethod + " return value (" + sourceReturnType + ") incompatible with target return value (" + targetReturnType + ")");
                }
            }
        }
        return new DuckTypedPSKKeyManager(obj);
    }

    @Override // org.conscrypt.PSKKeyManager
    public String chooseServerKeyIdentityHint(Socket socket) {
        try {
            return (String) this.mDelegate.getClass().getMethod("chooseServerKeyIdentityHint", Socket.class).invoke(this.mDelegate, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseServerKeyIdentityHint", e);
        }
    }

    @Override // org.conscrypt.PSKKeyManager
    public String chooseServerKeyIdentityHint(SSLEngine engine) {
        try {
            return (String) this.mDelegate.getClass().getMethod("chooseServerKeyIdentityHint", SSLEngine.class).invoke(this.mDelegate, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseServerKeyIdentityHint", e);
        }
    }

    @Override // org.conscrypt.PSKKeyManager
    public String chooseClientKeyIdentity(String identityHint, Socket socket) {
        try {
            return (String) this.mDelegate.getClass().getMethod("chooseClientKeyIdentity", String.class, Socket.class).invoke(this.mDelegate, identityHint, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseClientKeyIdentity", e);
        }
    }

    @Override // org.conscrypt.PSKKeyManager
    public String chooseClientKeyIdentity(String identityHint, SSLEngine engine) {
        try {
            return (String) this.mDelegate.getClass().getMethod("chooseClientKeyIdentity", String.class, SSLEngine.class).invoke(this.mDelegate, identityHint, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke chooseClientKeyIdentity", e);
        }
    }

    @Override // org.conscrypt.PSKKeyManager
    public SecretKey getKey(String identityHint, String identity, Socket socket) {
        try {
            return (SecretKey) this.mDelegate.getClass().getMethod("getKey", String.class, String.class, Socket.class).invoke(this.mDelegate, identityHint, identity, socket);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getKey", e);
        }
    }

    @Override // org.conscrypt.PSKKeyManager
    public SecretKey getKey(String identityHint, String identity, SSLEngine engine) {
        try {
            return (SecretKey) this.mDelegate.getClass().getMethod("getKey", String.class, String.class, SSLEngine.class).invoke(this.mDelegate, identityHint, identity, engine);
        } catch (Exception e) {
            throw new RuntimeException("Failed to invoke getKey", e);
        }
    }
}
