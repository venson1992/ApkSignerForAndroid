package org.conscrypt;

import java.lang.reflect.Method;
import javax.net.ssl.SSLParameters;

/* access modifiers changed from: package-private */
public final class Java9PlatformUtil {
    private static final Method SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD;
    private static final Method SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD;

    static {
        Method getApplicationProtocolsMethod;
        Method setApplicationProtocolsMethod;
        try {
            getApplicationProtocolsMethod = SSLParameters.class.getMethod("getApplicationProtocols", new Class[0]);
            setApplicationProtocolsMethod = SSLParameters.class.getMethod("setApplicationProtocols", String[].class);
        } catch (NoSuchMethodException e) {
            getApplicationProtocolsMethod = null;
            setApplicationProtocolsMethod = null;
        }
        SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD = getApplicationProtocolsMethod;
        SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD = setApplicationProtocolsMethod;
    }

    static void setSSLParameters(SSLParameters src, SSLParametersImpl dest, AbstractConscryptSocket socket) {
        Java8PlatformUtil.setSSLParameters(src, dest, socket);
        dest.setApplicationProtocols(getApplicationProtocols(src));
    }

    static void getSSLParameters(SSLParameters dest, SSLParametersImpl src, AbstractConscryptSocket socket) {
        Java8PlatformUtil.getSSLParameters(dest, src, socket);
        setApplicationProtocols(dest, src.getApplicationProtocols());
    }

    static void setSSLParameters(SSLParameters src, SSLParametersImpl dest, ConscryptEngine engine) {
        Java8PlatformUtil.setSSLParameters(src, dest, engine);
        dest.setApplicationProtocols(getApplicationProtocols(src));
    }

    static void getSSLParameters(SSLParameters dest, SSLParametersImpl src, ConscryptEngine engine) {
        Java8PlatformUtil.getSSLParameters(dest, src, engine);
        setApplicationProtocols(dest, src.getApplicationProtocols());
    }

    private static String[] getApplicationProtocols(SSLParameters params) {
        if (SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                return (String[]) SSL_PARAMETERS_GET_APPLICATION_PROTOCOLS_METHOD.invoke(params, new Object[0]);
            } catch (ReflectiveOperationException e) {
            }
        }
        return EmptyArray.STRING;
    }

    private static void setApplicationProtocols(SSLParameters params, String[] protocols) {
        if (SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD != null) {
            try {
                SSL_PARAMETERS_SET_APPLICATION_PROTOCOLS_METHOD.invoke(params, protocols);
            } catch (ReflectiveOperationException e) {
            }
        }
    }

    private Java9PlatformUtil() {
    }
}
