package org.conscrypt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/* access modifiers changed from: package-private */
public final class Java8PlatformUtil {
    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        setSSLParameters(params, impl);
        String sniHost = getSniHostName(params);
        if (sniHost != null) {
            socket.setHostname(sniHost);
        }
    }

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl, AbstractConscryptSocket socket) {
        getSSLParameters(params, impl);
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(socket.getHostname())) {
            params.setServerNames(Collections.singletonList(new SNIHostName(socket.getHostname())));
        }
    }

    static void setSSLParameters(SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        setSSLParameters(params, impl);
        String sniHost = getSniHostName(params);
        if (sniHost != null) {
            engine.setHostname(sniHost);
        }
    }

    static void getSSLParameters(SSLParameters params, SSLParametersImpl impl, ConscryptEngine engine) {
        getSSLParameters(params, impl);
        if (impl.getUseSni() && AddressUtils.isValidSniHostname(engine.getHostname())) {
            params.setServerNames(Collections.singletonList(new SNIHostName(engine.getHostname())));
        }
    }

    private static String getSniHostName(SSLParameters params) {
        List<SNIServerName> serverNames = params.getServerNames();
        if (serverNames != null) {
            for (SNIServerName serverName : serverNames) {
                if (serverName.getType() == 0) {
                    return ((SNIHostName) serverName).getAsciiName();
                }
            }
        }
        return null;
    }

    private static void setSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        impl.setEndpointIdentificationAlgorithm(params.getEndpointIdentificationAlgorithm());
        impl.setUseCipherSuitesOrder(params.getUseCipherSuitesOrder());
        impl.setSNIMatchers(params.getSNIMatchers());
        impl.setAlgorithmConstraints(params.getAlgorithmConstraints());
    }

    private static void getSSLParameters(SSLParameters params, SSLParametersImpl impl) {
        params.setEndpointIdentificationAlgorithm(impl.getEndpointIdentificationAlgorithm());
        params.setUseCipherSuitesOrder(impl.getUseCipherSuitesOrder());
        params.setSNIMatchers(impl.getSNIMatchers());
        params.setAlgorithmConstraints(impl.getAlgorithmConstraints());
    }

    static boolean serverNamePermitted(SSLParametersImpl parameters, String serverName) {
        Collection<SNIMatcher> sniMatchers = parameters.getSNIMatchers();
        if (sniMatchers == null || sniMatchers.isEmpty()) {
            return true;
        }
        for (SNIMatcher m : sniMatchers) {
            if (m.matches(new SNIHostName(serverName))) {
                return true;
            }
        }
        return false;
    }

    static SSLEngine wrapEngine(ConscryptEngine engine) {
        return new Java8EngineWrapper(engine);
    }

    static SSLEngine unwrapEngine(SSLEngine engine) {
        return Java8EngineWrapper.getDelegate(engine);
    }

    static SSLSession wrapSSLSession(ExternalSession sslSession) {
        return new Java8ExtendedSSLSession(sslSession);
    }

    private Java8PlatformUtil() {
    }
}
