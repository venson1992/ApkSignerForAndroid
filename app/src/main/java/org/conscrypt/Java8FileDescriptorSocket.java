package org.conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.List;
import java.util.function.BiFunction;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public final class Java8FileDescriptorSocket extends ConscryptFileDescriptorSocket {
    private BiFunction<SSLSocket, List<String>, String> selector;

    Java8FileDescriptorSocket(SSLParametersImpl sslParameters) throws IOException {
        super(sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters) throws IOException {
        super(address, port, sslParameters);
    }

    Java8FileDescriptorSocket(String hostname, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort, sslParameters);
    }

    Java8FileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose, sslParameters);
    }

    @Override // javax.net.ssl.SSLSocket
    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLSocket, List<String>, String> selector2) {
        this.selector = selector2;
        setApplicationProtocolSelector(toApplicationProtocolSelector(selector2));
    }

    @Override // javax.net.ssl.SSLSocket
    public BiFunction<SSLSocket, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return this.selector;
    }

    private static ApplicationProtocolSelector toApplicationProtocolSelector(final BiFunction<SSLSocket, List<String>, String> selector2) {
        if (selector2 == null) {
            return null;
        }
        return new ApplicationProtocolSelector() {
            /* class org.conscrypt.Java8FileDescriptorSocket.AnonymousClass1 */

            @Override // org.conscrypt.ApplicationProtocolSelector
            public String selectApplicationProtocol(SSLEngine socket, List<String> list) {
                throw new UnsupportedOperationException();
            }

            @Override // org.conscrypt.ApplicationProtocolSelector
            public String selectApplicationProtocol(SSLSocket socket, List<String> protocols) {
                return (String) selector2.apply(socket, protocols);
            }
        };
    }
}
