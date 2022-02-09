package org.conscrypt;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* access modifiers changed from: package-private */
public abstract class AbstractConscryptSocket extends SSLSocket {
    private final boolean autoClose;
    private final List<HandshakeCompletedListener> listeners;
    private String peerHostname;
    private final PeerInfoProvider peerInfoProvider;
    private final int peerPort;
    private int readTimeoutMilliseconds;
    final Socket socket;

    /* access modifiers changed from: package-private */
    public abstract byte[] exportKeyingMaterial(String str, byte[] bArr, int i) throws SSLException;

    /* access modifiers changed from: package-private */
    public abstract SSLSession getActiveSession();

    /* access modifiers changed from: package-private */
    @Deprecated
    public abstract byte[] getAlpnSelectedProtocol();

    public abstract String getApplicationProtocol();

    /* access modifiers changed from: package-private */
    public abstract String[] getApplicationProtocols();

    /* access modifiers changed from: package-private */
    public abstract byte[] getChannelId() throws SSLException;

    public abstract String getHandshakeApplicationProtocol();

    public abstract SSLSession getHandshakeSession();

    /* access modifiers changed from: package-private */
    public abstract byte[] getTlsUnique();

    /* access modifiers changed from: package-private */
    @Deprecated
    public abstract void setAlpnProtocols(byte[] bArr);

    /* access modifiers changed from: package-private */
    @Deprecated
    public abstract void setAlpnProtocols(String[] strArr);

    /* access modifiers changed from: package-private */
    public abstract void setApplicationProtocolSelector(ApplicationProtocolSelector applicationProtocolSelector);

    /* access modifiers changed from: package-private */
    public abstract void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter applicationProtocolSelectorAdapter);

    /* access modifiers changed from: package-private */
    public abstract void setApplicationProtocols(String[] strArr);

    /* access modifiers changed from: package-private */
    public abstract void setChannelIdEnabled(boolean z);

    /* access modifiers changed from: package-private */
    public abstract void setChannelIdPrivateKey(PrivateKey privateKey);

    /* access modifiers changed from: package-private */
    public abstract void setUseSessionTickets(boolean z);

    AbstractConscryptSocket() throws IOException {
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(String hostname, int port) throws IOException {
        super(hostname, port);
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
    }

    AbstractConscryptSocket(InetAddress address, int port) throws IOException {
        super(address, port);
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(String hostname, int port, InetAddress clientAddress, int clientPort) throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = this;
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = false;
    }

    AbstractConscryptSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = this;
        this.peerHostname = null;
        this.peerPort = -1;
        this.autoClose = false;
    }

    AbstractConscryptSocket(Socket socket2, String hostname, int port, boolean autoClose2) throws IOException {
        this.peerInfoProvider = new PeerInfoProvider() {
            /* class org.conscrypt.AbstractConscryptSocket.AnonymousClass1 */

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostname() {
                return AbstractConscryptSocket.this.getHostname();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public String getHostnameOrIP() {
                return AbstractConscryptSocket.this.getHostnameOrIP();
            }

            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.PeerInfoProvider
            public int getPort() {
                return AbstractConscryptSocket.this.getPort();
            }
        };
        this.listeners = new ArrayList(2);
        this.socket = (Socket) Preconditions.checkNotNull(socket2, "socket");
        this.peerHostname = hostname;
        this.peerPort = port;
        this.autoClose = autoClose2;
    }

    @Override // java.net.Socket
    public final void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override // java.net.Socket
    public final void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (this.peerHostname == null && (endpoint instanceof InetSocketAddress)) {
            this.peerHostname = Platform.getHostStringFromInetSocketAddress((InetSocketAddress) endpoint);
        }
        if (isDelegating()) {
            this.socket.connect(endpoint, timeout);
        } else {
            super.connect(endpoint, timeout);
        }
    }

    @Override // java.net.Socket
    public void bind(SocketAddress bindpoint) throws IOException {
        if (isDelegating()) {
            this.socket.bind(bindpoint);
        } else {
            super.bind(bindpoint);
        }
    }

    @Override // java.net.Socket, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        if (isDelegating()) {
            if (this.autoClose && !this.socket.isClosed()) {
                this.socket.close();
            }
        } else if (!super.isClosed()) {
            super.close();
        }
    }

    public InetAddress getInetAddress() {
        if (isDelegating()) {
            return this.socket.getInetAddress();
        }
        return super.getInetAddress();
    }

    public InetAddress getLocalAddress() {
        if (isDelegating()) {
            return this.socket.getLocalAddress();
        }
        return super.getLocalAddress();
    }

    public int getLocalPort() {
        if (isDelegating()) {
            return this.socket.getLocalPort();
        }
        return super.getLocalPort();
    }

    public SocketAddress getRemoteSocketAddress() {
        if (isDelegating()) {
            return this.socket.getRemoteSocketAddress();
        }
        return super.getRemoteSocketAddress();
    }

    public SocketAddress getLocalSocketAddress() {
        if (isDelegating()) {
            return this.socket.getLocalSocketAddress();
        }
        return super.getLocalSocketAddress();
    }

    public final int getPort() {
        if (isDelegating()) {
            return this.socket.getPort();
        }
        if (this.peerPort != -1) {
            return this.peerPort;
        }
        return super.getPort();
    }

    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        Preconditions.checkArgument(listener != null, "Provided listener is null");
        this.listeners.add(listener);
    }

    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        Preconditions.checkArgument(listener != null, "Provided listener is null");
        if (!this.listeners.remove(listener)) {
            throw new IllegalArgumentException("Provided listener is not registered");
        }
    }

    public FileDescriptor getFileDescriptor$() {
        if (isDelegating()) {
            return Platform.getFileDescriptor(this.socket);
        }
        return Platform.getFileDescriptorFromSSLSocket(this);
    }

    @Override // java.net.Socket
    public final void setSoTimeout(int readTimeoutMilliseconds2) throws SocketException {
        if (isDelegating()) {
            this.socket.setSoTimeout(readTimeoutMilliseconds2);
            return;
        }
        super.setSoTimeout(readTimeoutMilliseconds2);
        this.readTimeoutMilliseconds = readTimeoutMilliseconds2;
    }

    @Override // java.net.Socket
    public final int getSoTimeout() throws SocketException {
        if (isDelegating()) {
            return this.socket.getSoTimeout();
        }
        return this.readTimeoutMilliseconds;
    }

    @Override // java.net.Socket
    public final void sendUrgentData(int data) throws IOException {
        throw new SocketException("Method sendUrgentData() is not supported.");
    }

    @Override // java.net.Socket
    public final void setOOBInline(boolean on) throws SocketException {
        throw new SocketException("Method setOOBInline() is not supported.");
    }

    @Override // java.net.Socket
    public boolean getOOBInline() throws SocketException {
        return false;
    }

    public SocketChannel getChannel() {
        return null;
    }

    @Override // java.net.Socket
    public InputStream getInputStream() throws IOException {
        if (isDelegating()) {
            return this.socket.getInputStream();
        }
        return super.getInputStream();
    }

    @Override // java.net.Socket
    public OutputStream getOutputStream() throws IOException {
        if (isDelegating()) {
            return this.socket.getOutputStream();
        }
        return super.getOutputStream();
    }

    @Override // java.net.Socket
    public void setTcpNoDelay(boolean on) throws SocketException {
        if (isDelegating()) {
            this.socket.setTcpNoDelay(on);
        } else {
            super.setTcpNoDelay(on);
        }
    }

    @Override // java.net.Socket
    public boolean getTcpNoDelay() throws SocketException {
        if (isDelegating()) {
            return this.socket.getTcpNoDelay();
        }
        return super.getTcpNoDelay();
    }

    @Override // java.net.Socket
    public void setSoLinger(boolean on, int linger) throws SocketException {
        if (isDelegating()) {
            this.socket.setSoLinger(on, linger);
        } else {
            super.setSoLinger(on, linger);
        }
    }

    @Override // java.net.Socket
    public int getSoLinger() throws SocketException {
        if (isDelegating()) {
            return this.socket.getSoLinger();
        }
        return super.getSoLinger();
    }

    @Override // java.net.Socket
    public void setSendBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            this.socket.setSendBufferSize(size);
        } else {
            super.setSendBufferSize(size);
        }
    }

    @Override // java.net.Socket
    public int getSendBufferSize() throws SocketException {
        if (isDelegating()) {
            return this.socket.getSendBufferSize();
        }
        return super.getSendBufferSize();
    }

    @Override // java.net.Socket
    public void setReceiveBufferSize(int size) throws SocketException {
        if (isDelegating()) {
            this.socket.setReceiveBufferSize(size);
        } else {
            super.setReceiveBufferSize(size);
        }
    }

    @Override // java.net.Socket
    public int getReceiveBufferSize() throws SocketException {
        if (isDelegating()) {
            return this.socket.getReceiveBufferSize();
        }
        return super.getReceiveBufferSize();
    }

    @Override // java.net.Socket
    public void setKeepAlive(boolean on) throws SocketException {
        if (isDelegating()) {
            this.socket.setKeepAlive(on);
        } else {
            super.setKeepAlive(on);
        }
    }

    @Override // java.net.Socket
    public boolean getKeepAlive() throws SocketException {
        if (isDelegating()) {
            return this.socket.getKeepAlive();
        }
        return super.getKeepAlive();
    }

    @Override // java.net.Socket
    public void setTrafficClass(int tc) throws SocketException {
        if (isDelegating()) {
            this.socket.setTrafficClass(tc);
        } else {
            super.setTrafficClass(tc);
        }
    }

    @Override // java.net.Socket
    public int getTrafficClass() throws SocketException {
        if (isDelegating()) {
            return this.socket.getTrafficClass();
        }
        return super.getTrafficClass();
    }

    @Override // java.net.Socket
    public void setReuseAddress(boolean on) throws SocketException {
        if (isDelegating()) {
            this.socket.setReuseAddress(on);
        } else {
            super.setReuseAddress(on);
        }
    }

    @Override // java.net.Socket
    public boolean getReuseAddress() throws SocketException {
        if (isDelegating()) {
            return this.socket.getReuseAddress();
        }
        return super.getReuseAddress();
    }

    @Override // java.net.Socket
    public void shutdownInput() throws IOException {
        if (isDelegating()) {
            this.socket.shutdownInput();
        } else {
            super.shutdownInput();
        }
    }

    @Override // java.net.Socket
    public void shutdownOutput() throws IOException {
        if (isDelegating()) {
            this.socket.shutdownOutput();
        } else {
            super.shutdownOutput();
        }
    }

    public boolean isConnected() {
        if (isDelegating()) {
            return this.socket.isConnected();
        }
        return super.isConnected();
    }

    public boolean isBound() {
        if (isDelegating()) {
            return this.socket.isBound();
        }
        return super.isBound();
    }

    public boolean isClosed() {
        if (isDelegating()) {
            return this.socket.isClosed();
        }
        return super.isClosed();
    }

    public boolean isInputShutdown() {
        if (isDelegating()) {
            return this.socket.isInputShutdown();
        }
        return super.isInputShutdown();
    }

    public boolean isOutputShutdown() {
        if (isDelegating()) {
            return this.socket.isOutputShutdown();
        }
        return super.isOutputShutdown();
    }

    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        if (isDelegating()) {
            this.socket.setPerformancePreferences(connectionTime, latency, bandwidth);
        } else {
            super.setPerformancePreferences(connectionTime, latency, bandwidth);
        }
    }

    public String toString() {
        StringBuilder builder = new StringBuilder("SSL socket over ");
        if (isDelegating()) {
            builder.append(this.socket.toString());
        } else {
            builder.append(super.toString());
        }
        return builder.toString();
    }

    /* access modifiers changed from: package-private */
    public String getHostname() {
        return this.peerHostname;
    }

    /* access modifiers changed from: package-private */
    public void setHostname(String hostname) {
        this.peerHostname = hostname;
    }

    /* access modifiers changed from: package-private */
    public String getHostnameOrIP() {
        if (this.peerHostname != null) {
            return this.peerHostname;
        }
        InetAddress peerAddress = getInetAddress();
        if (peerAddress != null) {
            return Platform.getOriginalHostNameFromInetAddress(peerAddress);
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public void setSoWriteTimeout(int writeTimeoutMilliseconds) throws SocketException {
        throw new SocketException("Method setSoWriteTimeout() is not supported.");
    }

    /* access modifiers changed from: package-private */
    public int getSoWriteTimeout() throws SocketException {
        return 0;
    }

    /* access modifiers changed from: package-private */
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
        throw new SocketException("Method setHandshakeTimeout() is not supported.");
    }

    /* access modifiers changed from: package-private */
    public final void checkOpen() throws SocketException {
        if (isClosed()) {
            throw new SocketException("Socket is closed");
        }
    }

    /* access modifiers changed from: package-private */
    public final PeerInfoProvider peerInfoProvider() {
        return this.peerInfoProvider;
    }

    /* access modifiers changed from: package-private */
    public final void notifyHandshakeCompletedListeners() {
        List<HandshakeCompletedListener> listenersCopy = new ArrayList<>(this.listeners);
        if (!listenersCopy.isEmpty()) {
            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getActiveSession());
            for (HandshakeCompletedListener listener : listenersCopy) {
                try {
                    listener.handshakeCompleted(event);
                } catch (RuntimeException e) {
                    Thread thread = Thread.currentThread();
                    thread.getUncaughtExceptionHandler().uncaughtException(thread, e);
                }
            }
        }
    }

    private boolean isDelegating() {
        return (this.socket == null || this.socket == this) ? false : true;
    }

    /* access modifiers changed from: package-private */
    @Deprecated
    public byte[] getNpnSelectedProtocol() {
        return null;
    }

    /* access modifiers changed from: package-private */
    @Deprecated
    public void setNpnProtocols(byte[] npnProtocols) {
    }
}
