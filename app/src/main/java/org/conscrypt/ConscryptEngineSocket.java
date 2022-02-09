package org.conscrypt;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.SSLParametersImpl;

/* access modifiers changed from: package-private */
public class ConscryptEngineSocket extends OpenSSLSocketImpl implements SSLParametersImpl.AliasChooser {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocate(0);
    private BufferAllocator bufferAllocator = ConscryptEngine.getDefaultBufferAllocator();
    private final ConscryptEngine engine;
    private final Object handshakeLock = new Object();
    private SSLInputStream in;
    private SSLOutputStream out;
    private int state = 0;
    private final Object stateLock = new Object();

    ConscryptEngineSocket(SSLParametersImpl sslParameters) throws IOException {
        this.engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(String hostname, int port, SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port);
        this.engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(InetAddress address, int port, SSLParametersImpl sslParameters) throws IOException {
        super(address, port);
        this.engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(String hostname, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.engine = newEngine(sslParameters, this);
    }

    ConscryptEngineSocket(Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters) throws IOException {
        super(socket, hostname, port, autoClose);
        this.engine = newEngine(sslParameters, this);
    }

    private static ConscryptEngine newEngine(SSLParametersImpl sslParameters, ConscryptEngineSocket socket) {
        SSLParametersImpl modifiedParams;
        if (Platform.supportsX509ExtendedTrustManager()) {
            modifiedParams = sslParameters.cloneWithTrustManager(getDelegatingTrustManager(sslParameters.getX509TrustManager(), socket));
        } else {
            modifiedParams = sslParameters;
        }
        ConscryptEngine engine2 = new ConscryptEngine(modifiedParams, socket.peerInfoProvider(), socket);
        engine2.setHandshakeListener(new HandshakeListener() {
            /* class org.conscrypt.ConscryptEngineSocket.AnonymousClass1 */

            @Override // org.conscrypt.HandshakeListener
            public void onHandshakeFinished() {
                ConscryptEngineSocket.this.onHandshakeFinished();
            }
        });
        engine2.setUseClientMode(sslParameters.getUseClientMode());
        return engine2;
    }

    private static X509TrustManager getDelegatingTrustManager(X509TrustManager delegate, final ConscryptEngineSocket socket) {
        if (!(delegate instanceof X509ExtendedTrustManager)) {
            return delegate;
        }
        final X509ExtendedTrustManager extendedDelegate = (X509ExtendedTrustManager) delegate;
        return new X509ExtendedTrustManager() {
            /* class org.conscrypt.ConscryptEngineSocket.AnonymousClass2 */

            @Override // javax.net.ssl.X509ExtendedTrustManager
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                throw new AssertionError("Should not be called");
            }

            @Override // javax.net.ssl.X509ExtendedTrustManager
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
                throw new AssertionError("Should not be called");
            }

            @Override // javax.net.ssl.X509ExtendedTrustManager
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                extendedDelegate.checkClientTrusted(x509Certificates, s, socket);
            }

            @Override // javax.net.ssl.X509ExtendedTrustManager
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
                extendedDelegate.checkServerTrusted(x509Certificates, s, socket);
            }

            @Override // javax.net.ssl.X509TrustManager
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                extendedDelegate.checkClientTrusted(x509Certificates, s);
            }

            @Override // javax.net.ssl.X509TrustManager
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                extendedDelegate.checkServerTrusted(x509Certificates, s);
            }

            public X509Certificate[] getAcceptedIssuers() {
                return extendedDelegate.getAcceptedIssuers();
            }
        };
    }

    public final SSLParameters getSSLParameters() {
        return this.engine.getSSLParameters();
    }

    public final void setSSLParameters(SSLParameters sslParameters) {
        this.engine.setSSLParameters(sslParameters);
    }

    @Override // javax.net.ssl.SSLSocket
    public final void startHandshake() throws IOException {
        checkOpen();
        try {
            synchronized (this.handshakeLock) {
                synchronized (this.stateLock) {
                    if (this.state == 0) {
                        this.state = 2;
                        this.engine.beginHandshake();
                        this.in = new SSLInputStream();
                        this.out = new SSLOutputStream();
                        doHandshake();
                    }
                }
            }
        } catch (SSLException e) {
            close();
            throw e;
        } catch (IOException e2) {
            close();
            throw e2;
        } catch (Exception e3) {
            close();
            throw SSLUtils.toSSLHandshakeException(e3);
        }
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private void doHandshake() throws IOException {
        boolean finished = false;
        while (!finished) {
            try {
                switch (AnonymousClass3.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[this.engine.getHandshakeStatus().ordinal()]) {
                    case 1:
                        if (this.in.processDataFromSocket(EmptyArray.BYTE, 0, 0) >= 0) {
                            break;
                        } else {
                            throw SSLUtils.toSSLHandshakeException(new EOFException("connection closed"));
                        }
                    case 2:
                        this.out.writeInternal(EMPTY_BUFFER);
                        this.out.flushInternal();
                        break;
                    case 3:
                        throw new IllegalStateException("Engine tasks are unsupported");
                    case 4:
                    case 5:
                        finished = true;
                        break;
                    default:
                        throw new IllegalStateException("Unknown handshake status: " + this.engine.getHandshakeStatus());
                }
            } catch (SSLException e) {
                drainOutgoingQueue();
                close();
                throw e;
            } catch (IOException e2) {
                close();
                throw e2;
            } catch (Exception e3) {
                close();
                throw SSLUtils.toSSLHandshakeException(e3);
            }
        }
    }

    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final InputStream getInputStream() throws IOException {
        checkOpen();
        waitForHandshake();
        return this.in;
    }

    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final OutputStream getOutputStream() throws IOException {
        checkOpen();
        waitForHandshake();
        return this.out;
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final SSLSession getHandshakeSession() {
        return this.engine.handshakeSession();
    }

    public final SSLSession getSession() {
        if (isConnected()) {
            try {
                waitForHandshake();
            } catch (IOException e) {
            }
        }
        return this.engine.getSession();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final SSLSession getActiveSession() {
        return this.engine.getSession();
    }

    public final boolean getEnableSessionCreation() {
        return this.engine.getEnableSessionCreation();
    }

    public final void setEnableSessionCreation(boolean flag) {
        this.engine.setEnableSessionCreation(flag);
    }

    public final String[] getSupportedCipherSuites() {
        return this.engine.getSupportedCipherSuites();
    }

    public final String[] getEnabledCipherSuites() {
        return this.engine.getEnabledCipherSuites();
    }

    public final void setEnabledCipherSuites(String[] suites) {
        this.engine.setEnabledCipherSuites(suites);
    }

    public final String[] getSupportedProtocols() {
        return this.engine.getSupportedProtocols();
    }

    public final String[] getEnabledProtocols() {
        return this.engine.getEnabledProtocols();
    }

    public final void setEnabledProtocols(String[] protocols) {
        this.engine.setEnabledProtocols(protocols);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setHostname(String hostname) {
        this.engine.setHostname(hostname);
        super.setHostname(hostname);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setUseSessionTickets(boolean useSessionTickets) {
        this.engine.setUseSessionTickets(useSessionTickets);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setChannelIdEnabled(boolean enabled) {
        this.engine.setChannelIdEnabled(enabled);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final byte[] getChannelId() throws SSLException {
        return this.engine.getChannelId();
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setChannelIdPrivateKey(PrivateKey privateKey) {
        this.engine.setChannelIdPrivateKey(privateKey);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public byte[] getTlsUnique() {
        return this.engine.getTlsUnique();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        return this.engine.exportKeyingMaterial(label, context, length);
    }

    public final boolean getUseClientMode() {
        return this.engine.getUseClientMode();
    }

    public final void setUseClientMode(boolean mode) {
        this.engine.setUseClientMode(mode);
    }

    public final boolean getWantClientAuth() {
        return this.engine.getWantClientAuth();
    }

    public final boolean getNeedClientAuth() {
        return this.engine.getNeedClientAuth();
    }

    public final void setNeedClientAuth(boolean need) {
        this.engine.setNeedClientAuth(need);
    }

    public final void setWantClientAuth(boolean want) {
        this.engine.setWantClientAuth(want);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:15:?, code lost:
        r4.engine.closeInbound();
        r4.engine.closeOutbound();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x002a, code lost:
        if (r0 < 2) goto L_0x0034;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x002c, code lost:
        drainOutgoingQueue();
        r4.engine.closeOutbound();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:19:?, code lost:
        super.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x0041, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0044, code lost:
        if (r4.in != null) goto L_0x0046;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0046, code lost:
        r4.in.release();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x004b, code lost:
        throw r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x004c, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:?, code lost:
        super.close();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:32:0x0052, code lost:
        if (r4.in != null) goto L_0x0054;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:33:0x0054, code lost:
        r4.in.release();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:0x0059, code lost:
        throw r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:35:0x005a, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:37:0x005d, code lost:
        if (r4.in != null) goto L_0x005f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:38:0x005f, code lost:
        r4.in.release();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x0064, code lost:
        throw r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:43:?, code lost:
        return;
     */
    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, java.io.Closeable, org.conscrypt.AbstractConscryptSocket, java.lang.AutoCloseable
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void close() throws java.io.IOException {
        /*
        // Method dump skipped, instructions count: 101
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.ConscryptEngineSocket.close():void");
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public void setHandshakeTimeout(int handshakeTimeoutMilliseconds) throws SocketException {
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocols(String[] protocols) {
        this.engine.setApplicationProtocols(protocols);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final String[] getApplicationProtocols() {
        return this.engine.getApplicationProtocols();
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final String getApplicationProtocol() {
        return this.engine.getApplicationProtocol();
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final String getHandshakeApplicationProtocol() {
        return this.engine.getHandshakeApplicationProtocol();
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        setApplicationProtocolSelector(selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter selector) {
        this.engine.setApplicationProtocolSelector(selector);
    }

    /* access modifiers changed from: package-private */
    public void setBufferAllocator(BufferAllocator bufferAllocator2) {
        this.engine.setBufferAllocator(bufferAllocator2);
        this.bufferAllocator = bufferAllocator2;
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private void onHandshakeFinished() {
        boolean notify = false;
        synchronized (this.stateLock) {
            if (this.state != 8) {
                if (this.state == 2) {
                    this.state = 4;
                } else if (this.state == 3) {
                    this.state = 5;
                }
                this.stateLock.notifyAll();
                notify = true;
            }
        }
        if (notify) {
            notifyHandshakeCompletedListeners();
        }
    }

    private void waitForHandshake() throws IOException {
        startHandshake();
        synchronized (this.stateLock) {
            while (this.state != 5 && this.state != 4 && this.state != 8) {
                try {
                    this.stateLock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted waiting for handshake", e);
                }
            }
            if (this.state == 8) {
                throw new SocketException("Socket is closed");
            }
        }
    }

    private void drainOutgoingQueue() {
        while (this.engine.pendingOutboundEncryptedBytes() > 0) {
            try {
                this.out.writeInternal(EMPTY_BUFFER);
                this.out.flushInternal();
            } catch (IOException e) {
                return;
            }
        }
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private OutputStream getUnderlyingOutputStream() throws IOException {
        return super.getOutputStream();
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private InputStream getUnderlyingInputStream() throws IOException {
        return super.getInputStream();
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public final String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        return keyManager.chooseServerAlias(keyType, null, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public final String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes) {
        return keyManager.chooseClientAlias(keyTypes, issuers, this);
    }

    /* access modifiers changed from: private */
    public final class SSLOutputStream extends OutputStream {
        private OutputStream socketOutputStream;
        private final ByteBuffer target;
        private final int targetArrayOffset;
        private final Object writeLock = new Object();

        SSLOutputStream() {
            this.target = ByteBuffer.allocate(ConscryptEngineSocket.this.engine.getSession().getPacketBufferSize());
            this.targetArrayOffset = this.target.arrayOffset();
        }

        @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            ConscryptEngineSocket.this.close();
        }

        @Override // java.io.OutputStream
        public void write(int b) throws IOException {
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.writeLock) {
                write(new byte[]{(byte) b});
            }
        }

        @Override // java.io.OutputStream
        public void write(byte[] b) throws IOException {
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.writeLock) {
                writeInternal(ByteBuffer.wrap(b));
            }
        }

        @Override // java.io.OutputStream
        public void write(byte[] b, int off, int len) throws IOException {
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.writeLock) {
                writeInternal(ByteBuffer.wrap(b, off, len));
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void writeInternal(ByteBuffer buffer) throws IOException {
            Platform.blockGuardOnNetwork();
            ConscryptEngineSocket.this.checkOpen();
            init();
            int len = buffer.remaining();
            do {
                this.target.clear();
                SSLEngineResult engineResult = ConscryptEngineSocket.this.engine.wrap(buffer, this.target);
                if (engineResult.getStatus() != SSLEngineResult.Status.OK && engineResult.getStatus() != SSLEngineResult.Status.CLOSED) {
                    throw new SSLException("Unexpected engine result " + engineResult.getStatus());
                } else if (this.target.position() != engineResult.bytesProduced()) {
                    throw new SSLException("Engine bytesProduced " + engineResult.bytesProduced() + " does not match bytes written " + this.target.position());
                } else {
                    len -= engineResult.bytesConsumed();
                    if (len != buffer.remaining()) {
                        throw new SSLException("Engine did not read the correct number of bytes");
                    } else if (engineResult.getStatus() != SSLEngineResult.Status.CLOSED || engineResult.bytesProduced() != 0) {
                        this.target.flip();
                        writeToSocket();
                    } else if (len > 0) {
                        throw new SocketException("Socket closed");
                    } else {
                        return;
                    }
                }
            } while (len > 0);
        }

        @Override // java.io.OutputStream, java.io.Flushable
        public void flush() throws IOException {
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.writeLock) {
                flushInternal();
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void flushInternal() throws IOException {
            ConscryptEngineSocket.this.checkOpen();
            init();
            this.socketOutputStream.flush();
        }

        private void init() throws IOException {
            if (this.socketOutputStream == null) {
                this.socketOutputStream = ConscryptEngineSocket.this.getUnderlyingOutputStream();
            }
        }

        private void writeToSocket() throws IOException {
            this.socketOutputStream.write(this.target.array(), this.targetArrayOffset, this.target.limit());
        }
    }

    /* access modifiers changed from: private */
    public final class SSLInputStream extends InputStream {
        private final AllocatedBuffer allocatedBuffer;
        private final ByteBuffer fromEngine;
        private final ByteBuffer fromSocket;
        private final int fromSocketArrayOffset;
        private final Object readLock = new Object();
        private final byte[] singleByte = new byte[1];
        private InputStream socketInputStream;

        SSLInputStream() {
            if (ConscryptEngineSocket.this.bufferAllocator != null) {
                this.allocatedBuffer = ConscryptEngineSocket.this.bufferAllocator.allocateDirectBuffer(ConscryptEngineSocket.this.engine.getSession().getApplicationBufferSize());
                this.fromEngine = this.allocatedBuffer.nioBuffer();
            } else {
                this.allocatedBuffer = null;
                this.fromEngine = ByteBuffer.allocateDirect(ConscryptEngineSocket.this.engine.getSession().getApplicationBufferSize());
            }
            this.fromEngine.flip();
            this.fromSocket = ByteBuffer.allocate(ConscryptEngineSocket.this.engine.getSession().getPacketBufferSize());
            this.fromSocketArrayOffset = this.fromSocket.arrayOffset();
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable, java.io.InputStream
        public void close() throws IOException {
            ConscryptEngineSocket.this.close();
        }

        /* access modifiers changed from: package-private */
        public void release() {
            synchronized (this.readLock) {
                if (this.allocatedBuffer != null) {
                    this.allocatedBuffer.release();
                }
            }
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            int i = -1;
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.readLock) {
                int count = read(this.singleByte, 0, 1);
                if (count != -1) {
                    if (count != 1) {
                        throw new SSLException("read incorrect number of bytes " + count);
                    }
                    i = this.singleByte[0] & 255;
                }
            }
            return i;
        }

        @Override // java.io.InputStream
        public int read(byte[] b) throws IOException {
            int read;
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.readLock) {
                read = read(b, 0, b.length);
            }
            return read;
        }

        @Override // java.io.InputStream
        public int read(byte[] b, int off, int len) throws IOException {
            int readUntilDataAvailable;
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.readLock) {
                readUntilDataAvailable = readUntilDataAvailable(b, off, len);
            }
            return readUntilDataAvailable;
        }

        @Override // java.io.InputStream
        public int available() throws IOException {
            int remaining;
            ConscryptEngineSocket.this.startHandshake();
            synchronized (this.readLock) {
                init();
                remaining = this.fromEngine.remaining();
            }
            return remaining;
        }

        private boolean isHandshaking(SSLEngineResult.HandshakeStatus status) {
            switch (AnonymousClass3.$SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[status.ordinal()]) {
                case 1:
                case 2:
                case 3:
                    return true;
                default:
                    return false;
            }
        }

        private int readUntilDataAvailable(byte[] b, int off, int len) throws IOException {
            int count;
            do {
                count = processDataFromSocket(b, off, len);
            } while (count == 0);
            return count;
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private int processDataFromSocket(byte[] b, int off, int len) throws IOException {
            Platform.blockGuardOnNetwork();
            ConscryptEngineSocket.this.checkOpen();
            init();
            while (this.fromEngine.remaining() <= 0) {
                boolean needMoreDataFromSocket = true;
                this.fromSocket.flip();
                this.fromEngine.clear();
                boolean engineHandshaking = isHandshaking(ConscryptEngineSocket.this.engine.getHandshakeStatus());
                SSLEngineResult engineResult = ConscryptEngineSocket.this.engine.unwrap(this.fromSocket, this.fromEngine);
                this.fromSocket.compact();
                this.fromEngine.flip();
                switch (AnonymousClass3.$SwitchMap$javax$net$ssl$SSLEngineResult$Status[engineResult.getStatus().ordinal()]) {
                    case 1:
                        if (engineResult.bytesProduced() != 0) {
                            needMoreDataFromSocket = false;
                            break;
                        }
                        break;
                    case 2:
                        if (engineHandshaking || !isHandshaking(engineResult.getHandshakeStatus()) || !isHandshakeFinished()) {
                            needMoreDataFromSocket = false;
                            break;
                        } else {
                            renegotiate();
                            return 0;
                        }
                    case 3:
                        return -1;
                    default:
                        throw new SSLException("Unexpected engine result " + engineResult.getStatus());
                }
                if (!needMoreDataFromSocket && engineResult.bytesProduced() == 0) {
                    return 0;
                }
                if (needMoreDataFromSocket && readFromSocket() == -1) {
                    return -1;
                }
            }
            int readFromEngine = Math.min(this.fromEngine.remaining(), len);
            this.fromEngine.get(b, off, readFromEngine);
            return readFromEngine;
        }

        private boolean isHandshakeFinished() {
            boolean z;
            synchronized (ConscryptEngineSocket.this.stateLock) {
                z = ConscryptEngineSocket.this.state >= 4;
            }
            return z;
        }

        private void renegotiate() throws IOException {
            synchronized (ConscryptEngineSocket.this.handshakeLock) {
                ConscryptEngineSocket.this.doHandshake();
            }
        }

        private void init() throws IOException {
            if (this.socketInputStream == null) {
                this.socketInputStream = ConscryptEngineSocket.this.getUnderlyingInputStream();
            }
        }

        private int readFromSocket() throws IOException {
            try {
                int pos = this.fromSocket.position();
                int read = this.socketInputStream.read(this.fromSocket.array(), this.fromSocketArrayOffset + pos, this.fromSocket.limit() - pos);
                if (read <= 0) {
                    return read;
                }
                this.fromSocket.position(pos + read);
                return read;
            } catch (EOFException e) {
                return -1;
            }
        }
    }

    /* access modifiers changed from: package-private */
    /* renamed from: org.conscrypt.ConscryptEngineSocket$3  reason: invalid class name */
    public static /* synthetic */ class AnonymousClass3 {
        static final /* synthetic */ int[] $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus = new int[SSLEngineResult.HandshakeStatus.values().length];
        static final /* synthetic */ int[] $SwitchMap$javax$net$ssl$SSLEngineResult$Status = new int[SSLEngineResult.Status.values().length];

        static {
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$Status[SSLEngineResult.Status.BUFFER_UNDERFLOW.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$Status[SSLEngineResult.Status.OK.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$Status[SSLEngineResult.Status.CLOSED.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.NEED_UNWRAP.ordinal()] = 1;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.NEED_WRAP.ordinal()] = 2;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.NEED_TASK.ordinal()] = 3;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING.ordinal()] = 4;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$javax$net$ssl$SSLEngineResult$HandshakeStatus[SSLEngineResult.HandshakeStatus.FINISHED.ordinal()] = 5;
            } catch (NoSuchFieldError e8) {
            }
        }
    }
}
