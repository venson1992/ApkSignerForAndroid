package org.conscrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.ExternalSession;
import org.conscrypt.NativeCrypto;
import org.conscrypt.NativeRef;
import org.conscrypt.SSLParametersImpl;

/* access modifiers changed from: package-private */
public class ConscryptFileDescriptorSocket extends OpenSSLSocketImpl implements NativeCrypto.SSLHandshakeCallbacks, SSLParametersImpl.PSKCallbacks, SSLParametersImpl.AliasChooser {
    private static final boolean DBG_STATE = false;
    private final ActiveSession activeSession;
    private OpenSSLKey channelIdPrivateKey;
    private SessionSnapshot closedSession;
    private final SSLSession externalSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
        /* class org.conscrypt.ConscryptFileDescriptorSocket.AnonymousClass1 */

        @Override // org.conscrypt.ExternalSession.Provider
        public ConscryptSession provideSession() {
            return ConscryptFileDescriptorSocket.this.provideSession();
        }
    }));
    private final Object guard = Platform.closeGuardGet();
    private int handshakeTimeoutMilliseconds = -1;
    private SSLInputStream is;
    private SSLOutputStream os;
    private final NativeSsl ssl;
    private final SSLParametersImpl sslParameters;
    private int state = 0;
    private int writeTimeoutMilliseconds = 0;

    ConscryptFileDescriptorSocket(SSLParametersImpl sslParameters2) throws IOException {
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    ConscryptFileDescriptorSocket(String hostname, int port, SSLParametersImpl sslParameters2) throws IOException {
        super(hostname, port);
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    ConscryptFileDescriptorSocket(InetAddress address, int port, SSLParametersImpl sslParameters2) throws IOException {
        super(address, port);
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    ConscryptFileDescriptorSocket(String hostname, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters2) throws IOException {
        super(hostname, port, clientAddress, clientPort);
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    ConscryptFileDescriptorSocket(InetAddress address, int port, InetAddress clientAddress, int clientPort, SSLParametersImpl sslParameters2) throws IOException {
        super(address, port, clientAddress, clientPort);
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    ConscryptFileDescriptorSocket(Socket socket, String hostname, int port, boolean autoClose, SSLParametersImpl sslParameters2) throws IOException {
        super(socket, hostname, port, autoClose);
        this.sslParameters = sslParameters2;
        this.ssl = newSsl(sslParameters2, this);
        this.activeSession = new ActiveSession(this.ssl, sslParameters2.getSessionContext());
    }

    private static NativeSsl newSsl(SSLParametersImpl sslParameters2, ConscryptFileDescriptorSocket engine) throws SSLException {
        return NativeSsl.newInstance(sslParameters2, engine, engine, engine);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:101:0x0120, code lost:
        if (r1.getMessage().contains("unexpected CCS") != false) goto L_0x0122;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:102:0x0122, code lost:
        org.conscrypt.Platform.logEvent(java.lang.String.format("ssl_unexpected_ccs: host=%s", getHostnameOrIP()));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:103:0x0135, code lost:
        throw r1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0026, code lost:
        if (getUseClientMode() == false) goto L_0x0041;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:110:0x013c, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:112:0x013f, code lost:
        if (r12.handshakeTimeoutMilliseconds < 0) goto L_0x0147;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:113:0x0141, code lost:
        setSoTimeout(r5);
        setSoWriteTimeout(r6);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:114:0x0147, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:115:0x0149, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:118:0x014e, code lost:
        if (r12.state != 8) goto L_0x017d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:119:0x0150, code lost:
        r4 = true;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0028, code lost:
        r0 = clientSessionContext().getCachedSession(getHostnameOrIP(), getPort(), r12.sslParameters);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:121:0x0154, code lost:
        if (r12.state != 2) goto L_0x017f;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:122:0x0156, code lost:
        transitionTo(4);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:123:0x015a, code lost:
        if (r4 != false) goto L_0x0161;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:124:0x015c, code lost:
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:125:0x0161, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:126:0x0162, code lost:
        if (r4 == false) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:127:0x0164, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:128:0x0166, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x003a, code lost:
        if (r0 == null) goto L_0x0041;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:131:?, code lost:
        transitionTo(8);
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:132:0x0171, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:134:?, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:139:0x017d, code lost:
        r4 = false;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:13:0x003c, code lost:
        r0.offerToResume(r12.ssl);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:140:0x017f, code lost:
        transitionTo(5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:14:0x0041, code lost:
        r5 = getSoTimeout();
        r6 = getSoWriteTimeout();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:152:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:153:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:154:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:155:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:156:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:158:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:159:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:15:0x004b, code lost:
        if (r12.handshakeTimeoutMilliseconds < 0) goto L_0x0057;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:160:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:161:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:162:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:163:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:164:?, code lost:
        return;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:16:0x004d, code lost:
        setSoTimeout(r12.handshakeTimeoutMilliseconds);
        setSoWriteTimeout(r12.handshakeTimeoutMilliseconds);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:17:0x0057, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:18:0x0059, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:21:0x005e, code lost:
        if (r12.state != 8) goto L_0x007d;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:22:0x0060, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:23:0x0061, code lost:
        if (1 == 0) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:24:0x0063, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0065, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:?, code lost:
        transitionTo(8);
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x0070, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:?, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:39:0x007d, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:41:?, code lost:
        r12.ssl.doHandshake(org.conscrypt.Platform.getFileDescriptor(r12.socket), getSoTimeout());
        r12.activeSession.onPeerCertificateAvailable(getHostnameOrIP(), getPort());
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:0x009a, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:43:0x009c, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:0x00a1, code lost:
        if (r12.state != 8) goto L_0x013c;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:47:0x00a3, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:48:0x00a4, code lost:
        if (1 == 0) goto L_?;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:49:0x00a6, code lost:
        r9 = r12.ssl;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:50:0x00a8, code lost:
        monitor-enter(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:53:?, code lost:
        transitionTo(8);
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:54:0x00b3, code lost:
        monitor-exit(r9);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:56:?, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:61:0x00bd, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:64:0x00cb, code lost:
        throw ((javax.net.ssl.SSLHandshakeException) new javax.net.ssl.SSLHandshakeException("Handshake failed").initCause(r1));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:65:0x00cc, code lost:
        r8 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:66:0x00cd, code lost:
        if (1 != 0) goto L_0x00cf;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:68:0x00d1, code lost:
        monitor-enter(r12.ssl);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:71:?, code lost:
        transitionTo(8);
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:74:?, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:75:0x00e0, code lost:
        throw r8;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:76:0x00e1, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x00e2, code lost:
        r7 = new javax.net.ssl.SSLHandshakeException(r1.getMessage());
        r7.initCause(r1);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x00ee, code lost:
        throw r7;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:79:0x00ef, code lost:
        r1 = move-exception;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:81:0x00f2, code lost:
        monitor-enter(r12.ssl);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:84:0x00f7, code lost:
        if (r12.state == 8) goto L_0x00f9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:86:0x00fa, code lost:
        if (1 != 0) goto L_0x00fc;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:88:0x00fe, code lost:
        monitor-enter(r12.ssl);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:91:?, code lost:
        transitionTo(8);
        r12.ssl.notifyAll();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:94:?, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:?, code lost:
        org.conscrypt.Platform.closeGuardOpen(r12.guard, "close");
        r12.ssl.initialize(getHostname(), r12.channelIdPrivateKey);
     */
    @Override // javax.net.ssl.SSLSocket
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void startHandshake() throws java.io.IOException {
        /*
        // Method dump skipped, instructions count: 403
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.ConscryptFileDescriptorSocket.startHandshake():void");
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final void clientCertificateRequested(byte[] keyTypeBytes, int[] signatureAlgs, byte[][] asn1DerEncodedPrincipals) throws CertificateEncodingException, SSLException {
        this.ssl.chooseClientCertificate(keyTypeBytes, signatureAlgs, asn1DerEncodedPrincipals);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
        return this.ssl.clientPSKKeyRequested(identityHint, identity, key);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        return this.ssl.serverPSKKeyRequested(identityHint, identity, key);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final void onSSLStateChange(int type, int val) {
        if (type == 32) {
            synchronized (this.ssl) {
                if (this.state != 8) {
                    transitionTo(5);
                    notifyHandshakeCompletedListeners();
                    synchronized (this.ssl) {
                        this.ssl.notifyAll();
                    }
                }
            }
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final void onNewSessionEstablished(long sslSessionNativePtr) {
        try {
            NativeCrypto.SSL_SESSION_up_ref(sslSessionNativePtr);
            sessionContext().cacheSession(NativeSslSession.newInstance(new NativeRef.SSL_SESSION(sslSessionNativePtr), this.activeSession));
        } catch (Exception e) {
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final long serverSessionRequested(byte[] id) {
        return 0;
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final void serverCertificateRequested() throws IOException {
        synchronized (this.ssl) {
            this.ssl.configureServerCertificate();
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public final void verifyCertificateChain(byte[][] certChain, String authMethod) throws CertificateException {
        if (certChain != null) {
            try {
                if (certChain.length != 0) {
                    X509Certificate[] peerCertChain = SSLUtils.decodeX509CertificateChain(certChain);
                    X509TrustManager x509tm = this.sslParameters.getX509TrustManager();
                    if (x509tm == null) {
                        throw new CertificateException("No X.509 TrustManager");
                    }
                    this.activeSession.onPeerCertificatesReceived(getHostnameOrIP(), getPort(), peerCertChain);
                    if (getUseClientMode()) {
                        Platform.checkServerTrusted(x509tm, peerCertChain, authMethod, this);
                        return;
                    } else {
                        Platform.checkClientTrusted(x509tm, peerCertChain, peerCertChain[0].getPublicKey().getAlgorithm(), this);
                        return;
                    }
                }
            } catch (CertificateException e) {
                throw e;
            } catch (Exception e2) {
                throw new CertificateException(e2);
            }
        }
        throw new CertificateException("Peer sent no certificate");
    }

    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final InputStream getInputStream() throws IOException {
        InputStream returnVal;
        checkOpen();
        synchronized (this.ssl) {
            if (this.state == 8) {
                throw new SocketException("Socket is closed.");
            }
            if (this.is == null) {
                this.is = new SSLInputStream();
            }
            returnVal = this.is;
        }
        waitForHandshake();
        return returnVal;
    }

    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final OutputStream getOutputStream() throws IOException {
        OutputStream returnVal;
        checkOpen();
        synchronized (this.ssl) {
            if (this.state == 8) {
                throw new SocketException("Socket is closed.");
            }
            if (this.os == null) {
                this.os = new SSLOutputStream();
            }
            returnVal = this.os;
        }
        waitForHandshake();
        return returnVal;
    }

    private void assertReadableOrWriteableState() {
        if (this.state != 5 && this.state != 4) {
            throw new AssertionError("Invalid state: " + this.state);
        }
    }

    private void waitForHandshake() throws IOException {
        startHandshake();
        synchronized (this.ssl) {
            while (this.state != 5 && this.state != 4 && this.state != 8) {
                try {
                    this.ssl.wait();
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

    private class SSLInputStream extends InputStream {
        private final Object readLock = new Object();

        SSLInputStream() {
        }

        @Override // java.io.InputStream
        public int read() throws IOException {
            byte[] buffer = new byte[1];
            if (read(buffer, 0, 1) != -1) {
                return buffer[0] & 255;
            }
            return -1;
        }

        @Override // java.io.InputStream
        public int read(byte[] buf, int offset, int byteCount) throws IOException {
            int ret;
            Platform.blockGuardOnNetwork();
            ConscryptFileDescriptorSocket.this.checkOpen();
            ArrayUtils.checkOffsetAndCount(buf.length, offset, byteCount);
            if (byteCount == 0) {
                return 0;
            }
            synchronized (this.readLock) {
                synchronized (ConscryptFileDescriptorSocket.this.ssl) {
                    if (ConscryptFileDescriptorSocket.this.state == 8) {
                        throw new SocketException("socket is closed");
                    }
                }
                ret = ConscryptFileDescriptorSocket.this.ssl.read(Platform.getFileDescriptor(ConscryptFileDescriptorSocket.this.socket), buf, offset, byteCount, ConscryptFileDescriptorSocket.this.getSoTimeout());
                if (ret == -1) {
                    synchronized (ConscryptFileDescriptorSocket.this.ssl) {
                        if (ConscryptFileDescriptorSocket.this.state == 8) {
                            throw new SocketException("socket is closed");
                        }
                    }
                }
            }
            return ret;
        }

        @Override // java.io.InputStream
        public int available() {
            return ConscryptFileDescriptorSocket.this.ssl.getPendingReadableBytes();
        }

        /* access modifiers changed from: package-private */
        public void awaitPendingOps() {
            synchronized (this.readLock) {
            }
        }
    }

    private class SSLOutputStream extends OutputStream {
        private final Object writeLock = new Object();

        SSLOutputStream() {
        }

        @Override // java.io.OutputStream
        public void write(int oneByte) throws IOException {
            write(new byte[]{(byte) (oneByte & 255)});
        }

        @Override // java.io.OutputStream
        public void write(byte[] buf, int offset, int byteCount) throws IOException {
            Platform.blockGuardOnNetwork();
            ConscryptFileDescriptorSocket.this.checkOpen();
            ArrayUtils.checkOffsetAndCount(buf.length, offset, byteCount);
            if (byteCount != 0) {
                synchronized (this.writeLock) {
                    synchronized (ConscryptFileDescriptorSocket.this.ssl) {
                        if (ConscryptFileDescriptorSocket.this.state == 8) {
                            throw new SocketException("socket is closed");
                        }
                    }
                    ConscryptFileDescriptorSocket.this.ssl.write(Platform.getFileDescriptor(ConscryptFileDescriptorSocket.this.socket), buf, offset, byteCount, ConscryptFileDescriptorSocket.this.writeTimeoutMilliseconds);
                    synchronized (ConscryptFileDescriptorSocket.this.ssl) {
                        if (ConscryptFileDescriptorSocket.this.state == 8) {
                            throw new SocketException("socket is closed");
                        }
                    }
                }
            }
        }

        /* access modifiers changed from: package-private */
        public void awaitPendingOps() {
            synchronized (this.writeLock) {
            }
        }
    }

    public final SSLSession getSession() {
        return this.externalSession;
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private ConscryptSession provideSession() {
        ConscryptSession nullSession;
        boolean handshakeCompleted = false;
        synchronized (this.ssl) {
            if (this.state == 8) {
                if (this.closedSession != null) {
                    nullSession = this.closedSession;
                } else {
                    nullSession = SSLNullSession.getNullSession();
                }
                return nullSession;
            }
            try {
                handshakeCompleted = this.state >= 5;
                if (!handshakeCompleted && isConnected()) {
                    waitForHandshake();
                    handshakeCompleted = true;
                }
            } catch (IOException e) {
            }
        }
        if (!handshakeCompleted) {
            return SSLNullSession.getNullSession();
        }
        return this.activeSession;
    }

    private ConscryptSession provideAfterHandshakeSession() {
        if (this.state < 2) {
            return SSLNullSession.getNullSession();
        }
        return provideSession();
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private ConscryptSession provideHandshakeSession() {
        ConscryptSession nullSession;
        synchronized (this.ssl) {
            if (this.state < 2 || this.state >= 5) {
                nullSession = SSLNullSession.getNullSession();
            } else {
                nullSession = this.activeSession;
            }
        }
        return nullSession;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final SSLSession getActiveSession() {
        return this.activeSession;
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final SSLSession getHandshakeSession() {
        SSLSession sSLSession;
        synchronized (this.ssl) {
            if (this.state < 2 || this.state >= 5) {
                sSLSession = null;
            } else {
                sSLSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
                    /* class org.conscrypt.ConscryptFileDescriptorSocket.AnonymousClass2 */

                    @Override // org.conscrypt.ExternalSession.Provider
                    public ConscryptSession provideSession() {
                        return ConscryptFileDescriptorSocket.this.provideHandshakeSession();
                    }
                }));
            }
        }
        return sSLSession;
    }

    public final boolean getEnableSessionCreation() {
        return this.sslParameters.getEnableSessionCreation();
    }

    public final void setEnableSessionCreation(boolean flag) {
        this.sslParameters.setEnableSessionCreation(flag);
    }

    public final String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    public final String[] getEnabledCipherSuites() {
        return this.sslParameters.getEnabledCipherSuites();
    }

    public final void setEnabledCipherSuites(String[] suites) {
        this.sslParameters.setEnabledCipherSuites(suites);
    }

    public final String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    public final String[] getEnabledProtocols() {
        return this.sslParameters.getEnabledProtocols();
    }

    public final void setEnabledProtocols(String[] protocols) {
        this.sslParameters.setEnabledProtocols(protocols);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setUseSessionTickets(boolean useSessionTickets) {
        this.sslParameters.setUseSessionTickets(useSessionTickets);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setHostname(String hostname) {
        this.sslParameters.setUseSni(hostname != null);
        super.setHostname(hostname);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setChannelIdEnabled(boolean enabled) {
        if (getUseClientMode()) {
            throw new IllegalStateException("Client mode");
        }
        synchronized (this.ssl) {
            if (this.state != 0) {
                throw new IllegalStateException("Could not enable/disable Channel ID after the initial handshake has begun.");
            }
        }
        this.sslParameters.channelIdEnabled = enabled;
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final byte[] getChannelId() throws SSLException {
        if (getUseClientMode()) {
            throw new IllegalStateException("Client mode");
        }
        synchronized (this.ssl) {
            if (this.state != 5) {
                throw new IllegalStateException("Channel ID is only available after handshake completes");
            }
        }
        return this.ssl.getTlsChannelId();
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setChannelIdPrivateKey(PrivateKey privateKey) {
        if (!getUseClientMode()) {
            throw new IllegalStateException("Server mode");
        }
        synchronized (this.ssl) {
            if (this.state != 0) {
                throw new IllegalStateException("Could not change Channel ID private key after the initial handshake has begun.");
            }
        }
        if (privateKey == null) {
            this.sslParameters.channelIdEnabled = false;
            this.channelIdPrivateKey = null;
            return;
        }
        this.sslParameters.channelIdEnabled = true;
        ECParameterSpec ecParams = null;
        try {
            if (privateKey instanceof ECKey) {
                ecParams = ((ECKey) privateKey).getParams();
            }
            if (ecParams == null) {
                ecParams = OpenSSLECGroupContext.getCurveByName("prime256v1").getECParameterSpec();
            }
            this.channelIdPrivateKey = OpenSSLKey.fromECPrivateKeyForTLSStackOnly(privateKey, ecParams);
        } catch (InvalidKeyException e) {
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public byte[] getTlsUnique() {
        return this.ssl.getTlsUnique();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        synchronized (this.ssl) {
            if (this.state < 3 || this.state == 8) {
                return null;
            }
            return this.ssl.exportKeyingMaterial(label, context, length);
        }
    }

    public final boolean getUseClientMode() {
        return this.sslParameters.getUseClientMode();
    }

    public final void setUseClientMode(boolean mode) {
        synchronized (this.ssl) {
            if (this.state != 0) {
                throw new IllegalArgumentException("Could not change the mode after the initial handshake has begun.");
            }
        }
        this.sslParameters.setUseClientMode(mode);
    }

    public final boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    public final boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    public final void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    public final void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setSoWriteTimeout(int writeTimeoutMilliseconds2) throws SocketException {
        this.writeTimeoutMilliseconds = writeTimeoutMilliseconds2;
        Platform.setSocketWriteTimeout(this, (long) writeTimeoutMilliseconds2);
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final int getSoWriteTimeout() throws SocketException {
        return this.writeTimeoutMilliseconds;
    }

    @Override // org.conscrypt.OpenSSLSocketImpl, org.conscrypt.AbstractConscryptSocket
    public final void setHandshakeTimeout(int handshakeTimeoutMilliseconds2) throws SocketException {
        this.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds2;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:24:0x0045, code lost:
        if (r1 != null) goto L_0x0049;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:25:0x0047, code lost:
        if (r2 == null) goto L_0x004e;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:26:0x0049, code lost:
        r6.ssl.interrupt();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:27:0x004e, code lost:
        if (r1 == null) goto L_0x0053;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:28:0x0050, code lost:
        r1.awaitPendingOps();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:29:0x0053, code lost:
        if (r2 == null) goto L_0x0058;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:30:0x0055, code lost:
        r2.awaitPendingOps();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:31:0x0058, code lost:
        shutdownAndFreeSslNative();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:34:?, code lost:
        return;
     */
    @Override // java.net.Socket, org.conscrypt.OpenSSLSocketImpl, java.io.Closeable, org.conscrypt.AbstractConscryptSocket, java.lang.AutoCloseable
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public final void close() throws java.io.IOException {
        /*
            r6 = this;
            r5 = 8
            org.conscrypt.NativeSsl r3 = r6.ssl
            if (r3 != 0) goto L_0x0007
        L_0x0006:
            return
        L_0x0007:
            org.conscrypt.NativeSsl r4 = r6.ssl
            monitor-enter(r4)
            int r3 = r6.state     // Catch:{ all -> 0x0010 }
            if (r3 != r5) goto L_0x0013
            monitor-exit(r4)     // Catch:{ all -> 0x0010 }
            goto L_0x0006
        L_0x0010:
            r3 = move-exception
            monitor-exit(r4)     // Catch:{ all -> 0x0010 }
            throw r3
        L_0x0013:
            int r0 = r6.state
            r3 = 8
            r6.transitionTo(r3)
            if (r0 != 0) goto L_0x0029
            r6.free()
            r6.closeUnderlyingSocket()
            org.conscrypt.NativeSsl r3 = r6.ssl
            r3.notifyAll()
            monitor-exit(r4)
            goto L_0x0006
        L_0x0029:
            r3 = 5
            if (r0 == r3) goto L_0x003b
            r3 = 4
            if (r0 == r3) goto L_0x003b
            org.conscrypt.NativeSsl r3 = r6.ssl
            r3.interrupt()
            org.conscrypt.NativeSsl r3 = r6.ssl
            r3.notifyAll()
            monitor-exit(r4)
            goto L_0x0006
        L_0x003b:
            org.conscrypt.NativeSsl r3 = r6.ssl
            r3.notifyAll()
            org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream r1 = r6.is
            org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream r2 = r6.os
            monitor-exit(r4)
            if (r1 != 0) goto L_0x0049
            if (r2 == 0) goto L_0x004e
        L_0x0049:
            org.conscrypt.NativeSsl r3 = r6.ssl
            r3.interrupt()
        L_0x004e:
            if (r1 == 0) goto L_0x0053
            r1.awaitPendingOps()
        L_0x0053:
            if (r2 == 0) goto L_0x0058
            r2.awaitPendingOps()
        L_0x0058:
            r6.shutdownAndFreeSslNative()
            goto L_0x0006
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.ConscryptFileDescriptorSocket.close():void");
    }

    private void shutdownAndFreeSslNative() throws IOException {
        try {
            Platform.blockGuardOnNetwork();
            this.ssl.shutdown(Platform.getFileDescriptor(this.socket));
        } catch (IOException e) {
        } finally {
            free();
            closeUnderlyingSocket();
        }
    }

    private void closeUnderlyingSocket() throws IOException {
        super.close();
    }

    private void free() {
        if (!this.ssl.isClosed()) {
            this.ssl.close();
            Platform.closeGuardClose(this.guard);
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.lang.Object
    public final void finalize() throws Throwable {
        try {
            if (this.guard != null) {
                Platform.closeGuardWarnIfOpen(this.guard);
            }
            if (this.ssl != null) {
                synchronized (this.ssl) {
                    transitionTo(8);
                }
            }
        } finally {
            super.finalize();
        }
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        setApplicationProtocolSelector(selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter selector) {
        this.sslParameters.setApplicationProtocolSelector(selector);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public int selectApplicationProtocol(byte[] protocols) {
        ApplicationProtocolSelectorAdapter adapter = this.sslParameters.getApplicationProtocolSelector();
        if (adapter == null) {
            return 3;
        }
        return adapter.selectApplicationProtocol(protocols);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final void setApplicationProtocols(String[] protocols) {
        this.sslParameters.setApplicationProtocols(protocols);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptSocket
    public final String[] getApplicationProtocols() {
        return this.sslParameters.getApplicationProtocols();
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final String getApplicationProtocol() {
        return provideAfterHandshakeSession().getApplicationProtocol();
    }

    @Override // org.conscrypt.AbstractConscryptSocket
    public final String getHandshakeApplicationProtocol() {
        String applicationProtocol;
        synchronized (this.ssl) {
            applicationProtocol = (this.state < 2 || this.state >= 5) ? null : getApplicationProtocol();
        }
        return applicationProtocol;
    }

    public final SSLParameters getSSLParameters() {
        SSLParameters params = super.getSSLParameters();
        Platform.getSSLParameters(params, this.sslParameters, this);
        return params;
    }

    public final void setSSLParameters(SSLParameters p) {
        super.setSSLParameters(p);
        Platform.setSSLParameters(p, this.sslParameters, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public final String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return keyManager.chooseServerKeyIdentityHint(this);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public final String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return keyManager.chooseClientKeyIdentity(identityHint, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public final SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return keyManager.getKey(identityHint, identity, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public final String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        return keyManager.chooseServerAlias(keyType, null, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public final String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes) {
        return keyManager.chooseClientAlias(keyTypes, issuers, this);
    }

    private ClientSessionContext clientSessionContext() {
        return this.sslParameters.getClientSessionContext();
    }

    private AbstractSessionContext sessionContext() {
        return this.sslParameters.getSessionContext();
    }

    private void transitionTo(int newState) {
        switch (newState) {
            case 8:
                if (!this.ssl.isClosed() && this.state >= 2 && this.state < 8) {
                    this.closedSession = new SessionSnapshot(this.activeSession);
                    break;
                }
        }
        this.state = newState;
    }
}
