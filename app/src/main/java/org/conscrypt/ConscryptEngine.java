package org.conscrypt;

import com.android.apksig.ApkVerificationIssue;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.ExternalSession;
import org.conscrypt.NativeCrypto;
import org.conscrypt.NativeRef;
import org.conscrypt.NativeSsl;
import org.conscrypt.SSLParametersImpl;

/* access modifiers changed from: package-private */
public final class ConscryptEngine extends AbstractConscryptEngine implements NativeCrypto.SSLHandshakeCallbacks, SSLParametersImpl.AliasChooser, SSLParametersImpl.PSKCallbacks {
    private static final SSLEngineResult CLOSED_NOT_HANDSHAKING = new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    private static final SSLEngineResult NEED_UNWRAP_CLOSED = new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
    private static final SSLEngineResult NEED_UNWRAP_OK = new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
    private static final SSLEngineResult NEED_WRAP_CLOSED = new SSLEngineResult(SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
    private static final SSLEngineResult NEED_WRAP_OK = new SSLEngineResult(SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, 0, 0);
    private static BufferAllocator defaultBufferAllocator = null;
    private ActiveSession activeSession;
    private BufferAllocator bufferAllocator;
    private OpenSSLKey channelIdPrivateKey;
    private SessionSnapshot closedSession;
    private final SSLSession externalSession;
    private boolean handshakeFinished;
    private HandshakeListener handshakeListener;
    private ByteBuffer lazyDirectBuffer;
    private int maxSealOverhead;
    private final NativeSsl.BioWrapper networkBio;
    private String peerHostname;
    private final PeerInfoProvider peerInfoProvider;
    private final ByteBuffer[] singleDstBuffer;
    private final ByteBuffer[] singleSrcBuffer;
    private final NativeSsl ssl;
    private final SSLParametersImpl sslParameters;
    private int state;

    ConscryptEngine(SSLParametersImpl sslParameters2) {
        this.bufferAllocator = defaultBufferAllocator;
        this.state = 0;
        this.externalSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
            /* class org.conscrypt.ConscryptEngine.AnonymousClass1 */

            @Override // org.conscrypt.ExternalSession.Provider
            public ConscryptSession provideSession() {
                return ConscryptEngine.this.provideSession();
            }
        }));
        this.singleSrcBuffer = new ByteBuffer[1];
        this.singleDstBuffer = new ByteBuffer[1];
        this.sslParameters = sslParameters2;
        this.peerInfoProvider = PeerInfoProvider.nullProvider();
        this.ssl = newSsl(sslParameters2, this, this);
        this.networkBio = this.ssl.newBio();
    }

    ConscryptEngine(String host, int port, SSLParametersImpl sslParameters2) {
        this.bufferAllocator = defaultBufferAllocator;
        this.state = 0;
        this.externalSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
            /* class org.conscrypt.ConscryptEngine.AnonymousClass1 */

            @Override // org.conscrypt.ExternalSession.Provider
            public ConscryptSession provideSession() {
                return ConscryptEngine.this.provideSession();
            }
        }));
        this.singleSrcBuffer = new ByteBuffer[1];
        this.singleDstBuffer = new ByteBuffer[1];
        this.sslParameters = sslParameters2;
        this.peerInfoProvider = PeerInfoProvider.forHostAndPort(host, port);
        this.ssl = newSsl(sslParameters2, this, this);
        this.networkBio = this.ssl.newBio();
    }

    ConscryptEngine(SSLParametersImpl sslParameters2, PeerInfoProvider peerInfoProvider2, SSLParametersImpl.AliasChooser aliasChooser) {
        this.bufferAllocator = defaultBufferAllocator;
        this.state = 0;
        this.externalSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
            /* class org.conscrypt.ConscryptEngine.AnonymousClass1 */

            @Override // org.conscrypt.ExternalSession.Provider
            public ConscryptSession provideSession() {
                return ConscryptEngine.this.provideSession();
            }
        }));
        this.singleSrcBuffer = new ByteBuffer[1];
        this.singleDstBuffer = new ByteBuffer[1];
        this.sslParameters = sslParameters2;
        this.peerInfoProvider = (PeerInfoProvider) Preconditions.checkNotNull(peerInfoProvider2, "peerInfoProvider");
        this.ssl = newSsl(sslParameters2, this, aliasChooser);
        this.networkBio = this.ssl.newBio();
    }

    private static NativeSsl newSsl(SSLParametersImpl sslParameters2, ConscryptEngine engine, SSLParametersImpl.AliasChooser aliasChooser) {
        try {
            return NativeSsl.newInstance(sslParameters2, engine, aliasChooser, engine);
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    static void setDefaultBufferAllocator(BufferAllocator bufferAllocator2) {
        defaultBufferAllocator = bufferAllocator2;
    }

    static BufferAllocator getDefaultBufferAllocator() {
        return defaultBufferAllocator;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setBufferAllocator(BufferAllocator bufferAllocator2) {
        synchronized (this.ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException("Could not set buffer allocator after the initial handshake has begun.");
            }
            this.bufferAllocator = bufferAllocator2;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public int maxSealOverhead() {
        return this.maxSealOverhead;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setChannelIdEnabled(boolean enabled) {
        synchronized (this.ssl) {
            if (getUseClientMode()) {
                throw new IllegalStateException("Not allowed in client mode");
            } else if (isHandshakeStarted()) {
                throw new IllegalStateException("Could not enable/disable Channel ID after the initial handshake has begun.");
            } else {
                this.sslParameters.channelIdEnabled = enabled;
            }
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public byte[] getChannelId() throws SSLException {
        byte[] tlsChannelId;
        synchronized (this.ssl) {
            if (getUseClientMode()) {
                throw new IllegalStateException("Not allowed in client mode");
            } else if (isHandshakeStarted()) {
                throw new IllegalStateException("Channel ID is only available after handshake completes");
            } else {
                tlsChannelId = this.ssl.getTlsChannelId();
            }
        }
        return tlsChannelId;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setChannelIdPrivateKey(PrivateKey privateKey) {
        if (!getUseClientMode()) {
            throw new IllegalStateException("Not allowed in server mode");
        }
        synchronized (this.ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException("Could not change Channel ID private key after the initial handshake has begun.");
            } else if (privateKey == null) {
                this.sslParameters.channelIdEnabled = false;
                this.channelIdPrivateKey = null;
            } else {
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
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setHandshakeListener(HandshakeListener handshakeListener2) {
        synchronized (this.ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalStateException("Handshake listener must be set before starting the handshake.");
            }
            this.handshakeListener = handshakeListener2;
        }
    }

    private boolean isHandshakeStarted() {
        switch (this.state) {
            case BerEncoding.TAG_CLASS_UNIVERSAL:
            case 1:
                return false;
            default:
                return true;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setHostname(String hostname) {
        this.sslParameters.setUseSni(hostname != null);
        this.peerHostname = hostname;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public String getHostname() {
        return this.peerHostname != null ? this.peerHostname : this.peerInfoProvider.getHostname();
    }

    @Override // org.conscrypt.AbstractConscryptEngine
    public String getPeerHost() {
        return this.peerHostname != null ? this.peerHostname : this.peerInfoProvider.getHostnameOrIP();
    }

    @Override // org.conscrypt.AbstractConscryptEngine
    public int getPeerPort() {
        return this.peerInfoProvider.getPort();
    }

    @Override // javax.net.ssl.SSLEngine
    public void beginHandshake() throws SSLException {
        synchronized (this.ssl) {
            beginHandshakeInternal();
        }
    }

    private void beginHandshakeInternal() throws SSLException {
        NativeSslSession cachedSession;
        switch (this.state) {
            case BerEncoding.TAG_CLASS_UNIVERSAL:
                throw new IllegalStateException("Client/server mode must be set before handshake");
            case 1:
                transitionTo(2);
                try {
                    this.ssl.initialize(getHostname(), this.channelIdPrivateKey);
                    if (getUseClientMode() && (cachedSession = clientSessionContext().getCachedSession(getHostname(), getPeerPort(), this.sslParameters)) != null) {
                        cachedSession.offerToResume(this.ssl);
                    }
                    this.maxSealOverhead = this.ssl.getMaxSealOverhead();
                    handshake();
                    if (0 != 0) {
                        closeAndFreeResources();
                        return;
                    }
                    return;
                } catch (IOException e) {
                    if (e.getMessage().contains("unexpected CCS")) {
                        Platform.logEvent(String.format("ssl_unexpected_ccs: host=%s", getPeerHost()));
                    }
                    closeAll();
                    throw SSLUtils.toSSLHandshakeException(e);
                } catch (Throwable th) {
                    if (1 != 0) {
                        closeAndFreeResources();
                    }
                    throw th;
                }
            case 2:
            case 3:
            case 4:
            case 5:
            default:
                return;
            case 6:
            case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
            case 8:
                throw new SSLHandshakeException("Engine has already been closed");
        }
    }

    @Override // javax.net.ssl.SSLEngine
    public void closeInbound() {
        synchronized (this.ssl) {
            if (this.state != 8 && this.state != 6) {
                if (isHandshakeStarted()) {
                    if (this.state == 7) {
                        transitionTo(8);
                    } else {
                        transitionTo(6);
                    }
                    freeIfDone();
                } else {
                    closeAndFreeResources();
                }
            }
        }
    }

    public void closeOutbound() {
        synchronized (this.ssl) {
            if (this.state != 8 && this.state != 7) {
                if (isHandshakeStarted()) {
                    if (this.state == 6) {
                        transitionTo(8);
                    } else {
                        transitionTo(7);
                    }
                    sendSSLShutdown();
                    freeIfDone();
                } else {
                    closeAndFreeResources();
                }
            }
        }
    }

    public Runnable getDelegatedTask() {
        return null;
    }

    public String[] getEnabledCipherSuites() {
        return this.sslParameters.getEnabledCipherSuites();
    }

    public String[] getEnabledProtocols() {
        return this.sslParameters.getEnabledProtocols();
    }

    public boolean getEnableSessionCreation() {
        return this.sslParameters.getEnableSessionCreation();
    }

    public SSLParameters getSSLParameters() {
        SSLParameters params = super.getSSLParameters();
        Platform.getSSLParameters(params, this.sslParameters, this);
        return params;
    }

    public void setSSLParameters(SSLParameters p) {
        super.setSSLParameters(p);
        Platform.setSSLParameters(p, this.sslParameters, this);
    }

    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        SSLEngineResult.HandshakeStatus handshakeStatusInternal;
        synchronized (this.ssl) {
            handshakeStatusInternal = getHandshakeStatusInternal();
        }
        return handshakeStatusInternal;
    }

    private SSLEngineResult.HandshakeStatus getHandshakeStatusInternal() {
        if (this.handshakeFinished) {
            return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
        }
        switch (this.state) {
            case BerEncoding.TAG_CLASS_UNIVERSAL:
            case 1:
            case 4:
            case 5:
            case 6:
            case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
            case 8:
                return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
            case 2:
                return pendingStatus(pendingOutboundEncryptedBytes());
            case 3:
                return SSLEngineResult.HandshakeStatus.NEED_WRAP;
            default:
                throw new IllegalStateException("Unexpected engine state: " + this.state);
        }
    }

    /* access modifiers changed from: package-private */
    public int pendingOutboundEncryptedBytes() {
        return this.networkBio.getPendingWrittenBytes();
    }

    private int pendingInboundCleartextBytes() {
        return this.ssl.getPendingReadableBytes();
    }

    private static SSLEngineResult.HandshakeStatus pendingStatus(int pendingOutboundBytes) {
        return pendingOutboundBytes > 0 ? SSLEngineResult.HandshakeStatus.NEED_WRAP : SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    }

    public boolean getNeedClientAuth() {
        return this.sslParameters.getNeedClientAuth();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public SSLSession handshakeSession() {
        SSLSession sSLSession;
        synchronized (this.ssl) {
            if (this.state == 2) {
                sSLSession = Platform.wrapSSLSession(new ExternalSession(new ExternalSession.Provider() {
                    /* class org.conscrypt.ConscryptEngine.AnonymousClass2 */

                    @Override // org.conscrypt.ExternalSession.Provider
                    public ConscryptSession provideSession() {
                        return ConscryptEngine.this.provideHandshakeSession();
                    }
                }));
            } else {
                sSLSession = null;
            }
        }
        return sSLSession;
    }

    public SSLSession getSession() {
        return this.externalSession;
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private ConscryptSession provideSession() {
        ConscryptSession conscryptSession;
        synchronized (this.ssl) {
            if (this.state == 8) {
                conscryptSession = this.closedSession != null ? this.closedSession : SSLNullSession.getNullSession();
            } else if (this.state < 3) {
                conscryptSession = SSLNullSession.getNullSession();
            } else {
                conscryptSession = this.activeSession;
            }
        }
        return conscryptSession;
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private ConscryptSession provideHandshakeSession() {
        ConscryptSession nullSession;
        synchronized (this.ssl) {
            if (this.state == 2) {
                nullSession = this.activeSession;
            } else {
                nullSession = SSLNullSession.getNullSession();
            }
        }
        return nullSession;
    }

    private ConscryptSession provideAfterHandshakeSession() {
        if (this.state < 2) {
            return SSLNullSession.getNullSession();
        }
        return provideSession();
    }

    public String[] getSupportedCipherSuites() {
        return NativeCrypto.getSupportedCipherSuites();
    }

    public String[] getSupportedProtocols() {
        return NativeCrypto.getSupportedProtocols();
    }

    public boolean getUseClientMode() {
        return this.sslParameters.getUseClientMode();
    }

    public boolean getWantClientAuth() {
        return this.sslParameters.getWantClientAuth();
    }

    public boolean isInboundDone() {
        boolean z;
        synchronized (this.ssl) {
            z = (this.state == 8 || this.state == 6 || this.ssl.wasShutdownReceived()) && pendingInboundCleartextBytes() == 0;
        }
        return z;
    }

    public boolean isOutboundDone() {
        boolean z;
        synchronized (this.ssl) {
            z = (this.state == 8 || this.state == 7 || this.ssl.wasShutdownSent()) && pendingOutboundEncryptedBytes() == 0;
        }
        return z;
    }

    public void setEnabledCipherSuites(String[] suites) {
        this.sslParameters.setEnabledCipherSuites(suites);
    }

    public void setEnabledProtocols(String[] protocols) {
        this.sslParameters.setEnabledProtocols(protocols);
    }

    public void setEnableSessionCreation(boolean flag) {
        this.sslParameters.setEnableSessionCreation(flag);
    }

    public void setNeedClientAuth(boolean need) {
        this.sslParameters.setNeedClientAuth(need);
    }

    public void setUseClientMode(boolean mode) {
        synchronized (this.ssl) {
            if (isHandshakeStarted()) {
                throw new IllegalArgumentException("Can not change mode after handshake: state == " + this.state);
            }
            transitionTo(1);
            this.sslParameters.setUseClientMode(mode);
        }
    }

    public void setWantClientAuth(boolean want) {
        this.sslParameters.setWantClientAuth(want);
    }

    @Override // org.conscrypt.AbstractConscryptEngine, javax.net.ssl.SSLEngine
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        SSLEngineResult unwrap;
        synchronized (this.ssl) {
            try {
                unwrap = unwrap(singleSrcBuffer(src), singleDstBuffer(dst));
                resetSingleSrcBuffer();
                resetSingleDstBuffer();
            } catch (Throwable th) {
                resetSingleSrcBuffer();
                resetSingleDstBuffer();
                throw th;
            }
        }
        return unwrap;
    }

    @Override // org.conscrypt.AbstractConscryptEngine, javax.net.ssl.SSLEngine
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        SSLEngineResult unwrap;
        synchronized (this.ssl) {
            try {
                unwrap = unwrap(singleSrcBuffer(src), dsts);
                resetSingleSrcBuffer();
            } catch (Throwable th) {
                resetSingleSrcBuffer();
                throw th;
            }
        }
        return unwrap;
    }

    @Override // org.conscrypt.AbstractConscryptEngine, javax.net.ssl.SSLEngine
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length) throws SSLException {
        SSLEngineResult unwrap;
        synchronized (this.ssl) {
            try {
                unwrap = unwrap(singleSrcBuffer(src), 0, 1, dsts, offset, length);
                resetSingleSrcBuffer();
            } catch (Throwable th) {
                resetSingleSrcBuffer();
                throw th;
            }
        }
        return unwrap;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public SSLEngineResult unwrap(ByteBuffer[] srcs, ByteBuffer[] dsts) throws SSLException {
        boolean z;
        boolean z2 = true;
        if (srcs != null) {
            z = true;
        } else {
            z = false;
        }
        Preconditions.checkArgument(z, "srcs is null");
        if (dsts == null) {
            z2 = false;
        }
        Preconditions.checkArgument(z2, "dsts is null");
        return unwrap(srcs, 0, srcs.length, dsts, 0, dsts.length);
    }

    /* access modifiers changed from: package-private */
    /* JADX WARNING: Removed duplicated region for block: B:106:0x0204  */
    /* JADX WARNING: Removed duplicated region for block: B:110:0x0219  */
    /* JADX WARNING: Removed duplicated region for block: B:112:0x0221  */
    /* JADX WARNING: Removed duplicated region for block: B:115:0x0134 A[SYNTHETIC] */
    /* JADX WARNING: Removed duplicated region for block: B:13:0x005e  */
    /* JADX WARNING: Removed duplicated region for block: B:34:0x00b7  */
    /* JADX WARNING: Removed duplicated region for block: B:42:0x00e3  */
    /* JADX WARNING: Removed duplicated region for block: B:58:0x012c  */
    /* JADX WARNING: Removed duplicated region for block: B:63:0x0137  */
    /* JADX WARNING: Removed duplicated region for block: B:70:0x0148  */
    /* JADX WARNING: Removed duplicated region for block: B:72:0x0164  */
    /* JADX WARNING: Removed duplicated region for block: B:86:0x01a0  */
    /* JADX WARNING: Removed duplicated region for block: B:88:0x01a6  */
    @Override // org.conscrypt.AbstractConscryptEngine
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public javax.net.ssl.SSLEngineResult unwrap(java.nio.ByteBuffer[] r32, int r33, int r34, java.nio.ByteBuffer[] r35, int r36, int r37) throws javax.net.ssl.SSLException {
        /*
        // Method dump skipped, instructions count: 590
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.ConscryptEngine.unwrap(java.nio.ByteBuffer[], int, int, java.nio.ByteBuffer[], int, int):javax.net.ssl.SSLEngineResult");
    }

    private static int calcDstsLength(ByteBuffer[] dsts, int dstsOffset, int dstsLength) {
        int capacity = 0;
        for (int i = 0; i < dsts.length; i++) {
            ByteBuffer dst = dsts[i];
            Preconditions.checkArgument(dst != null, "dsts[%d] is null", Integer.valueOf(i));
            if (dst.isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
            if (i >= dstsOffset && i < dstsOffset + dstsLength) {
                capacity += dst.remaining();
            }
        }
        return capacity;
    }

    private static long calcSrcsLength(ByteBuffer[] srcs, int srcsOffset, int srcsEndOffset) {
        long len = 0;
        for (int i = srcsOffset; i < srcsEndOffset; i++) {
            ByteBuffer src = srcs[i];
            if (src == null) {
                throw new IllegalArgumentException("srcs[" + i + "] is null");
            }
            len += (long) src.remaining();
        }
        return len;
    }

    private SSLEngineResult.HandshakeStatus handshake() throws SSLException {
        try {
            switch (this.ssl.doHandshake()) {
                case 2:
                    return pendingStatus(pendingOutboundEncryptedBytes());
                case 3:
                    return SSLEngineResult.HandshakeStatus.NEED_WRAP;
                default:
                    try {
                        this.activeSession.onPeerCertificateAvailable(getPeerHost(), getPeerPort());
                        finishHandshake();
                        return SSLEngineResult.HandshakeStatus.FINISHED;
                    } catch (Exception e) {
                        throw SSLUtils.toSSLHandshakeException(e);
                    }
            }
        } catch (IOException e2) {
            closeAll();
            throw e2;
        }
    }

    private void finishHandshake() throws SSLException {
        this.handshakeFinished = true;
        if (this.handshakeListener != null) {
            this.handshakeListener.onHandshakeFinished();
        }
    }

    private int writePlaintextData(ByteBuffer src, int len) throws SSLException {
        int sslWrote;
        try {
            int pos = src.position();
            if (src.isDirect()) {
                sslWrote = writePlaintextDataDirect(src, pos, len);
            } else {
                sslWrote = writePlaintextDataHeap(src, pos, len);
            }
            if (sslWrote > 0) {
                src.position(pos + sslWrote);
            }
            return sslWrote;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private int writePlaintextDataDirect(ByteBuffer src, int pos, int len) throws IOException {
        return this.ssl.writeDirectByteBuffer(directByteBufferAddress(src, pos), len);
    }

    private int writePlaintextDataHeap(ByteBuffer src, int pos, int len) throws IOException {
        ByteBuffer buffer;
        AllocatedBuffer allocatedBuffer = null;
        try {
            if (this.bufferAllocator != null) {
                allocatedBuffer = this.bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                buffer = getOrCreateLazyDirectBuffer();
            }
            int limit = src.limit();
            int bytesToWrite = Math.min(len, buffer.remaining());
            src.limit(pos + bytesToWrite);
            buffer.put(src);
            buffer.flip();
            src.limit(limit);
            src.position(pos);
            return writePlaintextDataDirect(buffer, 0, bytesToWrite);
        } finally {
            if (allocatedBuffer != null) {
                allocatedBuffer.release();
            }
        }
    }

    private int readPlaintextData(ByteBuffer dst) throws IOException {
        try {
            int pos = dst.position();
            int len = Math.min(16709, dst.limit() - pos);
            if (!dst.isDirect()) {
                return readPlaintextDataHeap(dst, len);
            }
            int bytesRead = readPlaintextDataDirect(dst, pos, len);
            if (bytesRead <= 0) {
                return bytesRead;
            }
            dst.position(pos + bytesRead);
            return bytesRead;
        } catch (CertificateException e) {
            throw convertException(e);
        }
    }

    private int readPlaintextDataDirect(ByteBuffer dst, int pos, int len) throws IOException, CertificateException {
        return this.ssl.readDirectByteBuffer(directByteBufferAddress(dst, pos), len);
    }

    private int readPlaintextDataHeap(ByteBuffer dst, int len) throws IOException, CertificateException {
        ByteBuffer buffer;
        AllocatedBuffer allocatedBuffer = null;
        try {
            if (this.bufferAllocator != null) {
                allocatedBuffer = this.bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                buffer = getOrCreateLazyDirectBuffer();
            }
            int bytesRead = readPlaintextDataDirect(buffer, 0, Math.min(len, buffer.remaining()));
            if (bytesRead > 0) {
                buffer.position(bytesRead);
                buffer.flip();
                dst.put(buffer);
            }
            return bytesRead;
        } finally {
            if (allocatedBuffer != null) {
                allocatedBuffer.release();
            }
        }
    }

    private SSLException convertException(Throwable e) {
        if ((e instanceof SSLHandshakeException) || !this.handshakeFinished) {
            return SSLUtils.toSSLHandshakeException(e);
        }
        return SSLUtils.toSSLException(e);
    }

    private int writeEncryptedData(ByteBuffer src, int len) throws SSLException {
        int bytesWritten;
        try {
            int pos = src.position();
            if (src.isDirect()) {
                bytesWritten = writeEncryptedDataDirect(src, pos, len);
            } else {
                bytesWritten = writeEncryptedDataHeap(src, pos, len);
            }
            if (bytesWritten > 0) {
                src.position(pos + bytesWritten);
            }
            return bytesWritten;
        } catch (IOException e) {
            closeAll();
            throw new SSLException(e);
        }
    }

    private int writeEncryptedDataDirect(ByteBuffer src, int pos, int len) throws IOException {
        return this.networkBio.writeDirectByteBuffer(directByteBufferAddress(src, pos), len);
    }

    private int writeEncryptedDataHeap(ByteBuffer src, int pos, int len) throws IOException {
        ByteBuffer buffer;
        AllocatedBuffer allocatedBuffer = null;
        try {
            if (this.bufferAllocator != null) {
                allocatedBuffer = this.bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                buffer = getOrCreateLazyDirectBuffer();
            }
            int limit = src.limit();
            int bytesToCopy = Math.min(Math.min(limit - pos, len), buffer.remaining());
            src.limit(pos + bytesToCopy);
            buffer.put(src);
            src.limit(limit);
            src.position(pos);
            int bytesWritten = writeEncryptedDataDirect(buffer, 0, bytesToCopy);
            src.position(pos);
            return bytesWritten;
        } finally {
            if (allocatedBuffer != null) {
                allocatedBuffer.release();
            }
        }
    }

    private ByteBuffer getOrCreateLazyDirectBuffer() {
        if (this.lazyDirectBuffer == null) {
            this.lazyDirectBuffer = ByteBuffer.allocateDirect(Math.max(16384, 16709));
        }
        this.lazyDirectBuffer.clear();
        return this.lazyDirectBuffer;
    }

    private long directByteBufferAddress(ByteBuffer directBuffer, int pos) {
        return NativeCrypto.getDirectBufferAddress(directBuffer) + ((long) pos);
    }

    private SSLEngineResult readPendingBytesFromBIO(ByteBuffer dst, int bytesConsumed, int bytesProduced, SSLEngineResult.HandshakeStatus status) throws SSLException {
        try {
            int pendingNet = pendingOutboundEncryptedBytes();
            if (pendingNet <= 0) {
                return null;
            }
            if (dst.remaining() < pendingNet) {
                SSLEngineResult.Status status2 = SSLEngineResult.Status.BUFFER_OVERFLOW;
                if (status != SSLEngineResult.HandshakeStatus.FINISHED) {
                    status = getHandshakeStatus(pendingNet);
                }
                return new SSLEngineResult(status2, mayFinishHandshake(status), bytesConsumed, bytesProduced);
            }
            int produced = readEncryptedData(dst, pendingNet);
            if (produced <= 0) {
                NativeCrypto.SSL_clear_error();
            } else {
                bytesProduced += produced;
                pendingNet -= produced;
            }
            SSLEngineResult.Status engineStatus = getEngineStatus();
            if (status != SSLEngineResult.HandshakeStatus.FINISHED) {
                status = getHandshakeStatus(pendingNet);
            }
            return new SSLEngineResult(engineStatus, mayFinishHandshake(status), bytesConsumed, bytesProduced);
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private int readEncryptedData(ByteBuffer dst, int pending) throws SSLException {
        try {
            int pos = dst.position();
            if (dst.remaining() < pending) {
                return 0;
            }
            int len = Math.min(pending, dst.limit() - pos);
            if (!dst.isDirect()) {
                return readEncryptedDataHeap(dst, len);
            }
            int bytesRead = readEncryptedDataDirect(dst, pos, len);
            if (bytesRead <= 0) {
                return bytesRead;
            }
            dst.position(pos + bytesRead);
            return bytesRead;
        } catch (Exception e) {
            throw convertException(e);
        }
    }

    private int readEncryptedDataDirect(ByteBuffer dst, int pos, int len) throws IOException {
        return this.networkBio.readDirectByteBuffer(directByteBufferAddress(dst, pos), len);
    }

    private int readEncryptedDataHeap(ByteBuffer dst, int len) throws IOException {
        ByteBuffer buffer;
        AllocatedBuffer allocatedBuffer = null;
        try {
            if (this.bufferAllocator != null) {
                allocatedBuffer = this.bufferAllocator.allocateDirectBuffer(len);
                buffer = allocatedBuffer.nioBuffer();
            } else {
                buffer = getOrCreateLazyDirectBuffer();
            }
            int bytesRead = readEncryptedDataDirect(buffer, 0, Math.min(len, buffer.remaining()));
            if (bytesRead > 0) {
                buffer.position(bytesRead);
                buffer.flip();
                dst.put(buffer);
            }
            return bytesRead;
        } finally {
            if (allocatedBuffer != null) {
                allocatedBuffer.release();
            }
        }
    }

    private SSLEngineResult.HandshakeStatus mayFinishHandshake(SSLEngineResult.HandshakeStatus status) throws SSLException {
        if (this.handshakeFinished || status != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            return status;
        }
        return handshake();
    }

    private SSLEngineResult.HandshakeStatus getHandshakeStatus(int pending) {
        return !this.handshakeFinished ? pendingStatus(pending) : SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    private SSLEngineResult.Status getEngineStatus() {
        switch (this.state) {
            case 6:
            case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
            case 8:
                return SSLEngineResult.Status.CLOSED;
            default:
                return SSLEngineResult.Status.OK;
        }
    }

    private void closeAll() {
        closeOutbound();
        closeInbound();
    }

    private void freeIfDone() {
        if (isInboundDone() && isOutboundDone()) {
            closeAndFreeResources();
        }
    }

    private SSLException newSslExceptionWithMessage(String err) {
        if (!this.handshakeFinished) {
            return new SSLException(err);
        }
        return new SSLHandshakeException(err);
    }

    private SSLEngineResult newResult(int bytesConsumed, int bytesProduced, SSLEngineResult.HandshakeStatus status) throws SSLException {
        SSLEngineResult.Status engineStatus = getEngineStatus();
        if (status != SSLEngineResult.HandshakeStatus.FINISHED) {
            status = getHandshakeStatusInternal();
        }
        return new SSLEngineResult(engineStatus, mayFinishHandshake(status), bytesConsumed, bytesProduced);
    }

    @Override // org.conscrypt.AbstractConscryptEngine, javax.net.ssl.SSLEngine
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        SSLEngineResult wrap;
        synchronized (this.ssl) {
            try {
                wrap = wrap(singleSrcBuffer(src), dst);
                resetSingleSrcBuffer();
            } catch (Throwable th) {
                resetSingleSrcBuffer();
                throw th;
            }
        }
        return wrap;
    }

    /* JADX WARNING: Code restructure failed: missing block: B:76:0x0132, code lost:
        if (r2 != 0) goto L_0x0199;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:77:0x0134, code lost:
        r7 = readPendingBytesFromBIO(r21, 0, r3, r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:78:0x013d, code lost:
        if (r7 == null) goto L_0x0199;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:97:0x0199, code lost:
        r7 = newResult(r2, r3, r5);
     */
    /* JADX WARNING: Removed duplicated region for block: B:19:0x003e  */
    /* JADX WARNING: Removed duplicated region for block: B:42:0x0091  */
    /* JADX WARNING: Removed duplicated region for block: B:55:0x00d3  */
    /* JADX WARNING: Removed duplicated region for block: B:57:0x00e6  */
    @Override // org.conscrypt.AbstractConscryptEngine, javax.net.ssl.SSLEngine
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public javax.net.ssl.SSLEngineResult wrap(java.nio.ByteBuffer[] r18, int r19, int r20, java.nio.ByteBuffer r21) throws javax.net.ssl.SSLException {
        /*
        // Method dump skipped, instructions count: 454
        */
        throw new UnsupportedOperationException("Method not decompiled: org.conscrypt.ConscryptEngine.wrap(java.nio.ByteBuffer[], int, int, java.nio.ByteBuffer):javax.net.ssl.SSLEngineResult");
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public int clientPSKKeyRequested(String identityHint, byte[] identity, byte[] key) {
        return this.ssl.clientPSKKeyRequested(identityHint, identity, key);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public int serverPSKKeyRequested(String identityHint, String identity, byte[] key) {
        return this.ssl.serverPSKKeyRequested(identityHint, identity, key);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public void onSSLStateChange(int type, int val) {
        synchronized (this.ssl) {
            switch (type) {
                case 16:
                    transitionTo(2);
                    break;
                case 32:
                    if (this.state == 2 || this.state == 4) {
                        transitionTo(3);
                        break;
                    } else {
                        throw new IllegalStateException("Completed handshake while in mode " + this.state);
                    }
                    break;
            }
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public void serverCertificateRequested() throws IOException {
        synchronized (this.ssl) {
            this.ssl.configureServerCertificate();
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public void onNewSessionEstablished(long sslSessionNativePtr) {
        try {
            NativeCrypto.SSL_SESSION_up_ref(sslSessionNativePtr);
            sessionContext().cacheSession(NativeSslSession.newInstance(new NativeRef.SSL_SESSION(sslSessionNativePtr), this.activeSession));
        } catch (Exception e) {
        }
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public long serverSessionRequested(byte[] id) {
        return 0;
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public void verifyCertificateChain(byte[][] certChain, String authMethod) throws CertificateException {
        if (certChain != null) {
            try {
                if (certChain.length != 0) {
                    X509Certificate[] peerCertChain = SSLUtils.decodeX509CertificateChain(certChain);
                    X509TrustManager x509tm = this.sslParameters.getX509TrustManager();
                    if (x509tm == null) {
                        throw new CertificateException("No X.509 TrustManager");
                    }
                    this.activeSession.onPeerCertificatesReceived(getPeerHost(), getPeerPort(), peerCertChain);
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

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public void clientCertificateRequested(byte[] keyTypeBytes, int[] signatureAlgs, byte[][] asn1DerEncodedPrincipals) throws CertificateEncodingException, SSLException {
        this.ssl.chooseClientCertificate(keyTypeBytes, signatureAlgs, asn1DerEncodedPrincipals);
    }

    private void sendSSLShutdown() {
        try {
            this.ssl.shutdown();
        } catch (IOException e) {
        }
    }

    private void closeAndFreeResources() {
        transitionTo(8);
        if (!this.ssl.isClosed()) {
            this.ssl.close();
            this.networkBio.close();
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.lang.Object
    public void finalize() throws Throwable {
        try {
            transitionTo(8);
        } finally {
            super.finalize();
        }
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public String chooseServerAlias(X509KeyManager keyManager, String keyType) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            return ((X509ExtendedKeyManager) keyManager).chooseEngineServerAlias(keyType, null, this);
        }
        return keyManager.chooseServerAlias(keyType, null, null);
    }

    @Override // org.conscrypt.SSLParametersImpl.AliasChooser
    public String chooseClientAlias(X509KeyManager keyManager, X500Principal[] issuers, String[] keyTypes) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            return ((X509ExtendedKeyManager) keyManager).chooseEngineClientAlias(keyTypes, issuers, this);
        }
        return keyManager.chooseClientAlias(keyTypes, issuers, null);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public String chooseServerPSKIdentityHint(PSKKeyManager keyManager) {
        return keyManager.chooseServerKeyIdentityHint(this);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public String chooseClientPSKIdentity(PSKKeyManager keyManager, String identityHint) {
        return keyManager.chooseClientKeyIdentity(identityHint, this);
    }

    @Override // org.conscrypt.SSLParametersImpl.PSKCallbacks
    public SecretKey getPSKKey(PSKKeyManager keyManager, String identityHint, String identity) {
        return keyManager.getKey(identityHint, identity, this);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setUseSessionTickets(boolean useSessionTickets) {
        this.sslParameters.setUseSessionTickets(useSessionTickets);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public String[] getApplicationProtocols() {
        return this.sslParameters.getApplicationProtocols();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setApplicationProtocols(String[] protocols) {
        this.sslParameters.setApplicationProtocols(protocols);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public void setApplicationProtocolSelector(ApplicationProtocolSelector selector) {
        setApplicationProtocolSelector(selector == null ? null : new ApplicationProtocolSelectorAdapter(this, selector));
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public byte[] getTlsUnique() {
        return this.ssl.getTlsUnique();
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.AbstractConscryptEngine
    public byte[] exportKeyingMaterial(String label, byte[] context, int length) throws SSLException {
        synchronized (this.ssl) {
            if (this.state < 3 || this.state == 8) {
                return null;
            }
            return this.ssl.exportKeyingMaterial(label, context, length);
        }
    }

    /* access modifiers changed from: package-private */
    public void setApplicationProtocolSelector(ApplicationProtocolSelectorAdapter adapter) {
        this.sslParameters.setApplicationProtocolSelector(adapter);
    }

    @Override // org.conscrypt.NativeCrypto.SSLHandshakeCallbacks
    public int selectApplicationProtocol(byte[] protocols) {
        ApplicationProtocolSelectorAdapter adapter = this.sslParameters.getApplicationProtocolSelector();
        if (adapter == null) {
            return 3;
        }
        return adapter.selectApplicationProtocol(protocols);
    }

    @Override // org.conscrypt.AbstractConscryptEngine
    public String getApplicationProtocol() {
        return provideAfterHandshakeSession().getApplicationProtocol();
    }

    @Override // org.conscrypt.AbstractConscryptEngine
    public String getHandshakeApplicationProtocol() {
        String applicationProtocol;
        synchronized (this.ssl) {
            applicationProtocol = this.state >= 2 ? getApplicationProtocol() : null;
        }
        return applicationProtocol;
    }

    private ByteBuffer[] singleSrcBuffer(ByteBuffer src) {
        this.singleSrcBuffer[0] = src;
        return this.singleSrcBuffer;
    }

    private void resetSingleSrcBuffer() {
        this.singleSrcBuffer[0] = null;
    }

    private ByteBuffer[] singleDstBuffer(ByteBuffer src) {
        this.singleDstBuffer[0] = src;
        return this.singleDstBuffer;
    }

    private void resetSingleDstBuffer() {
        this.singleDstBuffer[0] = null;
    }

    private ClientSessionContext clientSessionContext() {
        return this.sslParameters.getClientSessionContext();
    }

    private AbstractSessionContext sessionContext() {
        return this.sslParameters.getSessionContext();
    }

    private void transitionTo(int newState) {
        switch (newState) {
            case 2:
                this.handshakeFinished = false;
                this.activeSession = new ActiveSession(this.ssl, this.sslParameters.getSessionContext());
                break;
            case 8:
                if (!this.ssl.isClosed() && this.state >= 2 && this.state < 8) {
                    this.closedSession = new SessionSnapshot(this.activeSession);
                    break;
                }
        }
        this.state = newState;
    }
}
