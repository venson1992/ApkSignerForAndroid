package org.conscrypt;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import org.conscrypt.NativeRef;
import org.conscrypt.SSLUtils;

abstract class NativeSslSession {
    private static final Logger logger = Logger.getLogger(NativeSslSession.class.getName());

    /* access modifiers changed from: package-private */
    public abstract String getCipherSuite();

    /* access modifiers changed from: package-private */
    public abstract byte[] getId();

    /* access modifiers changed from: package-private */
    public abstract String getPeerHost();

    /* access modifiers changed from: package-private */
    public abstract byte[] getPeerOcspStapledResponse();

    /* access modifiers changed from: package-private */
    public abstract int getPeerPort();

    /* access modifiers changed from: package-private */
    public abstract byte[] getPeerSignedCertificateTimestamp();

    /* access modifiers changed from: package-private */
    public abstract String getProtocol();

    /* access modifiers changed from: package-private */
    public abstract boolean isSingleUse();

    /* access modifiers changed from: package-private */
    public abstract boolean isValid();

    /* access modifiers changed from: package-private */
    public abstract void offerToResume(NativeSsl nativeSsl) throws SSLException;

    /* access modifiers changed from: package-private */
    public abstract byte[] toBytes();

    /* access modifiers changed from: package-private */
    public abstract SSLSession toSSLSession();

    NativeSslSession() {
    }

    static NativeSslSession newInstance(NativeRef.SSL_SESSION ref, ConscryptSession session) throws SSLPeerUnverifiedException {
        AbstractSessionContext context = (AbstractSessionContext) session.getSessionContext();
        if (context instanceof ClientSessionContext) {
            return new Impl(context, ref, session.getPeerHost(), session.getPeerPort(), session.getPeerCertificates(), getOcspResponse(session), session.getPeerSignedCertificateTimestamp());
        }
        return new Impl(context, ref, null, -1, null, null, null);
    }

    private static byte[] getOcspResponse(ConscryptSession session) {
        List<byte[]> ocspResponseList = session.getStatusResponses();
        if (ocspResponseList.size() >= 1) {
            return ocspResponseList.get(0);
        }
        return null;
    }

    static NativeSslSession newInstance(AbstractSessionContext context, byte[] data, String host, int port) {
        ByteBuffer buf = ByteBuffer.wrap(data);
        try {
            int type = buf.getInt();
            if (!SSLUtils.SessionType.isSupportedType(type)) {
                throw new IOException("Unexpected type ID: " + type);
            }
            int length = buf.getInt();
            checkRemaining(buf, length);
            byte[] sessionData = new byte[length];
            buf.get(sessionData);
            int count = buf.getInt();
            checkRemaining(buf, count);
            X509Certificate[] peerCerts = new X509Certificate[count];
            for (int i = 0; i < count; i++) {
                int length2 = buf.getInt();
                checkRemaining(buf, length2);
                byte[] certData = new byte[length2];
                buf.get(certData);
                try {
                    peerCerts[i] = OpenSSLX509Certificate.fromX509Der(certData);
                } catch (Exception e) {
                    throw new IOException("Can not read certificate " + i + "/" + count);
                }
            }
            byte[] ocspData = null;
            if (type >= SSLUtils.SessionType.OPEN_SSL_WITH_OCSP.value) {
                int countOcspResponses = buf.getInt();
                checkRemaining(buf, countOcspResponses);
                if (countOcspResponses >= 1) {
                    int ocspLength = buf.getInt();
                    checkRemaining(buf, ocspLength);
                    ocspData = new byte[ocspLength];
                    buf.get(ocspData);
                    for (int i2 = 1; i2 < countOcspResponses; i2++) {
                        int ocspLength2 = buf.getInt();
                        checkRemaining(buf, ocspLength2);
                        buf.position(buf.position() + ocspLength2);
                    }
                }
            }
            byte[] tlsSctData = null;
            if (type == SSLUtils.SessionType.OPEN_SSL_WITH_TLS_SCT.value) {
                int tlsSctDataLength = buf.getInt();
                checkRemaining(buf, tlsSctDataLength);
                if (tlsSctDataLength > 0) {
                    tlsSctData = new byte[tlsSctDataLength];
                    buf.get(tlsSctData);
                }
            }
            if (buf.remaining() == 0) {
                return new Impl(context, new NativeRef.SSL_SESSION(NativeCrypto.d2i_SSL_SESSION(sessionData)), host, port, peerCerts, ocspData, tlsSctData);
            }
            log(new AssertionError("Read entire session, but data still remains; rejecting"));
            return null;
        } catch (IOException e2) {
            log(e2);
            return null;
        } catch (BufferUnderflowException e3) {
            log(e3);
            return null;
        }
    }

    private static final class Impl extends NativeSslSession {
        private final String cipherSuite;
        private final AbstractSessionContext context;
        private final String host;
        private final X509Certificate[] peerCertificates;
        private final byte[] peerOcspStapledResponse;
        private final byte[] peerSignedCertificateTimestamp;
        private final int port;
        private final String protocol;
        private final NativeRef.SSL_SESSION ref;

        private Impl(AbstractSessionContext context2, NativeRef.SSL_SESSION ref2, String host2, int port2, X509Certificate[] peerCertificates2, byte[] peerOcspStapledResponse2, byte[] peerSignedCertificateTimestamp2) {
            this.context = context2;
            this.host = host2;
            this.port = port2;
            this.peerCertificates = peerCertificates2;
            this.peerOcspStapledResponse = peerOcspStapledResponse2;
            this.peerSignedCertificateTimestamp = peerSignedCertificateTimestamp2;
            this.protocol = NativeCrypto.SSL_SESSION_get_version(ref2.address);
            this.cipherSuite = NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_SESSION_cipher(ref2.address));
            this.ref = ref2;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public byte[] getId() {
            return NativeCrypto.SSL_SESSION_session_id(this.ref.address);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private long getCreationTime() {
            return NativeCrypto.SSL_SESSION_get_time(this.ref.address);
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public boolean isValid() {
            return System.currentTimeMillis() - (Math.max(0, Math.min((long) this.context.getSessionTimeout(), NativeCrypto.SSL_SESSION_get_timeout(this.ref.address))) * 1000) < getCreationTime();
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public boolean isSingleUse() {
            return NativeCrypto.SSL_SESSION_should_be_single_use(this.ref.address);
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public void offerToResume(NativeSsl ssl) throws SSLException {
            ssl.offerToResumeSession(this.ref.address);
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public String getCipherSuite() {
            return this.cipherSuite;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public String getProtocol() {
            return this.protocol;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public String getPeerHost() {
            return this.host;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public int getPeerPort() {
            return this.port;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public byte[] getPeerOcspStapledResponse() {
            return this.peerOcspStapledResponse;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public byte[] getPeerSignedCertificateTimestamp() {
            return this.peerSignedCertificateTimestamp;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public byte[] toBytes() {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream daos = new DataOutputStream(baos);
                daos.writeInt(SSLUtils.SessionType.OPEN_SSL_WITH_TLS_SCT.value);
                byte[] data = NativeCrypto.i2d_SSL_SESSION(this.ref.address);
                daos.writeInt(data.length);
                daos.write(data);
                daos.writeInt(this.peerCertificates.length);
                for (Certificate cert : this.peerCertificates) {
                    byte[] data2 = cert.getEncoded();
                    daos.writeInt(data2.length);
                    daos.write(data2);
                }
                if (this.peerOcspStapledResponse != null) {
                    daos.writeInt(1);
                    daos.writeInt(this.peerOcspStapledResponse.length);
                    daos.write(this.peerOcspStapledResponse);
                } else {
                    daos.writeInt(0);
                }
                if (this.peerSignedCertificateTimestamp != null) {
                    daos.writeInt(this.peerSignedCertificateTimestamp.length);
                    daos.write(this.peerSignedCertificateTimestamp);
                } else {
                    daos.writeInt(0);
                }
                return baos.toByteArray();
            } catch (IOException e) {
                NativeSslSession.logger.log(Level.WARNING, "Failed to convert saved SSL Session: ", (Throwable) e);
                return null;
            } catch (CertificateEncodingException e2) {
                NativeSslSession.log(e2);
                return null;
            }
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.NativeSslSession
        public SSLSession toSSLSession() {
            return new SSLSession() {
                /* class org.conscrypt.NativeSslSession.Impl.AnonymousClass1 */

                public byte[] getId() {
                    return Impl.this.getId();
                }

                public String getCipherSuite() {
                    return Impl.this.getCipherSuite();
                }

                public String getProtocol() {
                    return Impl.this.getProtocol();
                }

                public String getPeerHost() {
                    return Impl.this.getPeerHost();
                }

                public int getPeerPort() {
                    return Impl.this.getPeerPort();
                }

                public long getCreationTime() {
                    return Impl.this.getCreationTime();
                }

                public boolean isValid() {
                    return Impl.this.isValid();
                }

                public SSLSessionContext getSessionContext() {
                    throw new UnsupportedOperationException();
                }

                public long getLastAccessedTime() {
                    throw new UnsupportedOperationException();
                }

                public void invalidate() {
                    throw new UnsupportedOperationException();
                }

                public void putValue(String s, Object o) {
                    throw new UnsupportedOperationException();
                }

                public Object getValue(String s) {
                    throw new UnsupportedOperationException();
                }

                public void removeValue(String s) {
                    throw new UnsupportedOperationException();
                }

                public String[] getValueNames() {
                    throw new UnsupportedOperationException();
                }

                @Override // javax.net.ssl.SSLSession
                public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
                    throw new UnsupportedOperationException();
                }

                public Certificate[] getLocalCertificates() {
                    throw new UnsupportedOperationException();
                }

                @Override // javax.net.ssl.SSLSession
                public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
                    throw new UnsupportedOperationException();
                }

                @Override // javax.net.ssl.SSLSession
                public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
                    throw new UnsupportedOperationException();
                }

                public Principal getLocalPrincipal() {
                    throw new UnsupportedOperationException();
                }

                public int getPacketBufferSize() {
                    throw new UnsupportedOperationException();
                }

                public int getApplicationBufferSize() {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }

    /* access modifiers changed from: private */
    public static void log(Throwable t) {
        logger.log(Level.INFO, "Error inflating SSL session: {0}", t.getMessage() != null ? t.getMessage() : t.getClass().getName());
    }

    private static void checkRemaining(ByteBuffer buf, int length) throws IOException {
        if (length < 0) {
            throw new IOException("Length is negative: " + length);
        } else if (length > buf.remaining()) {
            throw new IOException("Length of blob is longer than available: " + length + " > " + buf.remaining());
        }
    }
}
