package org.conscrypt;

import com.android.apksig.ApkVerificationIssue;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

/* access modifiers changed from: package-private */
public final class SSLUtils {
    private static final String KEY_TYPE_EC = "EC";
    private static final String KEY_TYPE_RSA = "RSA";
    private static final int MAX_ENCRYPTION_OVERHEAD_DIFF = 2147483561;
    private static final int MAX_ENCRYPTION_OVERHEAD_LENGTH = 86;
    private static final int MAX_PROTOCOL_LENGTH = 255;
    static final boolean USE_ENGINE_SOCKET_BY_DEFAULT = Boolean.parseBoolean(System.getProperty("org.conscrypt.useEngineSocketByDefault", "true"));
    private static final Charset US_ASCII = Charset.forName("US-ASCII");

    /* access modifiers changed from: package-private */
    public enum SessionType {
        OPEN_SSL(1),
        OPEN_SSL_WITH_OCSP(2),
        OPEN_SSL_WITH_TLS_SCT(3);
        
        final int value;

        private SessionType(int value2) {
            this.value = value2;
        }

        static boolean isSupportedType(int type) {
            return type == OPEN_SSL.value || type == OPEN_SSL_WITH_OCSP.value || type == OPEN_SSL_WITH_TLS_SCT.value;
        }
    }

    static final class EngineStates {
        static final int STATE_CLOSED = 8;
        static final int STATE_CLOSED_INBOUND = 6;
        static final int STATE_CLOSED_OUTBOUND = 7;
        static final int STATE_HANDSHAKE_COMPLETED = 3;
        static final int STATE_HANDSHAKE_STARTED = 2;
        static final int STATE_MODE_SET = 1;
        static final int STATE_NEW = 0;
        static final int STATE_READY = 5;
        static final int STATE_READY_HANDSHAKE_CUT_THROUGH = 4;

        private EngineStates() {
        }
    }

    static X509Certificate[] decodeX509CertificateChain(byte[][] certChain) throws CertificateException {
        CertificateFactory certificateFactory = getCertificateFactory();
        int numCerts = certChain.length;
        X509Certificate[] decodedCerts = new X509Certificate[numCerts];
        for (int i = 0; i < numCerts; i++) {
            decodedCerts[i] = decodeX509Certificate(certificateFactory, certChain[i]);
        }
        return decodedCerts;
    }

    private static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            return null;
        }
    }

    private static X509Certificate decodeX509Certificate(CertificateFactory certificateFactory, byte[] bytes) throws CertificateException {
        if (certificateFactory != null) {
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));
        }
        return OpenSSLX509Certificate.fromX509Der(bytes);
    }

    static String getServerX509KeyType(long sslCipherNative) {
        String kx_name = NativeCrypto.SSL_CIPHER_get_kx_name(sslCipherNative);
        if (kx_name.equals(KEY_TYPE_RSA) || kx_name.equals("DHE_RSA") || kx_name.equals("ECDHE_RSA")) {
            return KEY_TYPE_RSA;
        }
        if (kx_name.equals("ECDHE_ECDSA")) {
            return KEY_TYPE_EC;
        }
        return null;
    }

    static String getClientKeyType(byte clientCertificateType) {
        switch (clientCertificateType) {
            case 1:
                return KEY_TYPE_RSA;
            case 64:
                return KEY_TYPE_EC;
            default:
                return null;
        }
    }

    static String getClientKeyTypeFromSignatureAlg(int signatureAlg) {
        switch (NativeCrypto.SSL_get_signature_algorithm_key_type(signatureAlg)) {
            case 6:
                return KEY_TYPE_RSA;
            case 408:
                return KEY_TYPE_EC;
            default:
                return null;
        }
    }

    static Set<String> getSupportedClientKeyTypes(byte[] clientCertificateTypes, int[] signatureAlgs) {
        Set<String> fromClientCerts = new HashSet<>(clientCertificateTypes.length);
        for (byte keyTypeCode : clientCertificateTypes) {
            String keyType = getClientKeyType(keyTypeCode);
            if (keyType != null) {
                fromClientCerts.add(keyType);
            }
        }
        Set<String> fromSigAlgs = new LinkedHashSet<>(signatureAlgs.length);
        for (int signatureAlg : signatureAlgs) {
            String keyType2 = getClientKeyTypeFromSignatureAlg(signatureAlg);
            if (keyType2 != null) {
                fromSigAlgs.add(keyType2);
            }
        }
        if (clientCertificateTypes.length <= 0 || signatureAlgs.length <= 0) {
            return signatureAlgs.length <= 0 ? fromClientCerts : fromSigAlgs;
        }
        fromSigAlgs.retainAll(fromClientCerts);
        return fromSigAlgs;
    }

    static byte[][] encodeSubjectX509Principals(X509Certificate[] certificates) throws CertificateEncodingException {
        byte[][] principalBytes = new byte[certificates.length][];
        for (int i = 0; i < certificates.length; i++) {
            principalBytes[i] = certificates[i].getSubjectX500Principal().getEncoded();
        }
        return principalBytes;
    }

    static javax.security.cert.X509Certificate[] toCertificateChain(X509Certificate[] certificates) throws SSLPeerUnverifiedException {
        try {
            javax.security.cert.X509Certificate[] chain = new javax.security.cert.X509Certificate[certificates.length];
            for (int i = 0; i < certificates.length; i++) {
                chain[i] = javax.security.cert.X509Certificate.getInstance(certificates[i].getEncoded());
            }
            return chain;
        } catch (CertificateEncodingException e) {
            SSLPeerUnverifiedException exception = new SSLPeerUnverifiedException(e.getMessage());
            exception.initCause(exception);
            throw exception;
        } catch (javax.security.cert.CertificateException e2) {
            SSLPeerUnverifiedException exception2 = new SSLPeerUnverifiedException(e2.getMessage());
            exception2.initCause(exception2);
            throw exception2;
        }
    }

    static int calculateOutNetBufSize(int pendingBytes) {
        return Math.min(16709, Math.min((int) MAX_ENCRYPTION_OVERHEAD_DIFF, pendingBytes) + MAX_ENCRYPTION_OVERHEAD_LENGTH);
    }

    static SSLHandshakeException toSSLHandshakeException(Throwable e) {
        if (e instanceof SSLHandshakeException) {
            return (SSLHandshakeException) e;
        }
        return (SSLHandshakeException) new SSLHandshakeException(e.getMessage()).initCause(e);
    }

    static SSLException toSSLException(Throwable e) {
        if (e instanceof SSLException) {
            return (SSLException) e;
        }
        return new SSLException(e);
    }

    static String toProtocolString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return new String(bytes, US_ASCII);
    }

    static byte[] toProtocolBytes(String protocol) {
        if (protocol == null) {
            return null;
        }
        return protocol.getBytes(US_ASCII);
    }

    static String[] decodeProtocols(byte[] protocols) {
        String str;
        if (protocols.length == 0) {
            return EmptyArray.STRING;
        }
        int numProtocols = 0;
        int i = 0;
        while (i < protocols.length) {
            byte b = protocols[i];
            if (b < 0 || b > protocols.length - i) {
                throw new IllegalArgumentException("Protocol has invalid length (" + ((int) b) + " at position " + i + "): " + (protocols.length < 50 ? Arrays.toString(protocols) : protocols.length + " byte array"));
            }
            numProtocols++;
            i += b + 1;
        }
        String[] decoded = new String[numProtocols];
        int i2 = 0;
        int d = 0;
        while (i2 < protocols.length) {
            byte b2 = protocols[i2];
            int d2 = d + 1;
            if (b2 > 0) {
                str = new String(protocols, i2 + 1, b2, US_ASCII);
            } else {
                str = "";
            }
            decoded[d] = str;
            i2 += b2 + 1;
            d = d2;
        }
        return decoded;
    }

    static byte[] encodeProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols array must be non-null");
        } else if (protocols.length == 0) {
            return EmptyArray.BYTE;
        } else {
            int length = 0;
            for (int i = 0; i < protocols.length; i++) {
                if (protocols[i] == null) {
                    throw new IllegalArgumentException("protocol[" + i + "] is null");
                }
                int protocolLength = protocols[i].length();
                if (protocolLength == 0 || protocolLength > MAX_PROTOCOL_LENGTH) {
                    throw new IllegalArgumentException("protocol[" + i + "] has invalid length: " + protocolLength);
                }
                length += protocolLength + 1;
            }
            byte[] data = new byte[length];
            int dataIndex = 0;
            int i2 = 0;
            while (i2 < protocols.length) {
                String protocol = protocols[i2];
                int protocolLength2 = protocol.length();
                int dataIndex2 = dataIndex + 1;
                data[dataIndex] = (byte) protocolLength2;
                int ci = 0;
                while (ci < protocolLength2) {
                    char c = protocol.charAt(ci);
                    if (c > 127) {
                        throw new IllegalArgumentException("Protocol contains invalid character: " + c + "(protocol=" + protocol + ")");
                    }
                    data[dataIndex2] = (byte) c;
                    ci++;
                    dataIndex2++;
                }
                i2++;
                dataIndex = dataIndex2;
            }
            return data;
        }
    }

    /* JADX INFO: finally extract failed */
    static int getEncryptedPacketLength(ByteBuffer[] buffers, int offset) {
        ByteBuffer buffer = buffers[offset];
        if (buffer.remaining() >= 5) {
            return getEncryptedPacketLength(buffer);
        }
        ByteBuffer tmp = ByteBuffer.allocate(5);
        while (true) {
            int offset2 = offset + 1;
            ByteBuffer buffer2 = buffers[offset];
            int pos = buffer2.position();
            int limit = buffer2.limit();
            if (buffer2.remaining() > tmp.remaining()) {
                buffer2.limit(tmp.remaining() + pos);
            }
            try {
                tmp.put(buffer2);
                buffer2.limit(limit);
                buffer2.position(pos);
                if (!tmp.hasRemaining()) {
                    tmp.flip();
                    return getEncryptedPacketLength(tmp);
                }
                offset = offset2;
            } catch (Throwable th) {
                buffer2.limit(limit);
                buffer2.position(pos);
                throw th;
            }
        }
    }

    private static int getEncryptedPacketLength(ByteBuffer buffer) {
        int pos = buffer.position();
        switch (unsignedByte(buffer.get(pos))) {
            case ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE:
            case 21:
            case ApkVerificationIssue.SOURCE_STAMP_VERIFY_EXCEPTION:
            case 23:
                if (unsignedByte(buffer.get(pos + 1)) != 3) {
                    return -1;
                }
                int packetLength = unsignedShort(buffer.getShort(pos + 3)) + 5;
                if (packetLength <= 5) {
                    return -1;
                }
                return packetLength;
            default:
                return -1;
        }
    }

    private static short unsignedByte(byte b) {
        return (short) (b & 255);
    }

    private static int unsignedShort(short s) {
        return 65535 & s;
    }

    static String[] concat(String[]... arrays) {
        int resultLength = 0;
        for (String[] array : arrays) {
            resultLength += array.length;
        }
        String[] result = new String[resultLength];
        int resultOffset = 0;
        for (String[] array2 : arrays) {
            System.arraycopy(array2, 0, result, resultOffset, array2.length);
            resultOffset += array2.length;
        }
        return result;
    }

    private SSLUtils() {
    }
}
