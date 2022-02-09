package org.conscrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.conscrypt.OpenSSLX509CertificateFactory;

final class OpenSSLX509CertPath extends CertPath {
    private static final List<String> ALL_ENCODINGS = Collections.unmodifiableList(Arrays.asList(Encoding.PKI_PATH.apiName, Encoding.PKCS7.apiName));
    private static final Encoding DEFAULT_ENCODING = Encoding.PKI_PATH;
    private static final byte[] PKCS7_MARKER = {45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 75, 67, 83, 55};
    private static final int PUSHBACK_SIZE = 64;
    private static final long serialVersionUID = -3249106005255170761L;
    private final List<? extends X509Certificate> mCertificates;

    /* access modifiers changed from: private */
    public enum Encoding {
        PKI_PATH("PkiPath"),
        PKCS7("PKCS7");
        
        private final String apiName;

        private Encoding(String apiName2) {
            this.apiName = apiName2;
        }

        static Encoding findByApiName(String apiName2) throws CertificateEncodingException {
            Encoding[] values = values();
            for (Encoding element : values) {
                if (element.apiName.equals(apiName2)) {
                    return element;
                }
            }
            return null;
        }
    }

    static Iterator<String> getEncodingsIterator() {
        return ALL_ENCODINGS.iterator();
    }

    OpenSSLX509CertPath(List<? extends X509Certificate> certificates) {
        super("X.509");
        this.mCertificates = certificates;
    }

    @Override // java.security.cert.CertPath
    public List<? extends Certificate> getCertificates() {
        return Collections.unmodifiableList(this.mCertificates);
    }

    private byte[] getEncoded(Encoding encoding) throws CertificateEncodingException {
        OpenSSLX509Certificate[] certs = new OpenSSLX509Certificate[this.mCertificates.size()];
        long[] certRefs = new long[certs.length];
        int i = 0;
        for (int j = certs.length - 1; j >= 0; j--) {
            X509Certificate cert = (X509Certificate) this.mCertificates.get(i);
            if (cert instanceof OpenSSLX509Certificate) {
                certs[j] = (OpenSSLX509Certificate) cert;
            } else {
                certs[j] = OpenSSLX509Certificate.fromX509Der(cert.getEncoded());
            }
            certRefs[j] = certs[j].getContext();
            i++;
        }
        switch (encoding) {
            case PKI_PATH:
                return NativeCrypto.ASN1_seq_pack_X509(certRefs);
            case PKCS7:
                return NativeCrypto.i2d_PKCS7(certRefs);
            default:
                throw new CertificateEncodingException("Unknown encoding");
        }
    }

    @Override // java.security.cert.CertPath
    public byte[] getEncoded() throws CertificateEncodingException {
        return getEncoded(DEFAULT_ENCODING);
    }

    @Override // java.security.cert.CertPath
    public byte[] getEncoded(String encoding) throws CertificateEncodingException {
        Encoding enc = Encoding.findByApiName(encoding);
        if (enc != null) {
            return getEncoded(enc);
        }
        throw new CertificateEncodingException("Invalid encoding: " + encoding);
    }

    @Override // java.security.cert.CertPath
    public Iterator<String> getEncodings() {
        return getEncodingsIterator();
    }

    private static CertPath fromPkiPathEncoding(InputStream inStream) throws CertificateException {
        OpenSSLBIOInputStream bis = new OpenSSLBIOInputStream(inStream, true);
        boolean markable = inStream.markSupported();
        if (markable) {
            inStream.mark(PUSHBACK_SIZE);
        }
        try {
            long[] certRefs = NativeCrypto.ASN1_seq_unpack_X509_bio(bis.getBioContext());
            bis.release();
            if (certRefs == null) {
                return new OpenSSLX509CertPath(Collections.emptyList());
            }
            List<OpenSSLX509Certificate> certs = new ArrayList<>(certRefs.length);
            for (int i = certRefs.length - 1; i >= 0; i--) {
                if (certRefs[i] != 0) {
                    try {
                        certs.add(new OpenSSLX509Certificate(certRefs[i]));
                    } catch (OpenSSLX509CertificateFactory.ParsingException e) {
                        throw new CertificateParsingException(e);
                    }
                }
            }
            return new OpenSSLX509CertPath(certs);
        } catch (Exception e2) {
            if (markable) {
                try {
                    inStream.reset();
                } catch (IOException e3) {
                }
            }
            throw new CertificateException(e2);
        } catch (Throwable th) {
            bis.release();
            throw th;
        }
    }

    private static CertPath fromPkcs7Encoding(InputStream inStream) throws CertificateException {
        if (inStream != null) {
            try {
                if (inStream.available() != 0) {
                    boolean markable = inStream.markSupported();
                    if (markable) {
                        inStream.mark(PUSHBACK_SIZE);
                    }
                    PushbackInputStream pbis = new PushbackInputStream(inStream, PUSHBACK_SIZE);
                    try {
                        byte[] buffer = new byte[PKCS7_MARKER.length];
                        int len = pbis.read(buffer);
                        if (len < 0) {
                            throw new OpenSSLX509CertificateFactory.ParsingException("inStream is empty");
                        }
                        pbis.unread(buffer, 0, len);
                        if (len != PKCS7_MARKER.length || !Arrays.equals(PKCS7_MARKER, buffer)) {
                            return new OpenSSLX509CertPath(OpenSSLX509Certificate.fromPkcs7DerInputStream(pbis));
                        }
                        return new OpenSSLX509CertPath(OpenSSLX509Certificate.fromPkcs7PemInputStream(pbis));
                    } catch (Exception e) {
                        if (markable) {
                            try {
                                inStream.reset();
                            } catch (IOException e2) {
                            }
                        }
                        throw new CertificateException(e);
                    }
                }
            } catch (IOException e3) {
                throw new CertificateException("Problem reading input stream", e3);
            }
        }
        return new OpenSSLX509CertPath(Collections.emptyList());
    }

    private static CertPath fromEncoding(InputStream inStream, Encoding encoding) throws CertificateException {
        switch (encoding) {
            case PKI_PATH:
                return fromPkiPathEncoding(inStream);
            case PKCS7:
                return fromPkcs7Encoding(inStream);
            default:
                throw new CertificateEncodingException("Unknown encoding");
        }
    }

    static CertPath fromEncoding(InputStream inStream, String encoding) throws CertificateException {
        if (inStream == null) {
            throw new CertificateException("inStream == null");
        }
        Encoding enc = Encoding.findByApiName(encoding);
        if (enc != null) {
            return fromEncoding(inStream, enc);
        }
        throw new CertificateException("Invalid encoding: " + encoding);
    }

    static CertPath fromEncoding(InputStream inStream) throws CertificateException {
        if (inStream != null) {
            return fromEncoding(inStream, DEFAULT_ENCODING);
        }
        throw new CertificateException("inStream == null");
    }
}
