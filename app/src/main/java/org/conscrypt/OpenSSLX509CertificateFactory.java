package org.conscrypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class OpenSSLX509CertificateFactory extends CertificateFactorySpi {
    private static final byte[] PKCS7_MARKER = {45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80, 75, 67, 83, 55};
    private static final int PUSHBACK_SIZE = 64;
    private Parser<OpenSSLX509Certificate> certificateParser = new Parser<OpenSSLX509Certificate>() {
        /* class org.conscrypt.OpenSSLX509CertificateFactory.AnonymousClass1 */

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public OpenSSLX509Certificate fromX509PemInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509Certificate.fromX509PemInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public OpenSSLX509Certificate fromX509DerInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509Certificate.fromX509DerInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public List<? extends OpenSSLX509Certificate> fromPkcs7PemInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509Certificate.fromPkcs7PemInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public List<? extends OpenSSLX509Certificate> fromPkcs7DerInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509Certificate.fromPkcs7DerInputStream(is);
        }
    };
    private Parser<OpenSSLX509CRL> crlParser = new Parser<OpenSSLX509CRL>() {
        /* class org.conscrypt.OpenSSLX509CertificateFactory.AnonymousClass2 */

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public OpenSSLX509CRL fromX509PemInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509CRL.fromX509PemInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public OpenSSLX509CRL fromX509DerInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509CRL.fromX509DerInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public List<? extends OpenSSLX509CRL> fromPkcs7PemInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509CRL.fromPkcs7PemInputStream(is);
        }

        @Override // org.conscrypt.OpenSSLX509CertificateFactory.Parser
        public List<? extends OpenSSLX509CRL> fromPkcs7DerInputStream(InputStream is) throws ParsingException {
            return OpenSSLX509CRL.fromPkcs7DerInputStream(is);
        }
    };

    /* access modifiers changed from: package-private */
    public static class ParsingException extends Exception {
        private static final long serialVersionUID = 8390802697728301325L;

        ParsingException(String message) {
            super(message);
        }

        ParsingException(Exception cause) {
            super(cause);
        }

        ParsingException(String message, Exception cause) {
            super(message, cause);
        }
    }

    private static abstract class Parser<T> {
        /* access modifiers changed from: protected */
        public abstract List<? extends T> fromPkcs7DerInputStream(InputStream inputStream) throws ParsingException;

        /* access modifiers changed from: protected */
        public abstract List<? extends T> fromPkcs7PemInputStream(InputStream inputStream) throws ParsingException;

        /* access modifiers changed from: protected */
        public abstract T fromX509DerInputStream(InputStream inputStream) throws ParsingException;

        /* access modifiers changed from: protected */
        public abstract T fromX509PemInputStream(InputStream inputStream) throws ParsingException;

        private Parser() {
        }

        /* access modifiers changed from: package-private */
        public T generateItem(InputStream inStream) throws ParsingException {
            if (inStream == null) {
                throw new ParsingException("inStream == null");
            }
            boolean markable = inStream.markSupported();
            if (markable) {
                inStream.mark(OpenSSLX509CertificateFactory.PKCS7_MARKER.length);
            }
            PushbackInputStream pbis = new PushbackInputStream(inStream, OpenSSLX509CertificateFactory.PUSHBACK_SIZE);
            try {
                byte[] buffer = new byte[OpenSSLX509CertificateFactory.PKCS7_MARKER.length];
                int len = pbis.read(buffer);
                if (len < 0) {
                    throw new ParsingException("inStream is empty");
                }
                pbis.unread(buffer, 0, len);
                if (buffer[0] == 45) {
                    if (len != OpenSSLX509CertificateFactory.PKCS7_MARKER.length || !Arrays.equals(OpenSSLX509CertificateFactory.PKCS7_MARKER, buffer)) {
                        return fromX509PemInputStream(pbis);
                    }
                    List<? extends T> items = fromPkcs7PemInputStream(pbis);
                    if (items.size() == 0) {
                        return null;
                    }
                    items.get(0);
                }
                if (buffer[4] != 6) {
                    return fromX509DerInputStream(pbis);
                }
                List<? extends T> certs = fromPkcs7DerInputStream(pbis);
                if (certs.size() != 0) {
                    return (T) certs.get(0);
                }
                return null;
            } catch (Exception e) {
                if (markable) {
                    try {
                        inStream.reset();
                    } catch (IOException e2) {
                    }
                }
                throw new ParsingException(e);
            }
        }

        /* access modifiers changed from: package-private */
        public Collection<? extends T> generateItems(InputStream inStream) throws ParsingException {
            T c;
            if (inStream == null) {
                throw new ParsingException("inStream == null");
            }
            try {
                if (inStream.available() == 0) {
                    return new ArrayList();
                }
                boolean markable = inStream.markSupported();
                if (markable) {
                    inStream.mark(OpenSSLX509CertificateFactory.PUSHBACK_SIZE);
                }
                PushbackInputStream pbis = new PushbackInputStream(inStream, OpenSSLX509CertificateFactory.PUSHBACK_SIZE);
                try {
                    byte[] buffer = new byte[OpenSSLX509CertificateFactory.PKCS7_MARKER.length];
                    int len = pbis.read(buffer);
                    if (len < 0) {
                        throw new ParsingException("inStream is empty");
                    }
                    pbis.unread(buffer, 0, len);
                    if (len == OpenSSLX509CertificateFactory.PKCS7_MARKER.length && Arrays.equals(OpenSSLX509CertificateFactory.PKCS7_MARKER, buffer)) {
                        return fromPkcs7PemInputStream(pbis);
                    }
                    if (buffer[4] == 6) {
                        return fromPkcs7DerInputStream(pbis);
                    }
                    List<T> coll = new ArrayList<>();
                    do {
                        if (markable) {
                            inStream.mark(OpenSSLX509CertificateFactory.PUSHBACK_SIZE);
                        }
                        try {
                            c = generateItem(pbis);
                            coll.add(c);
                            continue;
                        } catch (ParsingException e) {
                            if (markable) {
                                try {
                                    inStream.reset();
                                } catch (IOException e2) {
                                }
                            }
                            c = null;
                            continue;
                        }
                    } while (c != null);
                    return coll;
                } catch (Exception e3) {
                    if (markable) {
                        try {
                            inStream.reset();
                        } catch (IOException e4) {
                        }
                    }
                    throw new ParsingException(e3);
                }
            } catch (IOException e5) {
                throw new ParsingException("Problem reading input stream", e5);
            }
        }
    }

    @Override // java.security.cert.CertificateFactorySpi
    public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
        try {
            return this.certificateParser.generateItem(inStream);
        } catch (ParsingException e) {
            throw new CertificateException(e);
        }
    }

    @Override // java.security.cert.CertificateFactorySpi
    public Collection<? extends Certificate> engineGenerateCertificates(InputStream inStream) throws CertificateException {
        try {
            return this.certificateParser.generateItems(inStream);
        } catch (ParsingException e) {
            throw new CertificateException(e);
        }
    }

    @Override // java.security.cert.CertificateFactorySpi
    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        try {
            return this.crlParser.generateItem(inStream);
        } catch (ParsingException e) {
            throw new CRLException(e);
        }
    }

    @Override // java.security.cert.CertificateFactorySpi
    public Collection<? extends CRL> engineGenerateCRLs(InputStream inStream) throws CRLException {
        if (inStream == null) {
            return Collections.emptyList();
        }
        try {
            return this.crlParser.generateItems(inStream);
        } catch (ParsingException e) {
            throw new CRLException(e);
        }
    }

    @Override // java.security.cert.CertificateFactorySpi
    public Iterator<String> engineGetCertPathEncodings() {
        return OpenSSLX509CertPath.getEncodingsIterator();
    }

    @Override // java.security.cert.CertificateFactorySpi
    public CertPath engineGenerateCertPath(InputStream inStream) throws CertificateException {
        return OpenSSLX509CertPath.fromEncoding(inStream);
    }

    @Override // java.security.cert.CertificateFactorySpi
    public CertPath engineGenerateCertPath(InputStream inStream, String encoding) throws CertificateException {
        return OpenSSLX509CertPath.fromEncoding(inStream, encoding);
    }

    @Override // java.security.cert.CertificateFactorySpi
    public CertPath engineGenerateCertPath(List<? extends Certificate> certificates) throws CertificateException {
        List<X509Certificate> filtered = new ArrayList<>(certificates.size());
        for (int i = 0; i < certificates.size(); i++) {
            Certificate c = (Certificate) certificates.get(i);
            if (!(c instanceof X509Certificate)) {
                throw new CertificateException("Certificate not X.509 type at index " + i);
            }
            filtered.add((X509Certificate) c);
        }
        return new OpenSSLX509CertPath(filtered);
    }
}
