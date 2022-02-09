package com.android.apksig.internal.util;

import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.asn1.Asn1DerEncoder;
import com.android.apksig.internal.asn1.Asn1EncodingException;
import com.android.apksig.internal.x509.Certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;

public class X509CertificateUtils {
    public static final byte[] BEGIN_CERT_HEADER = "-----BEGIN CERTIFICATE-----".getBytes();
    public static final byte[] END_CERT_FOOTER = "-----END CERTIFICATE-----".getBytes();
    private static CertificateFactory sCertFactory = null;

    private static void buildCertFactory() {
        if (sCertFactory == null) {
            try {
                sCertFactory = CertificateFactory.getInstance("X.509");
            } catch (CertificateException e) {
                throw new RuntimeException("Failed to create X.509 CertificateFactory", e);
            }
        }
    }

    public static X509Certificate generateCertificate(InputStream in) throws CertificateException {
        try {
            return generateCertificate(ByteStreams.toByteArray(in));
        } catch (IOException e) {
            throw new CertificateException("Failed to parse certificate", e);
        }
    }

    public static X509Certificate generateCertificate(byte[] encodedForm) throws CertificateException {
        if (sCertFactory == null) {
            buildCertFactory();
        }
        return generateCertificate(encodedForm, sCertFactory);
    }

    public static X509Certificate generateCertificate(byte[] encodedForm, CertificateFactory certFactory) throws CertificateException {
        try {
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(encodedForm));
        } catch (CertificateException e) {
            try {
                ByteBuffer encodedCertBuffer = getNextDEREncodedCertificateBlock(ByteBuffer.wrap(encodedForm));
                int startingPos = encodedCertBuffer.position();
                byte[] originalEncoding = new byte[(encodedCertBuffer.position() - startingPos)];
                encodedCertBuffer.position(startingPos);
                encodedCertBuffer.get(originalEncoding);
                return new GuaranteedEncodedFormX509Certificate((X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Asn1DerEncoder.encode((Certificate) Asn1BerParser.parse(encodedCertBuffer, Certificate.class)))), originalEncoding);
            } catch (Asn1DecodingException | Asn1EncodingException | CertificateException e2) {
                throw new CertificateException("Failed to parse certificate", e2);
            }
        }
    }

    public static Collection<? extends java.security.cert.Certificate> generateCertificates(InputStream in) throws CertificateException {
        if (sCertFactory == null) {
            buildCertFactory();
        }
        return generateCertificates(in, sCertFactory);
    }

    public static Collection<? extends java.security.cert.Certificate> generateCertificates(InputStream in, CertificateFactory certFactory) throws CertificateException {
        try {
            byte[] encodedCerts = ByteStreams.toByteArray(in);
            try {
                return certFactory.generateCertificates(new ByteArrayInputStream(encodedCerts));
            } catch (CertificateException e) {
                try {
                    Collection<X509Certificate> certificates = new ArrayList<>(1);
                    ByteBuffer encodedCertsBuffer = ByteBuffer.wrap(encodedCerts);
                    while (encodedCertsBuffer.hasRemaining()) {
                        ByteBuffer certBuffer = getNextDEREncodedCertificateBlock(encodedCertsBuffer);
                        int startingPos = certBuffer.position();
                        byte[] originalEncoding = new byte[(certBuffer.position() - startingPos)];
                        certBuffer.position(startingPos);
                        certBuffer.get(originalEncoding);
                        certificates.add(new GuaranteedEncodedFormX509Certificate((X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(Asn1DerEncoder.encode((Certificate) Asn1BerParser.parse(certBuffer, Certificate.class)))), originalEncoding));
                    }
                    return certificates;
                } catch (Asn1DecodingException | Asn1EncodingException e2) {
                    throw new CertificateException("Failed to parse certificates", e2);
                }
            }
        } catch (IOException e3) {
            throw new CertificateException("Failed to read the input stream", e3);
        }
    }

    private static ByteBuffer getNextDEREncodedCertificateBlock(ByteBuffer certificateBuffer) throws CertificateException {
        char encodedChar;
        if (certificateBuffer == null) {
            throw new NullPointerException("The certificateBuffer cannot be null");
        } else if (certificateBuffer.remaining() < BEGIN_CERT_HEADER.length) {
            return certificateBuffer;
        } else {
            certificateBuffer.mark();
            for (int i = 0; i < BEGIN_CERT_HEADER.length; i++) {
                if (certificateBuffer.get() != BEGIN_CERT_HEADER[i]) {
                    certificateBuffer.reset();
                    return certificateBuffer;
                }
            }
            StringBuilder pemEncoding = new StringBuilder();
            while (certificateBuffer.hasRemaining() && (encodedChar = (char) certificateBuffer.get()) != '-') {
                if (!Character.isWhitespace(encodedChar)) {
                    pemEncoding.append(encodedChar);
                }
            }
            for (int i2 = 1; i2 < END_CERT_FOOTER.length; i2++) {
                if (!certificateBuffer.hasRemaining()) {
                    throw new CertificateException("The provided input contains the PEM certificate header but does not contain sufficient data for the footer");
                } else if (certificateBuffer.get() != END_CERT_FOOTER[i2]) {
                    throw new CertificateException("The provided input contains the PEM certificate header without a valid certificate footer");
                }
            }
            byte[] derEncoding = Base64.getDecoder().decode(pemEncoding.toString());
            int nextEncodedChar = certificateBuffer.position();
            while (certificateBuffer.hasRemaining() && Character.isWhitespace((char) certificateBuffer.get())) {
                nextEncodedChar++;
            }
            certificateBuffer.position(nextEncodedChar);
            return ByteBuffer.wrap(derEncoding);
        }
    }
}
