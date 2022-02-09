package org.conscrypt.ct;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.conscrypt.NativeCrypto;
import org.conscrypt.OpenSSLX509Certificate;
import org.conscrypt.ct.SignedCertificateTimestamp;
import org.conscrypt.ct.VerifiedSCT;

public class CTVerifier {
    private final CTLogStore store;

    public CTVerifier(CTLogStore store2) {
        this.store = store2;
    }

    public CTVerificationResult verifySignedCertificateTimestamps(List<X509Certificate> chain, byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
        OpenSSLX509Certificate[] certs = new OpenSSLX509Certificate[chain.size()];
        int i = 0;
        for (X509Certificate cert : chain) {
            certs[i] = OpenSSLX509Certificate.fromCertificate(cert);
            i++;
        }
        return verifySignedCertificateTimestamps(certs, tlsData, ocspData);
    }

    public CTVerificationResult verifySignedCertificateTimestamps(OpenSSLX509Certificate[] chain, byte[] tlsData, byte[] ocspData) throws CertificateEncodingException {
        if (chain.length == 0) {
            throw new IllegalArgumentException("Chain of certificates mustn't be empty.");
        }
        OpenSSLX509Certificate leaf = chain[0];
        CTVerificationResult result = new CTVerificationResult();
        verifyExternalSCTs(getSCTsFromTLSExtension(tlsData), leaf, result);
        verifyExternalSCTs(getSCTsFromOCSPResponse(ocspData, chain), leaf, result);
        verifyEmbeddedSCTs(getSCTsFromX509Extension(chain[0]), chain, result);
        return result;
    }

    private void verifyEmbeddedSCTs(List<SignedCertificateTimestamp> scts, OpenSSLX509Certificate[] chain, CTVerificationResult result) {
        if (!scts.isEmpty()) {
            CertificateEntry precertEntry = null;
            if (chain.length >= 2) {
                try {
                    precertEntry = CertificateEntry.createForPrecertificate(chain[0], chain[1]);
                } catch (CertificateException e) {
                }
            }
            if (precertEntry == null) {
                markSCTsAsInvalid(scts, result);
                return;
            }
            for (SignedCertificateTimestamp sct : scts) {
                result.add(new VerifiedSCT(sct, verifySingleSCT(sct, precertEntry)));
            }
        }
    }

    private void verifyExternalSCTs(List<SignedCertificateTimestamp> scts, OpenSSLX509Certificate leaf, CTVerificationResult result) {
        if (!scts.isEmpty()) {
            try {
                CertificateEntry x509Entry = CertificateEntry.createForX509Certificate(leaf);
                for (SignedCertificateTimestamp sct : scts) {
                    result.add(new VerifiedSCT(sct, verifySingleSCT(sct, x509Entry)));
                }
            } catch (CertificateException e) {
                markSCTsAsInvalid(scts, result);
            }
        }
    }

    private VerifiedSCT.Status verifySingleSCT(SignedCertificateTimestamp sct, CertificateEntry certEntry) {
        CTLogInfo log = this.store.getKnownLog(sct.getLogID());
        if (log == null) {
            return VerifiedSCT.Status.UNKNOWN_LOG;
        }
        return log.verifySingleSCT(sct, certEntry);
    }

    private void markSCTsAsInvalid(List<SignedCertificateTimestamp> scts, CTVerificationResult result) {
        for (SignedCertificateTimestamp sct : scts) {
            result.add(new VerifiedSCT(sct, VerifiedSCT.Status.INVALID_SCT));
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromSCTList(byte[] data, SignedCertificateTimestamp.Origin origin) {
        if (data == null) {
            return Collections.emptyList();
        }
        try {
            byte[][] sctList = Serialization.readList(data, 2, 2);
            List<SignedCertificateTimestamp> scts = new ArrayList<>();
            for (byte[] encodedSCT : sctList) {
                try {
                    scts.add(SignedCertificateTimestamp.decode(encodedSCT, origin));
                } catch (SerializationException e) {
                }
            }
            return scts;
        } catch (SerializationException e2) {
            return Collections.emptyList();
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromTLSExtension(byte[] data) {
        return getSCTsFromSCTList(data, SignedCertificateTimestamp.Origin.TLS_EXTENSION);
    }

    private List<SignedCertificateTimestamp> getSCTsFromOCSPResponse(byte[] data, OpenSSLX509Certificate[] chain) {
        if (data == null || chain.length < 2) {
            return Collections.emptyList();
        }
        byte[] extData = NativeCrypto.get_ocsp_single_extension(data, CTConstants.OCSP_SCT_LIST_OID, chain[0].getContext(), chain[0], chain[1].getContext(), chain[1]);
        if (extData == null) {
            return Collections.emptyList();
        }
        try {
            return getSCTsFromSCTList(Serialization.readDEROctetString(Serialization.readDEROctetString(extData)), SignedCertificateTimestamp.Origin.OCSP_RESPONSE);
        } catch (SerializationException e) {
            return Collections.emptyList();
        }
    }

    private List<SignedCertificateTimestamp> getSCTsFromX509Extension(OpenSSLX509Certificate leaf) {
        byte[] extData = leaf.getExtensionValue(CTConstants.X509_SCT_LIST_OID);
        if (extData == null) {
            return Collections.emptyList();
        }
        try {
            return getSCTsFromSCTList(Serialization.readDEROctetString(Serialization.readDEROctetString(extData)), SignedCertificateTimestamp.Origin.EMBEDDED);
        } catch (SerializationException e) {
            return Collections.emptyList();
        }
    }
}
