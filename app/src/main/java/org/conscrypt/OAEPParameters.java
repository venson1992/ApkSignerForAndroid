package org.conscrypt;

import com.android.apksig.internal.oid.OidConstants;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class OAEPParameters extends AlgorithmParametersSpi {
    private static final String MGF1_OID = "1.2.840.113549.1.1.8";
    private static final Map<String, String> NAME_TO_OID = new HashMap();
    private static final Map<String, String> OID_TO_NAME = new HashMap();
    private static final String PSPECIFIED_OID = "1.2.840.113549.1.1.9";
    private OAEPParameterSpec spec = OAEPParameterSpec.DEFAULT;

    static {
        OID_TO_NAME.put(OidConstants.OID_DIGEST_SHA1, "SHA-1");
        OID_TO_NAME.put(OidConstants.OID_DIGEST_SHA224, "SHA-224");
        OID_TO_NAME.put(OidConstants.OID_DIGEST_SHA256, "SHA-256");
        OID_TO_NAME.put(OidConstants.OID_DIGEST_SHA384, "SHA-384");
        OID_TO_NAME.put(OidConstants.OID_DIGEST_SHA512, "SHA-512");
        for (Map.Entry<String, String> entry : OID_TO_NAME.entrySet()) {
            NAME_TO_OID.put(entry.getValue(), entry.getKey());
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof OAEPParameterSpec) {
            this.spec = (OAEPParameterSpec) algorithmParameterSpec;
            return;
        }
        throw new InvalidParameterSpecException("Only OAEPParameterSpec is supported");
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes) throws IOException {
        Throwable th;
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            PSource.PSpecified pSpecified = PSource.PSpecified.DEFAULT;
            String hash = readHash(seqRef);
            String mgfHash = readMgfHash(seqRef);
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 2)) {
                long pSourceRef = 0;
                long pSourceSeqRef = 0;
                try {
                    pSourceRef = NativeCrypto.asn1_read_tagged(seqRef);
                    pSourceSeqRef = NativeCrypto.asn1_read_sequence(pSourceRef);
                    if (!NativeCrypto.asn1_read_oid(pSourceSeqRef).equals(PSPECIFIED_OID)) {
                        throw new IOException("Error reading ASN.1 encoding");
                    }
                    PSource.PSpecified pSpecified2 = new PSource.PSpecified(NativeCrypto.asn1_read_octetstring(pSourceSeqRef));
                    try {
                        if (!NativeCrypto.asn1_read_is_empty(pSourceSeqRef)) {
                            throw new IOException("Error reading ASN.1 encoding");
                        }
                        NativeCrypto.asn1_read_free(pSourceSeqRef);
                        NativeCrypto.asn1_read_free(pSourceRef);
                        pSpecified = pSpecified2;
                    } catch (Throwable th2) {
                        th = th2;
                        NativeCrypto.asn1_read_free(pSourceSeqRef);
                        NativeCrypto.asn1_read_free(pSourceRef);
                        throw th;
                    }
                } catch (Throwable th3) {
                    th = th3;
                    NativeCrypto.asn1_read_free(pSourceSeqRef);
                    NativeCrypto.asn1_read_free(pSourceRef);
                    throw th;
                }
            }
            if (!NativeCrypto.asn1_read_is_empty(seqRef) || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.spec = new OAEPParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash), pSpecified);
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        } catch (Throwable th4) {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
            throw th4;
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            engineInit(bytes);
            return;
        }
        throw new IOException("Unsupported format: " + format);
    }

    static String readHash(long seqRef) throws IOException {
        if (!NativeCrypto.asn1_read_next_tag_is(seqRef, 0)) {
            return "SHA-1";
        }
        long hashRef = 0;
        try {
            hashRef = NativeCrypto.asn1_read_tagged(seqRef);
            return getHashName(hashRef);
        } finally {
            NativeCrypto.asn1_read_free(hashRef);
        }
    }

    static String readMgfHash(long seqRef) throws IOException {
        if (!NativeCrypto.asn1_read_next_tag_is(seqRef, 1)) {
            return "SHA-1";
        }
        long mgfRef = 0;
        long mgfSeqRef = 0;
        try {
            mgfRef = NativeCrypto.asn1_read_tagged(seqRef);
            mgfSeqRef = NativeCrypto.asn1_read_sequence(mgfRef);
            if (!NativeCrypto.asn1_read_oid(mgfSeqRef).equals(MGF1_OID)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            String mgfHash = getHashName(mgfSeqRef);
            if (NativeCrypto.asn1_read_is_empty(mgfSeqRef)) {
                return mgfHash;
            }
            throw new IOException("Error reading ASN.1 encoding");
        } finally {
            NativeCrypto.asn1_read_free(mgfSeqRef);
            NativeCrypto.asn1_read_free(mgfRef);
        }
    }

    private static String getHashName(long hashRef) throws IOException {
        long hashSeqRef = 0;
        try {
            hashSeqRef = NativeCrypto.asn1_read_sequence(hashRef);
            String hashOid = NativeCrypto.asn1_read_oid(hashSeqRef);
            if (!NativeCrypto.asn1_read_is_empty(hashSeqRef)) {
                NativeCrypto.asn1_read_null(hashSeqRef);
            }
            if (!NativeCrypto.asn1_read_is_empty(hashSeqRef) || !OID_TO_NAME.containsKey(hashOid)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            return OID_TO_NAME.get(hashOid);
        } finally {
            NativeCrypto.asn1_read_free(hashSeqRef);
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass) throws InvalidParameterSpecException {
        if (aClass != null && aClass == OAEPParameterSpec.class) {
            return this.spec;
        }
        throw new InvalidParameterSpecException("Unsupported class: " + aClass);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        long seqRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbbRef);
            writeHashAndMgfHash(seqRef, this.spec.getDigestAlgorithm(), (MGF1ParameterSpec) this.spec.getMGFParameters());
            PSource.PSpecified pSource = (PSource.PSpecified) this.spec.getPSource();
            if (pSource.getValue().length != 0) {
                long pSourceRef = 0;
                long pSourceParamsRef = 0;
                try {
                    pSourceRef = NativeCrypto.asn1_write_tag(seqRef, 2);
                    pSourceParamsRef = writeAlgorithmIdentifier(pSourceRef, PSPECIFIED_OID);
                    NativeCrypto.asn1_write_octetstring(pSourceParamsRef, pSource.getValue());
                } finally {
                    NativeCrypto.asn1_write_flush(seqRef);
                    NativeCrypto.asn1_write_free(pSourceParamsRef);
                    NativeCrypto.asn1_write_free(pSourceRef);
                }
            }
            byte[] asn1_write_finish = NativeCrypto.asn1_write_finish(cbbRef);
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbbRef);
            return asn1_write_finish;
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } catch (Throwable th) {
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbbRef);
            throw th;
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public byte[] engineGetEncoded(String format) throws IOException {
        if (format == null || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    static void writeHashAndMgfHash(long seqRef, String hash, MGF1ParameterSpec mgfSpec) throws IOException {
        if (!hash.equals("SHA-1")) {
            long hashRef = 0;
            long hashParamsRef = 0;
            try {
                hashRef = NativeCrypto.asn1_write_tag(seqRef, 0);
                hashParamsRef = writeAlgorithmIdentifier(hashRef, NAME_TO_OID.get(hash));
                NativeCrypto.asn1_write_null(hashParamsRef);
            } finally {
                NativeCrypto.asn1_write_flush(seqRef);
                NativeCrypto.asn1_write_free(hashParamsRef);
                NativeCrypto.asn1_write_free(hashRef);
            }
        }
        if (!mgfSpec.getDigestAlgorithm().equals("SHA-1")) {
            long mgfRef = 0;
            long mgfParamsRef = 0;
            long hashParamsRef2 = 0;
            try {
                mgfRef = NativeCrypto.asn1_write_tag(seqRef, 1);
                mgfParamsRef = writeAlgorithmIdentifier(mgfRef, MGF1_OID);
                hashParamsRef2 = writeAlgorithmIdentifier(mgfParamsRef, NAME_TO_OID.get(mgfSpec.getDigestAlgorithm()));
                NativeCrypto.asn1_write_null(hashParamsRef2);
            } finally {
                NativeCrypto.asn1_write_flush(seqRef);
                NativeCrypto.asn1_write_free(hashParamsRef2);
                NativeCrypto.asn1_write_free(mgfParamsRef);
                NativeCrypto.asn1_write_free(mgfRef);
            }
        }
    }

    private static long writeAlgorithmIdentifier(long container, String oid) throws IOException {
        long seqRef = 0;
        try {
            seqRef = NativeCrypto.asn1_write_sequence(container);
            NativeCrypto.asn1_write_oid(seqRef, oid);
            return seqRef;
        } catch (IOException e) {
            NativeCrypto.asn1_write_free(seqRef);
            throw e;
        }
    }

    /* access modifiers changed from: protected */
    public String engineToString() {
        return "Conscrypt OAEP AlgorithmParameters";
    }
}
