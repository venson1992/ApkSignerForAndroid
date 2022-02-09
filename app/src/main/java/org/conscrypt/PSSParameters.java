package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class PSSParameters extends AlgorithmParametersSpi {
    private PSSParameterSpec spec = PSSParameterSpec.DEFAULT;

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof PSSParameterSpec) {
            this.spec = (PSSParameterSpec) algorithmParameterSpec;
            return;
        }
        throw new InvalidParameterSpecException("Only PSSParameterSpec is supported");
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            int saltLength = 20;
            String hash = OAEPParameters.readHash(seqRef);
            String mgfHash = OAEPParameters.readMgfHash(seqRef);
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 2)) {
                long saltRef = 0;
                try {
                    saltRef = NativeCrypto.asn1_read_tagged(seqRef);
                    saltLength = (int) NativeCrypto.asn1_read_uint64(saltRef);
                } finally {
                    NativeCrypto.asn1_read_free(saltRef);
                }
            }
            if (NativeCrypto.asn1_read_next_tag_is(seqRef, 3)) {
                long trailerRef = 0;
                try {
                    trailerRef = NativeCrypto.asn1_read_tagged(seqRef);
                    NativeCrypto.asn1_read_free(trailerRef);
                    if (((long) ((int) NativeCrypto.asn1_read_uint64(trailerRef))) != 1) {
                        throw new IOException("Error reading ASN.1 encoding");
                    }
                } catch (Throwable th) {
                    NativeCrypto.asn1_read_free(trailerRef);
                    throw th;
                }
            }
            if (!NativeCrypto.asn1_read_is_empty(seqRef) || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.spec = new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgfHash), saltLength, 1);
        } finally {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public void engineInit(byte[] bytes, String format) throws IOException {
        if (format == null || format.equals("ASN.1") || format.equals("X.509")) {
            engineInit(bytes);
            return;
        }
        throw new IOException("Unsupported format: " + format);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.AlgorithmParametersSpi
    public <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass) throws InvalidParameterSpecException {
        if (aClass != null && aClass == PSSParameterSpec.class) {
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
            OAEPParameters.writeHashAndMgfHash(seqRef, this.spec.getDigestAlgorithm(), (MGF1ParameterSpec) this.spec.getMGFParameters());
            if (this.spec.getSaltLength() != 20) {
                long tagRef = 0;
                try {
                    tagRef = NativeCrypto.asn1_write_tag(seqRef, 2);
                    NativeCrypto.asn1_write_uint64(tagRef, (long) this.spec.getSaltLength());
                } finally {
                    NativeCrypto.asn1_write_flush(seqRef);
                    NativeCrypto.asn1_write_free(tagRef);
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
        if (format == null || format.equals("ASN.1") || format.equals("X.509")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    /* access modifiers changed from: protected */
    public String engineToString() {
        return "Conscrypt PSS AlgorithmParameters";
    }
}
