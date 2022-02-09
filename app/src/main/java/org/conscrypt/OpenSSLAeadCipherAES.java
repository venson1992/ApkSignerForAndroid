package org.conscrypt;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.conscrypt.OpenSSLCipher;

public abstract class OpenSSLAeadCipherAES extends OpenSSLAeadCipher {
    private static final int AES_BLOCK_SIZE = 16;

    OpenSSLAeadCipherAES(OpenSSLCipher.Mode mode) {
        super(mode);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
        switch (keyLength) {
            case 16:
            case 32:
                return;
            default:
                throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes (must be 16 or 32)");
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public String getBaseCipherName() {
        return "AES";
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getCipherBlockSize() {
        return 16;
    }

    /* access modifiers changed from: protected */
    @Override // org.conscrypt.OpenSSLCipher
    public AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            return null;
        }
        AlgorithmParameterSpec spec = Platform.fromGCMParameters(params);
        if (spec != null) {
            return spec;
        }
        return super.getParameterSpec(params);
    }

    /* access modifiers changed from: protected */
    @Override // org.conscrypt.OpenSSLCipher
    public AlgorithmParameters engineGetParameters() {
        if (this.iv == null) {
            return null;
        }
        AlgorithmParameterSpec spec = Platform.toGCMParameterSpec(this.tagLengthInBytes * 8, this.iv);
        if (spec == null) {
            return super.engineGetParameters();
        }
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
            params.init(spec);
            return params;
        } catch (NoSuchAlgorithmException e) {
            throw ((Error) new AssertionError("GCM not supported").initCause(e));
        } catch (InvalidParameterSpecException e2) {
            return null;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher, org.conscrypt.OpenSSLAeadCipher
    public int getOutputSizeForFinal(int inputLen) {
        if (isEncrypting()) {
            return this.bufCount + inputLen + this.tagLengthInBytes;
        }
        return Math.max(0, (this.bufCount + inputLen) - this.tagLengthInBytes);
    }

    public static class GCM extends OpenSSLAeadCipherAES {
        public GCM() {
            super(OpenSSLCipher.Mode.GCM);
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLCipher
        public void checkSupportedMode(OpenSSLCipher.Mode mode) throws NoSuchAlgorithmException {
            if (mode != OpenSSLCipher.Mode.GCM) {
                throw new NoSuchAlgorithmException("Mode must be GCM");
            }
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLAeadCipher
        public long getEVP_AEAD(int keyLength) throws InvalidKeyException {
            if (keyLength == 16) {
                return NativeCrypto.EVP_aead_aes_128_gcm();
            }
            if (keyLength == 32) {
                return NativeCrypto.EVP_aead_aes_256_gcm();
            }
            throw new RuntimeException("Unexpected key length: " + keyLength);
        }

        public static class AES_128 extends GCM {
            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.OpenSSLCipher, org.conscrypt.OpenSSLAeadCipherAES
            public void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 16) {
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes (must be 16)");
                }
            }
        }

        public static class AES_256 extends GCM {
            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.OpenSSLCipher, org.conscrypt.OpenSSLAeadCipherAES
            public void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 32) {
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes (must be 32)");
                }
            }
        }
    }

    public static class GCM_SIV extends OpenSSLAeadCipherAES {
        public GCM_SIV() {
            super(OpenSSLCipher.Mode.GCM_SIV);
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLCipher
        public void checkSupportedMode(OpenSSLCipher.Mode mode) throws NoSuchAlgorithmException {
            if (mode != OpenSSLCipher.Mode.GCM_SIV) {
                throw new NoSuchAlgorithmException("Mode must be GCM-SIV");
            }
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLAeadCipher
        public boolean allowsNonceReuse() {
            return true;
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLAeadCipher
        public void checkSupportedTagLength(int tagLengthInBits) throws InvalidAlgorithmParameterException {
            if (tagLengthInBits != 128) {
                throw new InvalidAlgorithmParameterException("Tag length must be 128 bits");
            }
        }

        /* access modifiers changed from: package-private */
        @Override // org.conscrypt.OpenSSLAeadCipher
        public long getEVP_AEAD(int keyLength) throws InvalidKeyException {
            if (keyLength == 16) {
                return NativeCrypto.EVP_aead_aes_128_gcm_siv();
            }
            if (keyLength == 32) {
                return NativeCrypto.EVP_aead_aes_256_gcm_siv();
            }
            throw new RuntimeException("Unexpected key length: " + keyLength);
        }

        public static class AES_128 extends GCM_SIV {
            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.OpenSSLCipher, org.conscrypt.OpenSSLAeadCipherAES
            public void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 16) {
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes (must be 16)");
                }
            }
        }

        public static class AES_256 extends GCM_SIV {
            /* access modifiers changed from: package-private */
            @Override // org.conscrypt.OpenSSLCipher, org.conscrypt.OpenSSLAeadCipherAES
            public void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
                if (keyLength != 32) {
                    throw new InvalidKeyException("Unsupported key size: " + keyLength + " bytes (must be 32)");
                }
            }
        }
    }
}
