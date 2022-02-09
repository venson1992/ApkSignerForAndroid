package org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.conscrypt.NativeRef;
import org.conscrypt.OpenSSLCipher;

public abstract class OpenSSLEvpCipher extends OpenSSLCipher {
    private boolean calledUpdate;
    private final NativeRef.EVP_CIPHER_CTX cipherCtx = new NativeRef.EVP_CIPHER_CTX(NativeCrypto.EVP_CIPHER_CTX_new());
    private int modeBlockSize;

    /* access modifiers changed from: package-private */
    public abstract String getCipherName(int i, OpenSSLCipher.Mode mode);

    public OpenSSLEvpCipher(OpenSSLCipher.Mode mode, OpenSSLCipher.Padding padding) {
        super(mode, padding);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] iv;
        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
        } else {
            iv = null;
        }
        long cipherType = NativeCrypto.EVP_get_cipherbyname(getCipherName(encodedKey.length, this.mode));
        if (cipherType == 0) {
            throw new InvalidAlgorithmParameterException("Cannot find name for key length = " + (encodedKey.length * 8) + " and mode = " + this.mode);
        }
        boolean encrypting = isEncrypting();
        int expectedIvLength = NativeCrypto.EVP_CIPHER_iv_length(cipherType);
        if (iv != null || expectedIvLength == 0) {
            if (expectedIvLength == 0 && iv != null) {
                throw new InvalidAlgorithmParameterException("IV not used in " + this.mode + " mode");
            } else if (!(iv == null || iv.length == expectedIvLength)) {
                throw new InvalidAlgorithmParameterException("expected IV length of " + expectedIvLength + " but was " + iv.length);
            }
        } else if (!encrypting) {
            throw new InvalidAlgorithmParameterException("IV must be specified in " + this.mode + " mode");
        } else {
            iv = new byte[expectedIvLength];
            if (random != null) {
                random.nextBytes(iv);
            } else {
                NativeCrypto.RAND_bytes(iv);
            }
        }
        this.iv = iv;
        if (supportsVariableSizeKey()) {
            NativeCrypto.EVP_CipherInit_ex(this.cipherCtx, cipherType, null, null, encrypting);
            NativeCrypto.EVP_CIPHER_CTX_set_key_length(this.cipherCtx, encodedKey.length);
            NativeCrypto.EVP_CipherInit_ex(this.cipherCtx, 0, encodedKey, iv, isEncrypting());
        } else {
            NativeCrypto.EVP_CipherInit_ex(this.cipherCtx, cipherType, encodedKey, iv, encrypting);
        }
        NativeCrypto.EVP_CIPHER_CTX_set_padding(this.cipherCtx, getPadding() == OpenSSLCipher.Padding.PKCS5PADDING);
        this.modeBlockSize = NativeCrypto.EVP_CIPHER_CTX_block_size(this.cipherCtx);
        this.calledUpdate = false;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, int maximumLen) throws ShortBufferException {
        int bytesLeft = output.length - outputOffset;
        if (bytesLeft < maximumLen) {
            throw new ShortBufferWithoutStackTraceException("output buffer too small during update: " + bytesLeft + " < " + maximumLen);
        }
        this.calledUpdate = true;
        return (outputOffset + NativeCrypto.EVP_CipherUpdate(this.cipherCtx, output, outputOffset, input, inputOffset, inputLen)) - outputOffset;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int doFinalInternal(byte[] output, int outputOffset, int maximumLen) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        int writtenBytes;
        if (!isEncrypting() && !this.calledUpdate) {
            return 0;
        }
        int bytesLeft = output.length - outputOffset;
        if (bytesLeft >= maximumLen) {
            writtenBytes = NativeCrypto.EVP_CipherFinal_ex(this.cipherCtx, output, outputOffset);
        } else {
            byte[] lastBlock = new byte[maximumLen];
            writtenBytes = NativeCrypto.EVP_CipherFinal_ex(this.cipherCtx, lastBlock, 0);
            if (writtenBytes > bytesLeft) {
                throw new ShortBufferWithoutStackTraceException("buffer is too short: " + writtenBytes + " > " + bytesLeft);
            } else if (writtenBytes > 0) {
                System.arraycopy(lastBlock, 0, output, outputOffset, writtenBytes);
            }
        }
        reset();
        return (outputOffset + writtenBytes) - outputOffset;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForFinal(int inputLen) {
        int i;
        int i2 = 0;
        if (this.modeBlockSize == 1) {
            return inputLen;
        }
        int buffered = NativeCrypto.get_EVP_CIPHER_CTX_buf_len(this.cipherCtx);
        if (getPadding() == OpenSSLCipher.Padding.NOPADDING) {
            return inputLen + buffered;
        }
        int i3 = inputLen + buffered;
        if (NativeCrypto.get_EVP_CIPHER_CTX_final_used(this.cipherCtx)) {
            i = this.modeBlockSize;
        } else {
            i = 0;
        }
        int totalLen = i3 + i;
        if (totalLen % this.modeBlockSize != 0 || isEncrypting()) {
            i2 = this.modeBlockSize;
        }
        int totalLen2 = totalLen + i2;
        return totalLen2 - (totalLen2 % this.modeBlockSize);
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForUpdate(int inputLen) {
        return getOutputSizeForFinal(inputLen);
    }

    private void reset() {
        NativeCrypto.EVP_CipherInit_ex(this.cipherCtx, 0, this.encodedKey, this.iv, isEncrypting());
        this.calledUpdate = false;
    }
}
