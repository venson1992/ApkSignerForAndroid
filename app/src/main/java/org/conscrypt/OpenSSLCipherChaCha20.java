package org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.conscrypt.OpenSSLCipher;

public class OpenSSLCipherChaCha20 extends OpenSSLCipher {
    static final /* synthetic */ boolean $assertionsDisabled = (!OpenSSLCipherChaCha20.class.desiredAssertionStatus() ? true : $assertionsDisabled);
    private static final int BLOCK_SIZE_BYTES = 64;
    private static final int NONCE_SIZE_BYTES = 12;
    private int blockCounter = 0;
    private int currentBlockConsumedBytes = 0;

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivParams = (IvParameterSpec) params;
            if (ivParams.getIV().length != 12) {
                throw new InvalidAlgorithmParameterException("IV must be 12 bytes long");
            }
            this.iv = ivParams.getIV();
        } else if (!isEncrypting()) {
            throw new InvalidAlgorithmParameterException("IV must be specified when decrypting");
        } else {
            this.iv = new byte[12];
            if (random != null) {
                random.nextBytes(this.iv);
            } else {
                NativeCrypto.RAND_bytes(this.iv);
            }
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, int maximumLen) throws ShortBufferException {
        int inputLenRemaining;
        if (inputLen > output.length - outputOffset) {
            throw new ShortBufferWithoutStackTraceException("Insufficient output space");
        }
        if (this.currentBlockConsumedBytes > 0) {
            int len = Math.min(64 - this.currentBlockConsumedBytes, inputLen);
            byte[] singleBlock = new byte[BLOCK_SIZE_BYTES];
            byte[] singleBlockOut = new byte[BLOCK_SIZE_BYTES];
            System.arraycopy(input, inputOffset, singleBlock, this.currentBlockConsumedBytes, len);
            NativeCrypto.chacha20_encrypt_decrypt(singleBlock, 0, singleBlockOut, 0, BLOCK_SIZE_BYTES, this.encodedKey, this.iv, this.blockCounter);
            System.arraycopy(singleBlockOut, this.currentBlockConsumedBytes, output, outputOffset, len);
            this.currentBlockConsumedBytes += len;
            if (this.currentBlockConsumedBytes < BLOCK_SIZE_BYTES) {
                return len;
            }
            if ($assertionsDisabled || this.currentBlockConsumedBytes == BLOCK_SIZE_BYTES) {
                this.currentBlockConsumedBytes = 0;
                inputOffset += len;
                outputOffset += len;
                inputLenRemaining = inputLen - len;
                this.blockCounter++;
            } else {
                throw new AssertionError();
            }
        } else {
            inputLenRemaining = inputLen;
        }
        NativeCrypto.chacha20_encrypt_decrypt(input, inputOffset, output, outputOffset, inputLenRemaining, this.encodedKey, this.iv, this.blockCounter);
        this.currentBlockConsumedBytes = inputLenRemaining % BLOCK_SIZE_BYTES;
        this.blockCounter += inputLenRemaining / BLOCK_SIZE_BYTES;
        return inputLen;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int doFinalInternal(byte[] output, int outputOffset, int maximumLen) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        reset();
        return 0;
    }

    private void reset() {
        this.blockCounter = 0;
        this.currentBlockConsumedBytes = 0;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public String getBaseCipherName() {
        return "ChaCha20";
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 32) {
            throw new InvalidKeyException("Unsupported key size: " + keySize + " bytes (must be 32)");
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedMode(OpenSSLCipher.Mode mode) throws NoSuchAlgorithmException {
        if (mode != OpenSSLCipher.Mode.NONE) {
            throw new NoSuchAlgorithmException("Mode must be NONE");
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedPadding(OpenSSLCipher.Padding padding) throws NoSuchPaddingException {
        if (padding != OpenSSLCipher.Padding.NOPADDING) {
            throw new NoSuchPaddingException("Must be NoPadding");
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getCipherBlockSize() {
        return 0;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForFinal(int inputLen) {
        return inputLen;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForUpdate(int inputLen) {
        return inputLen;
    }
}
