package org.conscrypt;

import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.conscrypt.OpenSSLCipher;

public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
    static final int DEFAULT_TAG_SIZE_BITS = 128;
    private static int lastGlobalMessageSize = 32;
    private byte[] aad;
    byte[] buf;
    int bufCount;
    long evpAead;
    private boolean mustInitialize;
    private byte[] previousIv;
    private byte[] previousKey;
    int tagLengthInBytes;

    /* access modifiers changed from: package-private */
    public abstract long getEVP_AEAD(int i) throws InvalidKeyException;

    public OpenSSLAeadCipher(OpenSSLCipher.Mode mode) {
        super(mode, OpenSSLCipher.Padding.NOPADDING);
    }

    private void checkInitialization() {
        if (this.mustInitialize) {
            throw new IllegalStateException("Cannot re-use same key and IV for multiple encryptions");
        }
    }

    private boolean arraysAreEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        if (diff == 0) {
            return true;
        }
        return false;
    }

    private void expand(int i) {
        if (this.bufCount + i > this.buf.length) {
            byte[] newbuf = new byte[((this.bufCount + i) * 2)];
            System.arraycopy(this.buf, 0, newbuf, 0, this.bufCount);
            this.buf = newbuf;
        }
    }

    private void reset() {
        this.aad = null;
        int lastBufSize = lastGlobalMessageSize;
        if (this.buf == null) {
            this.buf = new byte[lastBufSize];
        } else if (this.bufCount > 0 && this.bufCount != lastBufSize) {
            lastGlobalMessageSize = this.bufCount;
            if (this.buf.length != this.bufCount) {
                this.buf = new byte[this.bufCount];
            }
        }
        this.bufCount = 0;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] iv;
        int tagLenBits;
        if (params == null) {
            iv = null;
            tagLenBits = 128;
        } else {
            GCMParameters gcmParams = Platform.fromGCMParameterSpec(params);
            if (gcmParams != null) {
                iv = gcmParams.getIV();
                tagLenBits = gcmParams.getTLen();
            } else if (params instanceof IvParameterSpec) {
                iv = ((IvParameterSpec) params).getIV();
                tagLenBits = 128;
            } else {
                iv = null;
                tagLenBits = 128;
            }
        }
        checkSupportedTagLength(tagLenBits);
        this.tagLengthInBytes = tagLenBits / 8;
        boolean encrypting = isEncrypting();
        this.evpAead = getEVP_AEAD(encodedKey.length);
        int expectedIvLength = NativeCrypto.EVP_AEAD_nonce_length(this.evpAead);
        if (iv != null || expectedIvLength == 0) {
            if (expectedIvLength == 0 && iv != null) {
                throw new InvalidAlgorithmParameterException("IV not used in " + this.mode + " mode");
            } else if (!(iv == null || iv.length == expectedIvLength)) {
                throw new InvalidAlgorithmParameterException("Expected IV length of " + expectedIvLength + " but was " + iv.length);
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
        if (isEncrypting() && iv != null && !allowsNonceReuse()) {
            if (this.previousKey == null || this.previousIv == null || !arraysAreEqual(this.previousKey, encodedKey) || !arraysAreEqual(this.previousIv, iv)) {
                this.previousKey = encodedKey;
                this.previousIv = iv;
            } else {
                this.mustInitialize = true;
                throw new InvalidAlgorithmParameterException("When using AEAD key and IV must not be re-used");
            }
        }
        this.mustInitialize = false;
        this.iv = iv;
        reset();
    }

    /* access modifiers changed from: package-private */
    public void checkSupportedTagLength(int tagLenBits) throws InvalidAlgorithmParameterException {
        if (tagLenBits % 8 != 0) {
            throw new InvalidAlgorithmParameterException("Tag length must be a multiple of 8; was " + tagLenBits);
        }
    }

    /* access modifiers changed from: package-private */
    public boolean allowsNonceReuse() {
        return false;
    }

    /* access modifiers changed from: protected */
    @Override // org.conscrypt.OpenSSLCipher, javax.crypto.CipherSpi
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        if (output == null || getOutputSizeForFinal(inputLen) <= output.length - outputOffset) {
            return super.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
        }
        throw new ShortBufferWithoutStackTraceException("Insufficient output space");
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset, int maximumLen) throws ShortBufferException {
        checkInitialization();
        if (this.buf == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        ArrayUtils.checkOffsetAndCount(input.length, inputOffset, inputLen);
        if (inputLen <= 0) {
            return 0;
        }
        expand(inputLen);
        System.arraycopy(input, inputOffset, this.buf, this.bufCount, inputLen);
        this.bufCount += inputLen;
        return 0;
    }

    private void throwAEADBadTagExceptionIfAvailable(String message, Throwable cause) throws BadPaddingException {
        try {
            BadPaddingException badTagException = null;
            try {
                badTagException = (BadPaddingException) Class.forName("javax.crypto.AEADBadTagException").getConstructor(String.class).newInstance(message);
                badTagException.initCause(cause);
            } catch (IllegalAccessException | InstantiationException e) {
            } catch (InvocationTargetException e2) {
                throw ((BadPaddingException) new BadPaddingException().initCause(e2.getTargetException()));
            }
            if (badTagException != null) {
                throw badTagException;
            }
        } catch (Exception e3) {
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int doFinalInternal(byte[] output, int outputOffset, int maximumLen) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int bytesWritten;
        checkInitialization();
        try {
            if (isEncrypting()) {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_seal(this.evpAead, this.encodedKey, this.tagLengthInBytes, output, outputOffset, this.iv, this.buf, 0, this.bufCount, this.aad);
            } else {
                bytesWritten = NativeCrypto.EVP_AEAD_CTX_open(this.evpAead, this.encodedKey, this.tagLengthInBytes, output, outputOffset, this.iv, this.buf, 0, this.bufCount, this.aad);
            }
            if (isEncrypting()) {
                this.mustInitialize = true;
            }
            reset();
            return bytesWritten;
        } catch (BadPaddingException e) {
            throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
            throw e;
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public void checkSupportedPadding(OpenSSLCipher.Padding padding) throws NoSuchPaddingException {
        if (padding != OpenSSLCipher.Padding.NOPADDING) {
            throw new NoSuchPaddingException("Must be NoPadding for AEAD ciphers");
        }
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForUpdate(int inputLen) {
        return 0;
    }

    /* access modifiers changed from: package-private */
    @Override // org.conscrypt.OpenSSLCipher
    public int getOutputSizeForFinal(int inputLen) {
        return (isEncrypting() ? NativeCrypto.EVP_AEAD_max_overhead(this.evpAead) : 0) + this.bufCount + inputLen;
    }

    /* access modifiers changed from: protected */
    public void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
        checkInitialization();
        if (this.aad == null) {
            this.aad = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
            return;
        }
        byte[] newaad = new byte[(this.aad.length + inputLen)];
        System.arraycopy(this.aad, 0, newaad, 0, this.aad.length);
        System.arraycopy(input, inputOffset, newaad, this.aad.length, inputLen);
        this.aad = newaad;
    }

    /* access modifiers changed from: protected */
    public void engineUpdateAAD(ByteBuffer buf2) {
        checkInitialization();
        if (this.aad == null) {
            this.aad = new byte[buf2.remaining()];
            buf2.get(this.aad);
            return;
        }
        byte[] newaad = new byte[(this.aad.length + buf2.remaining())];
        System.arraycopy(this.aad, 0, newaad, 0, this.aad.length);
        buf2.get(newaad, this.aad.length, buf2.remaining());
        this.aad = newaad;
    }
}
