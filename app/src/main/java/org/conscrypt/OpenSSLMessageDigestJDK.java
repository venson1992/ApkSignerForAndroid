package org.conscrypt;

import java.nio.ByteBuffer;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import org.conscrypt.EvpMdRef;
import org.conscrypt.NativeRef;

public class OpenSSLMessageDigestJDK extends MessageDigestSpi implements Cloneable {
    private final NativeRef.EVP_MD_CTX ctx;
    private boolean digestInitializedInContext;
    private final long evp_md;
    private final byte[] singleByte;
    private final int size;

    private OpenSSLMessageDigestJDK(long evp_md2, int size2) throws NoSuchAlgorithmException {
        this.singleByte = new byte[1];
        this.evp_md = evp_md2;
        this.size = size2;
        this.ctx = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
    }

    private OpenSSLMessageDigestJDK(long evp_md2, int size2, NativeRef.EVP_MD_CTX ctx2, boolean digestInitializedInContext2) {
        this.singleByte = new byte[1];
        this.evp_md = evp_md2;
        this.size = size2;
        this.ctx = ctx2;
        this.digestInitializedInContext = digestInitializedInContext2;
    }

    private synchronized void ensureDigestInitializedInContext() {
        if (!this.digestInitializedInContext) {
            NativeCrypto.EVP_DigestInit_ex(this.ctx, this.evp_md);
            this.digestInitializedInContext = true;
        }
    }

    /* access modifiers changed from: protected */
    public synchronized void engineReset() {
        NativeCrypto.EVP_MD_CTX_cleanup(this.ctx);
        this.digestInitializedInContext = false;
    }

    /* access modifiers changed from: protected */
    public int engineGetDigestLength() {
        return this.size;
    }

    /* access modifiers changed from: protected */
    @Override // java.security.MessageDigestSpi
    public synchronized void engineUpdate(byte input) {
        this.singleByte[0] = input;
        engineUpdate(this.singleByte, 0, 1);
    }

    /* access modifiers changed from: protected */
    public synchronized void engineUpdate(byte[] input, int offset, int len) {
        ensureDigestInitializedInContext();
        NativeCrypto.EVP_DigestUpdate(this.ctx, input, offset, len);
    }

    /* access modifiers changed from: protected */
    @Override // java.security.MessageDigestSpi
    public synchronized void engineUpdate(ByteBuffer input) {
        if (input.hasRemaining()) {
            if (!input.isDirect()) {
                super.engineUpdate(input);
            } else {
                long baseAddress = NativeCrypto.getDirectBufferAddress(input);
                if (baseAddress == 0) {
                    super.engineUpdate(input);
                } else {
                    int position = input.position();
                    if (position < 0) {
                        throw new RuntimeException("Negative position");
                    }
                    long ptr = baseAddress + ((long) position);
                    int len = input.remaining();
                    if (len < 0) {
                        throw new RuntimeException("Negative remaining amount");
                    }
                    ensureDigestInitializedInContext();
                    NativeCrypto.EVP_DigestUpdateDirect(this.ctx, ptr, len);
                    input.position(position + len);
                }
            }
        }
    }

    /* access modifiers changed from: protected */
    public synchronized byte[] engineDigest() {
        byte[] result;
        ensureDigestInitializedInContext();
        result = new byte[this.size];
        NativeCrypto.EVP_DigestFinal_ex(this.ctx, result, 0);
        this.digestInitializedInContext = false;
        return result;
    }

    public static final class MD5 extends OpenSSLMessageDigestJDK {
        public MD5() throws NoSuchAlgorithmException {
            super(EvpMdRef.MD5.EVP_MD, EvpMdRef.MD5.SIZE_BYTES);
        }
    }

    public static final class SHA1 extends OpenSSLMessageDigestJDK {
        public SHA1() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA1.EVP_MD, EvpMdRef.SHA1.SIZE_BYTES);
        }
    }

    public static final class SHA224 extends OpenSSLMessageDigestJDK {
        public SHA224() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA224.EVP_MD, EvpMdRef.SHA224.SIZE_BYTES);
        }
    }

    public static final class SHA256 extends OpenSSLMessageDigestJDK {
        public SHA256() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA256.EVP_MD, EvpMdRef.SHA256.SIZE_BYTES);
        }
    }

    public static final class SHA384 extends OpenSSLMessageDigestJDK {
        public SHA384() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA384.EVP_MD, EvpMdRef.SHA384.SIZE_BYTES);
        }
    }

    public static final class SHA512 extends OpenSSLMessageDigestJDK {
        public SHA512() throws NoSuchAlgorithmException {
            super(EvpMdRef.SHA512.EVP_MD, EvpMdRef.SHA512.SIZE_BYTES);
        }
    }

    @Override // java.security.MessageDigestSpi, java.lang.Object
    public Object clone() {
        NativeRef.EVP_MD_CTX ctxCopy = new NativeRef.EVP_MD_CTX(NativeCrypto.EVP_MD_CTX_create());
        if (this.digestInitializedInContext) {
            NativeCrypto.EVP_MD_CTX_copy_ex(ctxCopy, this.ctx);
        }
        return new OpenSSLMessageDigestJDK(this.evp_md, this.size, ctxCopy, this.digestInitializedInContext);
    }
}
