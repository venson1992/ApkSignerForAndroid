package org.conscrypt;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

class OpenSSLBIOInputStream extends FilterInputStream {
    private long ctx;

    OpenSSLBIOInputStream(InputStream is, boolean isFinite) {
        super(is);
        this.ctx = NativeCrypto.create_BIO_InputStream(this, isFinite);
    }

    /* access modifiers changed from: package-private */
    public long getBioContext() {
        return this.ctx;
    }

    /* access modifiers changed from: package-private */
    public void release() {
        NativeCrypto.BIO_free_all(this.ctx);
    }

    /* access modifiers changed from: package-private */
    public int gets(byte[] buffer) throws IOException {
        int inputByte;
        if (buffer == null || buffer.length == 0) {
            return 0;
        }
        int offset = 0;
        while (offset < buffer.length && (inputByte = read()) != -1) {
            if (inputByte != 10) {
                buffer[offset] = (byte) inputByte;
                offset++;
            } else if (offset != 0) {
                return offset;
            }
        }
        return offset;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] buffer) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] buffer, int offset, int len) throws IOException {
        if (offset < 0 || len < 0 || len > buffer.length - offset) {
            throw new IndexOutOfBoundsException("Invalid bounds");
        } else if (len == 0) {
            return 0;
        } else {
            int totalRead = 0;
            do {
                int read = super.read(buffer, offset + totalRead, (len - totalRead) - offset);
                if (read == -1) {
                    break;
                }
                totalRead += read;
            } while (offset + totalRead < len);
            if (totalRead == 0) {
                return -1;
            }
            return totalRead;
        }
    }
}
