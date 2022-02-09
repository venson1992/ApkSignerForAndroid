package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

public class ByteBufferSink implements DataSink {
    private final ByteBuffer mBuffer;

    public ByteBufferSink(ByteBuffer buffer) {
        this.mBuffer = buffer;
    }

    public ByteBuffer getBuffer() {
        return this.mBuffer;
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(byte[] buf, int offset, int length) throws IOException {
        try {
            this.mBuffer.put(buf, offset, length);
        } catch (BufferOverflowException e) {
            throw new IOException("Insufficient space in output buffer for " + length + " bytes", e);
        }
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(ByteBuffer buf) throws IOException {
        int length = buf.remaining();
        try {
            this.mBuffer.put(buf);
        } catch (BufferOverflowException e) {
            throw new IOException("Insufficient space in output buffer for " + length + " bytes", e);
        }
    }
}
