package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import java.io.IOException;
import java.nio.ByteBuffer;

public class ByteBufferDataSource implements DataSource {
    private final ByteBuffer mBuffer;
    private final int mSize;

    public ByteBufferDataSource(ByteBuffer buffer) {
        this(buffer, true);
    }

    private ByteBufferDataSource(ByteBuffer buffer, boolean sliceRequired) {
        ByteBuffer byteBuffer;
        if (sliceRequired) {
            byteBuffer = buffer.slice();
        } else {
            byteBuffer = buffer;
        }
        this.mBuffer = byteBuffer;
        this.mSize = buffer.remaining();
    }

    @Override // com.android.apksig.util.DataSource
    public long size() {
        return (long) this.mSize;
    }

    @Override // com.android.apksig.util.DataSource
    public ByteBuffer getByteBuffer(long offset, int size) {
        ByteBuffer slice;
        checkChunkValid(offset, (long) size);
        int chunkPosition = (int) offset;
        int chunkLimit = chunkPosition + size;
        synchronized (this.mBuffer) {
            this.mBuffer.position(0);
            this.mBuffer.limit(chunkLimit);
            this.mBuffer.position(chunkPosition);
            slice = this.mBuffer.slice();
        }
        return slice;
    }

    @Override // com.android.apksig.util.DataSource
    public void copyTo(long offset, int size, ByteBuffer dest) {
        dest.put(getByteBuffer(offset, size));
    }

    @Override // com.android.apksig.util.DataSource
    public void feed(long offset, long size, DataSink sink) throws IOException {
        if (size < 0 || size > ((long) this.mSize)) {
            throw new IndexOutOfBoundsException("size: " + size + ", source size: " + this.mSize);
        }
        sink.consume(getByteBuffer(offset, (int) size));
    }

    @Override // com.android.apksig.util.DataSource
    public ByteBufferDataSource slice(long offset, long size) {
        if (offset == 0 && size == ((long) this.mSize)) {
            return this;
        }
        if (size >= 0 && size <= ((long) this.mSize)) {
            return new ByteBufferDataSource(getByteBuffer(offset, (int) size), false);
        }
        throw new IndexOutOfBoundsException("size: " + size + ", source size: " + this.mSize);
    }

    private void checkChunkValid(long offset, long size) {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + offset);
        } else if (size < 0) {
            throw new IndexOutOfBoundsException("size: " + size);
        } else if (offset > ((long) this.mSize)) {
            throw new IndexOutOfBoundsException("offset (" + offset + ") > source size (" + this.mSize + ")");
        } else {
            long endOffset = offset + size;
            if (endOffset < offset) {
                throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") overflow");
            } else if (endOffset > ((long) this.mSize)) {
                throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") > source size (" + this.mSize + ")");
            }
        }
    }
}
