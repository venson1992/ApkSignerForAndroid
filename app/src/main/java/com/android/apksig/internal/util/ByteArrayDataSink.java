package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.ReadableDataSink;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class ByteArrayDataSink implements ReadableDataSink {
    private static final int MAX_READ_CHUNK_SIZE = 65536;
    private byte[] mArray;
    private int mSize;

    public ByteArrayDataSink() {
        this(MAX_READ_CHUNK_SIZE);
    }

    public ByteArrayDataSink(int initialCapacity) {
        if (initialCapacity < 0) {
            throw new IllegalArgumentException("initial capacity: " + initialCapacity);
        }
        this.mArray = new byte[initialCapacity];
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(byte[] buf, int offset, int length) throws IOException {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + offset);
        } else if (offset > buf.length) {
            throw new IndexOutOfBoundsException("offset: " + offset + ", buf.length: " + buf.length);
        } else if (length != 0) {
            ensureAvailable(length);
            System.arraycopy(buf, offset, this.mArray, this.mSize, length);
            this.mSize += length;
        }
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(ByteBuffer buf) throws IOException {
        if (buf.hasRemaining()) {
            if (buf.hasArray()) {
                consume(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
                buf.position(buf.limit());
                return;
            }
            ensureAvailable(buf.remaining());
            byte[] tmp = new byte[Math.min(buf.remaining(), (int) MAX_READ_CHUNK_SIZE)];
            while (buf.hasRemaining()) {
                int chunkSize = Math.min(buf.remaining(), tmp.length);
                buf.get(tmp, 0, chunkSize);
                System.arraycopy(tmp, 0, this.mArray, this.mSize, chunkSize);
                this.mSize += chunkSize;
            }
        }
    }

    private void ensureAvailable(int minAvailable) throws IOException {
        if (minAvailable > 0) {
            long minCapacity = ((long) this.mSize) + ((long) minAvailable);
            if (minCapacity <= ((long) this.mArray.length)) {
                return;
            }
            if (minCapacity > 2147483647L) {
                throw new IOException("Required capacity too large: " + minCapacity + ", max: " + Integer.MAX_VALUE);
            }
            this.mArray = Arrays.copyOf(this.mArray, (int) Math.max(minCapacity, (long) ((int) Math.min(((long) this.mArray.length) * 2, 2147483647L))));
        }
    }

    @Override // com.android.apksig.util.DataSource
    public long size() {
        return (long) this.mSize;
    }

    @Override // com.android.apksig.util.DataSource
    public ByteBuffer getByteBuffer(long offset, int size) {
        checkChunkValid(offset, (long) size);
        return ByteBuffer.wrap(this.mArray, (int) offset, size).slice();
    }

    @Override // com.android.apksig.util.DataSource
    public void feed(long offset, long size, DataSink sink) throws IOException {
        checkChunkValid(offset, size);
        sink.consume(this.mArray, (int) offset, (int) size);
    }

    @Override // com.android.apksig.util.DataSource
    public void copyTo(long offset, int size, ByteBuffer dest) throws IOException {
        checkChunkValid(offset, (long) size);
        dest.put(this.mArray, (int) offset, size);
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

    @Override // com.android.apksig.util.DataSource
    public DataSource slice(long offset, long size) {
        checkChunkValid(offset, size);
        return new SliceDataSource((int) offset, (int) size);
    }

    private class SliceDataSource implements DataSource {
        private final int mSliceOffset;
        private final int mSliceSize;

        private SliceDataSource(int offset, int size) {
            this.mSliceOffset = offset;
            this.mSliceSize = size;
        }

        @Override // com.android.apksig.util.DataSource
        public long size() {
            return (long) this.mSliceSize;
        }

        @Override // com.android.apksig.util.DataSource
        public void feed(long offset, long size, DataSink sink) throws IOException {
            checkChunkValid(offset, size);
            sink.consume(ByteArrayDataSink.this.mArray, (int) (((long) this.mSliceOffset) + offset), (int) size);
        }

        @Override // com.android.apksig.util.DataSource
        public ByteBuffer getByteBuffer(long offset, int size) throws IOException {
            checkChunkValid(offset, (long) size);
            return ByteBuffer.wrap(ByteArrayDataSink.this.mArray, (int) (((long) this.mSliceOffset) + offset), size).slice();
        }

        @Override // com.android.apksig.util.DataSource
        public void copyTo(long offset, int size, ByteBuffer dest) throws IOException {
            checkChunkValid(offset, (long) size);
            dest.put(ByteArrayDataSink.this.mArray, (int) (((long) this.mSliceOffset) + offset), size);
        }

        @Override // com.android.apksig.util.DataSource
        public DataSource slice(long offset, long size) {
            checkChunkValid(offset, size);
            return new SliceDataSource((int) (((long) this.mSliceOffset) + offset), (int) size);
        }

        private void checkChunkValid(long offset, long size) {
            if (offset < 0) {
                throw new IndexOutOfBoundsException("offset: " + offset);
            } else if (size < 0) {
                throw new IndexOutOfBoundsException("size: " + size);
            } else if (offset > ((long) this.mSliceSize)) {
                throw new IndexOutOfBoundsException("offset (" + offset + ") > source size (" + this.mSliceSize + ")");
            } else {
                long endOffset = offset + size;
                if (endOffset < offset) {
                    throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") overflow");
                } else if (endOffset > ((long) this.mSliceSize)) {
                    throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") > source size (" + this.mSliceSize + ")");
                }
            }
        }
    }
}
