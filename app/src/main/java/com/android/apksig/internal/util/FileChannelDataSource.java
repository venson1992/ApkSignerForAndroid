package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import java.io.IOException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class FileChannelDataSource implements DataSource {
    private static final int MAX_READ_CHUNK_SIZE = 1048576;
    private final FileChannel mChannel;
    private final long mOffset;
    private final long mSize;

    public FileChannelDataSource(FileChannel channel) {
        this.mChannel = channel;
        this.mOffset = 0;
        this.mSize = -1;
    }

    public FileChannelDataSource(FileChannel channel, long offset, long size) {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + size);
        } else if (size < 0) {
            throw new IndexOutOfBoundsException("size: " + size);
        } else {
            this.mChannel = channel;
            this.mOffset = offset;
            this.mSize = size;
        }
    }

    @Override // com.android.apksig.util.DataSource
    public long size() {
        if (this.mSize != -1) {
            return this.mSize;
        }
        try {
            return this.mChannel.size();
        } catch (IOException e) {
            return 0;
        }
    }

    @Override // com.android.apksig.util.DataSource
    public FileChannelDataSource slice(long offset, long size) {
        long sourceSize = size();
        checkChunkValid(offset, size, sourceSize);
        return (offset == 0 && size == sourceSize) ? this : new FileChannelDataSource(this.mChannel, this.mOffset + offset, size);
    }

    @Override // com.android.apksig.util.DataSource
    public void feed(long offset, long size, DataSink sink) throws IOException {
        checkChunkValid(offset, size, size());
        if (size != 0) {
            long chunkOffsetInFile = this.mOffset + offset;
            long remaining = size;
            ByteBuffer buf = ByteBuffer.allocateDirect((int) Math.min(remaining, 1048576L));
            while (remaining > 0) {
                int chunkSize = (int) Math.min(remaining, (long) buf.capacity());
                int chunkRemaining = chunkSize;
                buf.limit(chunkSize);
                synchronized (this.mChannel) {
                    this.mChannel.position(chunkOffsetInFile);
                    while (chunkRemaining > 0) {
                        int read = this.mChannel.read(buf);
                        if (read < 0) {
                            throw new IOException("Unexpected EOF encountered");
                        }
                        chunkRemaining -= read;
                    }
                }
                buf.flip();
                sink.consume(buf);
                buf.clear();
                chunkOffsetInFile += (long) chunkSize;
                remaining -= (long) chunkSize;
            }
        }
    }

    @Override // com.android.apksig.util.DataSource
    public void copyTo(long offset, int size, ByteBuffer dest) throws IOException {
        int chunkSize;
        checkChunkValid(offset, (long) size, size());
        if (size != 0) {
            if (size > dest.remaining()) {
                throw new BufferOverflowException();
            }
            long offsetInFile = this.mOffset + offset;
            int remaining = size;
            int prevLimit = dest.limit();
            try {
                prevLimit = dest.position() + size;
                while (remaining > 0) {
                    synchronized (this.mChannel) {
                        this.mChannel.position(offsetInFile);
                        chunkSize = this.mChannel.read(dest);
                    }
                    offsetInFile += (long) chunkSize;
                    remaining -= chunkSize;
                }
                dest.limit(prevLimit);
            } finally {
                dest.limit(prevLimit);
            }
        }
    }

    @Override // com.android.apksig.util.DataSource
    public ByteBuffer getByteBuffer(long offset, int size) throws IOException {
        if (size < 0) {
            throw new IndexOutOfBoundsException("size: " + size);
        }
        ByteBuffer result = ByteBuffer.allocate(size);
        copyTo(offset, size, result);
        result.flip();
        return result;
    }

    private static void checkChunkValid(long offset, long size, long sourceSize) {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + offset);
        } else if (size < 0) {
            throw new IndexOutOfBoundsException("size: " + size);
        } else if (offset > sourceSize) {
            throw new IndexOutOfBoundsException("offset (" + offset + ") > source size (" + sourceSize + ")");
        } else {
            long endOffset = offset + size;
            if (endOffset < offset) {
                throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") overflow");
            } else if (endOffset > sourceSize) {
                throw new IndexOutOfBoundsException("offset (" + offset + ") + size (" + size + ") > source size (" + sourceSize + ")");
            }
        }
    }
}
