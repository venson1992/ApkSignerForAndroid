package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class RandomAccessFileDataSink implements DataSink {
    private final RandomAccessFile mFile;
    private final FileChannel mFileChannel;
    private long mPosition;

    public RandomAccessFileDataSink(RandomAccessFile file) {
        this(file, 0);
    }

    public RandomAccessFileDataSink(RandomAccessFile file, long startPosition) {
        if (file == null) {
            throw new NullPointerException("file == null");
        } else if (startPosition < 0) {
            throw new IllegalArgumentException("startPosition: " + startPosition);
        } else {
            this.mFile = file;
            this.mFileChannel = file.getChannel();
            this.mPosition = startPosition;
        }
    }

    public RandomAccessFile getFile() {
        return this.mFile;
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(byte[] buf, int offset, int length) throws IOException {
        if (offset < 0) {
            throw new IndexOutOfBoundsException("offset: " + offset);
        } else if (offset > buf.length) {
            throw new IndexOutOfBoundsException("offset: " + offset + ", buf.length: " + buf.length);
        } else if (length != 0) {
            synchronized (this.mFile) {
                this.mFile.seek(this.mPosition);
                this.mFile.write(buf, offset, length);
                this.mPosition += (long) length;
            }
        }
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(ByteBuffer buf) throws IOException {
        int length = buf.remaining();
        if (length != 0) {
            synchronized (this.mFile) {
                this.mFile.seek(this.mPosition);
                while (buf.hasRemaining()) {
                    this.mFileChannel.write(buf);
                }
                this.mPosition += (long) length;
            }
        }
    }
}
