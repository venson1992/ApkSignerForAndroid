package com.android.apksig.util;

import com.android.apksig.internal.util.ByteBufferDataSource;
import com.android.apksig.internal.util.FileChannelDataSource;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public abstract class DataSources {
    private DataSources() {
    }

    public static DataSource asDataSource(ByteBuffer buffer) {
        if (buffer != null) {
            return new ByteBufferDataSource(buffer);
        }
        throw new NullPointerException();
    }

    public static DataSource asDataSource(RandomAccessFile file) {
        return asDataSource(file.getChannel());
    }

    public static DataSource asDataSource(RandomAccessFile file, long offset, long size) {
        return asDataSource(file.getChannel(), offset, size);
    }

    public static DataSource asDataSource(FileChannel channel) {
        if (channel != null) {
            return new FileChannelDataSource(channel);
        }
        throw new NullPointerException();
    }

    public static DataSource asDataSource(FileChannel channel, long offset, long size) {
        if (channel != null) {
            return new FileChannelDataSource(channel, offset, size);
        }
        throw new NullPointerException();
    }
}
