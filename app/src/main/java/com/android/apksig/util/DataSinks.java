package com.android.apksig.util;

import com.android.apksig.internal.util.ByteArrayDataSink;
import com.android.apksig.internal.util.MessageDigestSink;
import com.android.apksig.internal.util.OutputStreamDataSink;
import com.android.apksig.internal.util.RandomAccessFileDataSink;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;

public abstract class DataSinks {
    private DataSinks() {
    }

    public static DataSink asDataSink(OutputStream out) {
        return new OutputStreamDataSink(out);
    }

    public static DataSink asDataSink(RandomAccessFile file) {
        return new RandomAccessFileDataSink(file);
    }

    public static DataSink asDataSink(MessageDigest... digests) {
        return new MessageDigestSink(digests);
    }

    public static ReadableDataSink newInMemoryDataSink() {
        return new ByteArrayDataSink();
    }

    public static ReadableDataSink newInMemoryDataSink(int initialCapacity) {
        return new ByteArrayDataSink(initialCapacity);
    }
}
