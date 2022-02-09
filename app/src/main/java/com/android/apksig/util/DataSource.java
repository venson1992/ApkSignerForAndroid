package com.android.apksig.util;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface DataSource {
    void copyTo(long j, int i, ByteBuffer byteBuffer) throws IOException;

    void feed(long j, long j2, DataSink dataSink) throws IOException;

    ByteBuffer getByteBuffer(long j, int i) throws IOException;

    long size();

    DataSource slice(long j, long j2);
}
