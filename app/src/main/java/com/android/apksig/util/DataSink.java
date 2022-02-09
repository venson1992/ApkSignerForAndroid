package com.android.apksig.util;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface DataSink {
    void consume(ByteBuffer byteBuffer) throws IOException;

    void consume(byte[] bArr, int i, int i2) throws IOException;
}
