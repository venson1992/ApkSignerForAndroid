package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import java.io.IOException;
import java.nio.ByteBuffer;

public class TeeDataSink implements DataSink {
    private final DataSink[] mSinks;

    public TeeDataSink(DataSink[] sinks) {
        this.mSinks = sinks;
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(byte[] buf, int offset, int length) throws IOException {
        for (DataSink sink : this.mSinks) {
            sink.consume(buf, offset, length);
        }
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(ByteBuffer buf) throws IOException {
        int originalPosition = buf.position();
        for (int i = 0; i < this.mSinks.length; i++) {
            if (i > 0) {
                buf.position(originalPosition);
            }
            this.mSinks[i].consume(buf);
        }
    }
}
