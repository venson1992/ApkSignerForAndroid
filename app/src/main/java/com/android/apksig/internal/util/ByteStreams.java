package com.android.apksig.internal.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class ByteStreams {
    private ByteStreams() {
    }

    public static byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        while (true) {
            int chunkSize = in.read(buf);
            if (chunkSize == -1) {
                return result.toByteArray();
            }
            result.write(buf, 0, chunkSize);
        }
    }
}
