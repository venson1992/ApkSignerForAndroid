package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class MessageDigestSink implements DataSink {
    private final MessageDigest[] mMessageDigests;

    public MessageDigestSink(MessageDigest[] digests) {
        this.mMessageDigests = digests;
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(byte[] buf, int offset, int length) {
        for (MessageDigest md : this.mMessageDigests) {
            md.update(buf, offset, length);
        }
    }

    @Override // com.android.apksig.util.DataSink
    public void consume(ByteBuffer buf) {
        int originalPosition = buf.position();
        MessageDigest[] messageDigestArr = this.mMessageDigests;
        for (MessageDigest md : messageDigestArr) {
            buf.position(originalPosition);
            md.update(buf);
        }
    }
}
