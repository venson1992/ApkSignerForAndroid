package org.conscrypt;

import java.nio.ByteBuffer;

public abstract class AllocatedBuffer {
    public abstract ByteBuffer nioBuffer();

    public abstract AllocatedBuffer release();

    @Deprecated
    public AllocatedBuffer retain() {
        return this;
    }

    public static AllocatedBuffer wrap(final ByteBuffer buffer) {
        Preconditions.checkNotNull(buffer, "buffer");
        return new AllocatedBuffer() {
            /* class org.conscrypt.AllocatedBuffer.AnonymousClass1 */

            @Override // org.conscrypt.AllocatedBuffer
            public ByteBuffer nioBuffer() {
                return buffer;
            }

            @Override // org.conscrypt.AllocatedBuffer
            public AllocatedBuffer release() {
                return this;
            }
        };
    }
}
