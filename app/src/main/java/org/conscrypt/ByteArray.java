package org.conscrypt;

import java.util.Arrays;

final class ByteArray {
    private final byte[] bytes;
    private final int hashCode;

    ByteArray(byte[] bytes2) {
        this.bytes = bytes2;
        this.hashCode = Arrays.hashCode(bytes2);
    }

    public int hashCode() {
        return this.hashCode;
    }

    public boolean equals(Object o) {
        if (!(o instanceof ByteArray)) {
            return false;
        }
        return Arrays.equals(this.bytes, ((ByteArray) o).bytes);
    }
}
