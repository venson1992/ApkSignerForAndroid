package com.android.apksig.internal.apk;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkSigningBlockNotFoundException;
import com.android.apksig.apk.ApkUtilsLite;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipSections;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

public class ApkSigningBlockUtilsLite {
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private ApkSigningBlockUtilsLite() {
    }

    public static SignatureInfo findSignature(DataSource apk, ZipSections zipSections, int blockId) throws IOException, SignatureNotFoundException {
        try {
            ApkUtilsLite.ApkSigningBlock apkSigningBlockInfo = ApkUtilsLite.findApkSigningBlock(apk, zipSections);
            long apkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
            DataSource apkSigningBlock = apkSigningBlockInfo.getContents();
            ByteBuffer apkSigningBlockBuf = apkSigningBlock.getByteBuffer(0, (int) apkSigningBlock.size());
            apkSigningBlockBuf.order(ByteOrder.LITTLE_ENDIAN);
            return new SignatureInfo(findApkSignatureSchemeBlock(apkSigningBlockBuf, blockId), apkSigningBlockOffset, zipSections.getZipCentralDirectoryOffset(), zipSections.getZipEndOfCentralDirectoryOffset(), zipSections.getZipEndOfCentralDirectory());
        } catch (ApkSigningBlockNotFoundException e) {
            throw new SignatureNotFoundException(e.getMessage(), e);
        }
    }

    public static ByteBuffer findApkSignatureSchemeBlock(ByteBuffer apkSigningBlock, int blockId) throws SignatureNotFoundException {
        checkByteOrderLittleEndian(apkSigningBlock);
        ByteBuffer pairs = sliceFromTo(apkSigningBlock, 8, apkSigningBlock.capacity() - 24);
        int entryCount = 0;
        while (pairs.hasRemaining()) {
            entryCount++;
            if (pairs.remaining() < 8) {
                throw new SignatureNotFoundException("Insufficient data to read size of APK Signing Block entry #" + entryCount);
            }
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > 2147483647L) {
                throw new SignatureNotFoundException("APK Signing Block entry #" + entryCount + " size out of range: " + lenLong);
            }
            int len = (int) lenLong;
            int nextEntryPos = pairs.position() + len;
            if (len > pairs.remaining()) {
                throw new SignatureNotFoundException("APK Signing Block entry #" + entryCount + " size out of range: " + len + ", available: " + pairs.remaining());
            } else if (pairs.getInt() == blockId) {
                return getByteBuffer(pairs, len - 4);
            } else {
                pairs.position(nextEntryPos);
            }
        }
        throw new SignatureNotFoundException("No APK Signature Scheme block in APK Signing Block with ID: " + blockId);
    }

    public static void checkByteOrderLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    public static <T extends ApkSupportedSignature> List<T> getSignaturesToVerify(List<T> signatures, int minSdkVersion, int maxSdkVersion) throws NoApkSupportedSignaturesException {
        return getSignaturesToVerify(signatures, minSdkVersion, maxSdkVersion, false);
    }

    /* JADX WARN: Type inference failed for: r7v3, types: [void, java.util.Comparator] */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public static <T extends com.android.apksig.internal.apk.ApkSupportedSignature> java.util.List<T> getSignaturesToVerify(java.util.List<T> r10, int r11, int r12, boolean r13) throws com.android.apksig.internal.apk.NoApkSupportedSignaturesException {
        /*
        // Method dump skipped, instructions count: 138
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.ApkSigningBlockUtilsLite.getSignaturesToVerify(java.util.List, int, int, boolean):java.util.List");
    }

    public static int compareSignatureAlgorithm(SignatureAlgorithm alg1, SignatureAlgorithm alg2) {
        return compareContentDigestAlgorithm(alg1.getContentDigestAlgorithm(), alg2.getContentDigestAlgorithm());
    }

    private static int compareContentDigestAlgorithm(ContentDigestAlgorithm alg1, ContentDigestAlgorithm alg2) {
        switch (alg1) {
            case CHUNKED_SHA256:
                switch (alg2) {
                    case CHUNKED_SHA256:
                        return 0;
                    case CHUNKED_SHA512:
                    case VERITY_CHUNKED_SHA256:
                        return -1;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            case CHUNKED_SHA512:
                switch (alg2) {
                    case CHUNKED_SHA256:
                    case VERITY_CHUNKED_SHA256:
                        return 1;
                    case CHUNKED_SHA512:
                        return 0;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            case VERITY_CHUNKED_SHA256:
                switch (alg2) {
                    case CHUNKED_SHA256:
                        return 1;
                    case CHUNKED_SHA512:
                        return -1;
                    case VERITY_CHUNKED_SHA256:
                        return 0;
                    default:
                        throw new IllegalArgumentException("Unknown alg2: " + alg2);
                }
            default:
                throw new IllegalArgumentException("Unknown alg1: " + alg1);
        }
    }

    /* JADX INFO: finally extract failed */
    private static ByteBuffer sliceFromTo(ByteBuffer source, int start, int end) {
        if (start < 0) {
            throw new IllegalArgumentException("start: " + start);
        } else if (end < start) {
            throw new IllegalArgumentException("end < start: " + end + " < " + start);
        } else {
            int capacity = source.capacity();
            if (end > source.capacity()) {
                throw new IllegalArgumentException("end > capacity: " + end + " > " + capacity);
            }
            int originalLimit = source.limit();
            int originalPosition = source.position();
            try {
                source.position(0);
                source.limit(end);
                source.position(start);
                ByteBuffer result = source.slice();
                result.order(source.order());
                source.position(0);
                source.limit(originalLimit);
                source.position(originalPosition);
                return result;
            } catch (Throwable th) {
                source.position(0);
                source.limit(originalLimit);
                source.position(originalPosition);
                throw th;
            }
        }
    }

    private static ByteBuffer getByteBuffer(ByteBuffer source, int size) {
        if (size < 0) {
            throw new IllegalArgumentException("size: " + size);
        }
        int originalLimit = source.limit();
        int position = source.position();
        int limit = position + size;
        if (limit < position || limit > originalLimit) {
            throw new BufferUnderflowException();
        }
        source.limit(limit);
        try {
            ByteBuffer result = source.slice();
            result.order(source.order());
            source.position(limit);
            return result;
        } finally {
            source.limit(originalLimit);
        }
    }

    public static String toHex(byte[] value) {
        StringBuilder sb = new StringBuilder(value.length * 2);
        int len = value.length;
        for (int i = 0; i < len; i++) {
            sb.append(HEX_DIGITS[(value[i] & 255) >>> 4]).append(HEX_DIGITS[value[i] & 15]);
        }
        return sb.toString();
    }

    public static ByteBuffer getLengthPrefixedSlice(ByteBuffer source) throws ApkFormatException {
        if (source.remaining() < 4) {
            throw new ApkFormatException("Remaining buffer too short to contain length of length-prefixed field. Remaining: " + source.remaining());
        }
        int len = source.getInt();
        if (len < 0) {
            throw new IllegalArgumentException("Negative length");
        } else if (len <= source.remaining()) {
            return getByteBuffer(source, len);
        } else {
            throw new ApkFormatException("Length-prefixed field longer than remaining buffer. Field length: " + len + ", remaining: " + source.remaining());
        }
    }

    public static byte[] readLengthPrefixedByteArray(ByteBuffer buf) throws ApkFormatException {
        int len = buf.getInt();
        if (len < 0) {
            throw new ApkFormatException("Negative length");
        } else if (len > buf.remaining()) {
            throw new ApkFormatException("Underflow while reading length-prefixed value. Length: " + len + ", available: " + buf.remaining());
        } else {
            byte[] result = new byte[len];
            buf.get(result);
            return result;
        }
    }

    public static byte[] encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(List<Pair<Integer, byte[]>> sequence) {
        int resultSize = 0;
        for (Pair<Integer, byte[]> element : sequence) {
            resultSize += element.getSecond().length + 12;
        }
        ByteBuffer result = ByteBuffer.allocate(resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        for (Pair<Integer, byte[]> element2 : sequence) {
            byte[] second = element2.getSecond();
            result.putInt(second.length + 8);
            result.putInt(element2.getFirst().intValue());
            result.putInt(second.length);
            result.put(second);
        }
        return result.array();
    }
}
