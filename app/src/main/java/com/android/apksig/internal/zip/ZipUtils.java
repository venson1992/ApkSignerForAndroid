package com.android.apksig.internal.zip;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import com.android.apksig.zip.ZipSections;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

public abstract class ZipUtils {
    public static final short COMPRESSION_METHOD_DEFLATED = 8;
    public static final short COMPRESSION_METHOD_STORED = 0;
    public static final short GP_FLAG_DATA_DESCRIPTOR_USED = 8;
    public static final short GP_FLAG_EFS = 2048;
    private static final int UINT16_MAX_VALUE = 65535;
    private static final int ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16;
    private static final int ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12;
    private static final int ZIP_EOCD_CENTRAL_DIR_TOTAL_RECORD_COUNT_OFFSET = 10;
    private static final int ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20;
    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 101010256;

    private ZipUtils() {
    }

    public static void setZipEocdCentralDirectoryOffset(ByteBuffer zipEndOfCentralDirectory, long offset) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        setUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + 16, offset);
    }

    public static long getZipEocdCentralDirectoryOffset(ByteBuffer zipEndOfCentralDirectory) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        return getUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + 16);
    }

    public static long getZipEocdCentralDirectorySizeBytes(ByteBuffer zipEndOfCentralDirectory) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        return getUnsignedInt32(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + 12);
    }

    public static int getZipEocdCentralDirectoryTotalRecordCount(ByteBuffer zipEndOfCentralDirectory) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory);
        return getUnsignedInt16(zipEndOfCentralDirectory, zipEndOfCentralDirectory.position() + 10);
    }

    public static Pair<ByteBuffer, Long> findZipEndOfCentralDirectoryRecord(DataSource zip) throws IOException {
        if (zip.size() < 22) {
            return null;
        }
        Pair<ByteBuffer, Long> result = findZipEndOfCentralDirectoryRecord(zip, 0);
        return result == null ? findZipEndOfCentralDirectoryRecord(zip, UINT16_MAX_VALUE) : result;
    }

    private static Pair<ByteBuffer, Long> findZipEndOfCentralDirectoryRecord(DataSource zip, int maxCommentSize) throws IOException {
        if (maxCommentSize < 0 || maxCommentSize > UINT16_MAX_VALUE) {
            throw new IllegalArgumentException("maxCommentSize: " + maxCommentSize);
        }
        long fileSize = zip.size();
        if (fileSize < 22) {
            return null;
        }
        int maxEocdSize = ((int) Math.min((long) maxCommentSize, fileSize - 22)) + 22;
        long bufOffsetInFile = fileSize - ((long) maxEocdSize);
        ByteBuffer buf = zip.getByteBuffer(bufOffsetInFile, maxEocdSize);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        int eocdOffsetInBuf = findZipEndOfCentralDirectoryRecord(buf);
        if (eocdOffsetInBuf == -1) {
            return null;
        }
        buf.position(eocdOffsetInBuf);
        ByteBuffer eocd = buf.slice();
        eocd.order(ByteOrder.LITTLE_ENDIAN);
        return Pair.of(eocd, Long.valueOf(((long) eocdOffsetInBuf) + bufOffsetInFile));
    }

    private static int findZipEndOfCentralDirectoryRecord(ByteBuffer zipContents) {
        assertByteOrderLittleEndian(zipContents);
        int archiveSize = zipContents.capacity();
        if (archiveSize < 22) {
            return -1;
        }
        int maxCommentLength = Math.min(archiveSize - 22, (int) UINT16_MAX_VALUE);
        int eocdWithEmptyCommentStartPosition = archiveSize - 22;
        for (int expectedCommentLength = 0; expectedCommentLength <= maxCommentLength; expectedCommentLength++) {
            int eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength;
            if (zipContents.getInt(eocdStartPos) == ZIP_EOCD_REC_SIG && getUnsignedInt16(zipContents, eocdStartPos + 20) == expectedCommentLength) {
                return eocdStartPos;
            }
        }
        return -1;
    }

    static void assertByteOrderLittleEndian(ByteBuffer buffer) {
        if (buffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    public static int getUnsignedInt16(ByteBuffer buffer, int offset) {
        return buffer.getShort(offset) & UINT16_MAX_VALUE;
    }

    public static int getUnsignedInt16(ByteBuffer buffer) {
        return buffer.getShort() & UINT16_MAX_VALUE;
    }

    public static List<CentralDirectoryRecord> parseZipCentralDirectory(DataSource apk, ZipSections apkSections) throws IOException, ApkFormatException {
        long cdSizeBytes = apkSections.getZipCentralDirectorySizeBytes();
        if (cdSizeBytes > 2147483647L) {
            throw new ApkFormatException("ZIP Central Directory too large: " + cdSizeBytes);
        }
        long cdOffset = apkSections.getZipCentralDirectoryOffset();
        ByteBuffer cd = apk.getByteBuffer(cdOffset, (int) cdSizeBytes);
        cd.order(ByteOrder.LITTLE_ENDIAN);
        int expectedCdRecordCount = apkSections.getZipCentralDirectoryRecordCount();
        List<CentralDirectoryRecord> cdRecords = new ArrayList<>(expectedCdRecordCount);
        for (int i = 0; i < expectedCdRecordCount; i++) {
            int offsetInsideCd = cd.position();
            try {
                CentralDirectoryRecord cdRecord = CentralDirectoryRecord.getRecord(cd);
                if (!cdRecord.getName().endsWith("/")) {
                    cdRecords.add(cdRecord);
                }
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed ZIP Central Directory record #" + (i + 1) + " at file offset " + (((long) offsetInsideCd) + cdOffset), e);
            }
        }
        return cdRecords;
    }

    static void setUnsignedInt16(ByteBuffer buffer, int offset, int value) {
        if (value < 0 || value > UINT16_MAX_VALUE) {
            throw new IllegalArgumentException("uint16 value of out range: " + value);
        }
        buffer.putShort(offset, (short) value);
    }

    static void setUnsignedInt32(ByteBuffer buffer, int offset, long value) {
        if (value < 0 || value > 4294967295L) {
            throw new IllegalArgumentException("uint32 value of out range: " + value);
        }
        buffer.putInt(offset, (int) value);
    }

    public static void putUnsignedInt16(ByteBuffer buffer, int value) {
        if (value < 0 || value > UINT16_MAX_VALUE) {
            throw new IllegalArgumentException("uint16 value of out range: " + value);
        }
        buffer.putShort((short) value);
    }

    static long getUnsignedInt32(ByteBuffer buffer, int offset) {
        return ((long) buffer.getInt(offset)) & 4294967295L;
    }

    static long getUnsignedInt32(ByteBuffer buffer) {
        return ((long) buffer.getInt()) & 4294967295L;
    }

    static void putUnsignedInt32(ByteBuffer buffer, long value) {
        if (value < 0 || value > 4294967295L) {
            throw new IllegalArgumentException("uint32 value of out range: " + value);
        }
        buffer.putInt((int) value);
    }

    public static DeflateResult deflate(ByteBuffer input) {
        byte[] inputBuf;
        int inputOffset;
        int inputLength = input.remaining();
        if (input.hasArray()) {
            inputBuf = input.array();
            inputOffset = input.arrayOffset() + input.position();
            input.position(input.limit());
        } else {
            inputBuf = new byte[inputLength];
            inputOffset = 0;
            input.get(inputBuf);
        }
        CRC32 crc32 = new CRC32();
        crc32.update(inputBuf, inputOffset, inputLength);
        long crc32Value = crc32.getValue();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(9, true);
        deflater.setInput(inputBuf, inputOffset, inputLength);
        deflater.finish();
        byte[] buf = new byte[65536];
        while (!deflater.finished()) {
            out.write(buf, 0, deflater.deflate(buf));
        }
        return new DeflateResult(inputLength, crc32Value, out.toByteArray());
    }

    public static class DeflateResult {
        public final long inputCrc32;
        public final int inputSizeBytes;
        public final byte[] output;

        public DeflateResult(int inputSizeBytes2, long inputCrc322, byte[] output2) {
            this.inputSizeBytes = inputSizeBytes2;
            this.inputCrc32 = inputCrc322;
            this.output = output2;
        }
    }
}
