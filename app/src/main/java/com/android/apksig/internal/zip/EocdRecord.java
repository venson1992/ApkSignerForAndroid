package com.android.apksig.internal.zip;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class EocdRecord {
    private static final int CD_OFFSET_OFFSET = 16;
    private static final int CD_RECORD_COUNT_ON_DISK_OFFSET = 8;
    private static final int CD_RECORD_COUNT_TOTAL_OFFSET = 10;
    private static final int CD_SIZE_OFFSET = 12;

    public static ByteBuffer createWithModifiedCentralDirectoryInfo(ByteBuffer original, int centralDirectoryRecordCount, long centralDirectorySizeBytes, long centralDirectoryOffset) {
        ByteBuffer result = ByteBuffer.allocate(original.remaining());
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.put(original.slice());
        result.flip();
        ZipUtils.setUnsignedInt16(result, 8, centralDirectoryRecordCount);
        ZipUtils.setUnsignedInt16(result, 10, centralDirectoryRecordCount);
        ZipUtils.setUnsignedInt32(result, 12, centralDirectorySizeBytes);
        ZipUtils.setUnsignedInt32(result, 16, centralDirectoryOffset);
        return result;
    }
}
