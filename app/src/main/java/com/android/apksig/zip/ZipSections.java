package com.android.apksig.zip;

import java.nio.ByteBuffer;

public class ZipSections {
    private final long mCentralDirectoryOffset;
    private final int mCentralDirectoryRecordCount;
    private final long mCentralDirectorySizeBytes;
    private final ByteBuffer mEocd;
    private final long mEocdOffset;

    public ZipSections(long centralDirectoryOffset, long centralDirectorySizeBytes, int centralDirectoryRecordCount, long eocdOffset, ByteBuffer eocd) {
        this.mCentralDirectoryOffset = centralDirectoryOffset;
        this.mCentralDirectorySizeBytes = centralDirectorySizeBytes;
        this.mCentralDirectoryRecordCount = centralDirectoryRecordCount;
        this.mEocdOffset = eocdOffset;
        this.mEocd = eocd;
    }

    public long getZipCentralDirectoryOffset() {
        return this.mCentralDirectoryOffset;
    }

    public long getZipCentralDirectorySizeBytes() {
        return this.mCentralDirectorySizeBytes;
    }

    public int getZipCentralDirectoryRecordCount() {
        return this.mCentralDirectoryRecordCount;
    }

    public long getZipEndOfCentralDirectoryOffset() {
        return this.mEocdOffset;
    }

    public ByteBuffer getZipEndOfCentralDirectory() {
        return this.mEocd;
    }
}
