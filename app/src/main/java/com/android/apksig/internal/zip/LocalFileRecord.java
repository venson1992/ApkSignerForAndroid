package com.android.apksig.internal.zip;

import com.android.apksig.internal.util.ByteBufferSink;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class LocalFileRecord {
    private static final int COMPRESSED_SIZE_OFFSET = 18;
    private static final int CRC32_OFFSET = 14;
    private static final int DATA_DESCRIPTOR_SIGNATURE = 134695760;
    private static final int DATA_DESCRIPTOR_SIZE_BYTES_WITHOUT_SIGNATURE = 12;
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int EXTRA_LENGTH_OFFSET = 28;
    private static final int GP_FLAGS_OFFSET = 6;
    private static final int HEADER_SIZE_BYTES = 30;
    private static final int NAME_LENGTH_OFFSET = 26;
    private static final int NAME_OFFSET = 30;
    private static final int RECORD_SIGNATURE = 67324752;
    private static final int UNCOMPRESSED_SIZE_OFFSET = 22;
    private final boolean mDataCompressed;
    private final long mDataSize;
    private final int mDataStartOffset;
    private final ByteBuffer mExtra;
    private final String mName;
    private final int mNameSizeBytes;
    private final long mSize;
    private final long mStartOffsetInArchive;
    private final long mUncompressedDataSize;

    private LocalFileRecord(String name, int nameSizeBytes, ByteBuffer extra, long startOffsetInArchive, long size, int dataStartOffset, long dataSize, boolean dataCompressed, long uncompressedDataSize) {
        this.mName = name;
        this.mNameSizeBytes = nameSizeBytes;
        this.mExtra = extra;
        this.mStartOffsetInArchive = startOffsetInArchive;
        this.mSize = size;
        this.mDataStartOffset = dataStartOffset;
        this.mDataSize = dataSize;
        this.mDataCompressed = dataCompressed;
        this.mUncompressedDataSize = uncompressedDataSize;
    }

    public String getName() {
        return this.mName;
    }

    public ByteBuffer getExtra() {
        return this.mExtra.capacity() > 0 ? this.mExtra.slice() : this.mExtra;
    }

    public int getExtraFieldStartOffsetInsideRecord() {
        return this.mNameSizeBytes + 30;
    }

    public long getStartOffsetInArchive() {
        return this.mStartOffsetInArchive;
    }

    public int getDataStartOffsetInRecord() {
        return this.mDataStartOffset;
    }

    public long getSize() {
        return this.mSize;
    }

    public boolean isDataCompressed() {
        return this.mDataCompressed;
    }

    public static LocalFileRecord getRecord(DataSource apk, CentralDirectoryRecord cdRecord, long cdStartOffset) throws ZipFormatException, IOException {
        return getRecord(apk, cdRecord, cdStartOffset, true, true);
    }

    private static LocalFileRecord getRecord(DataSource apk, CentralDirectoryRecord cdRecord, long cdStartOffset, boolean extraFieldContentsNeeded, boolean dataDescriptorIncluded) throws ZipFormatException, IOException {
        long dataSize;
        String entryName = cdRecord.getName();
        int cdRecordEntryNameSizeBytes = cdRecord.getNameSizeBytes();
        int headerSizeWithName = cdRecordEntryNameSizeBytes + 30;
        long headerStartOffset = cdRecord.getLocalFileHeaderOffset();
        long headerEndOffset = headerStartOffset + ((long) headerSizeWithName);
        if (headerEndOffset > cdStartOffset) {
            throw new ZipFormatException("Local File Header of " + entryName + " extends beyond start of Central Directory. LFH end: " + headerEndOffset + ", CD start: " + cdStartOffset);
        }
        try {
            ByteBuffer header = apk.getByteBuffer(headerStartOffset, headerSizeWithName);
            header.order(ByteOrder.LITTLE_ENDIAN);
            int recordSignature = header.getInt();
            if (recordSignature != 67324752) {
                throw new ZipFormatException("Not a Local File Header record for entry " + entryName + ". Signature: 0x" + Long.toHexString(((long) recordSignature) & 4294967295L));
            }
            short gpFlags = header.getShort(6);
            boolean dataDescriptorUsed = (gpFlags & 8) != 0;
            boolean cdDataDescriptorUsed = (cdRecord.getGpFlags() & 8) != 0;
            if (dataDescriptorUsed != cdDataDescriptorUsed) {
                throw new ZipFormatException("Data Descriptor presence mismatch between Local File Header and Central Directory for entry " + entryName + ". LFH: " + dataDescriptorUsed + ", CD: " + cdDataDescriptorUsed);
            }
            long uncompressedDataCrc32FromCdRecord = cdRecord.getCrc32();
            long compressedDataSizeFromCdRecord = cdRecord.getCompressedSize();
            long uncompressedDataSizeFromCdRecord = cdRecord.getUncompressedSize();
            if (!dataDescriptorUsed) {
                long crc32 = ZipUtils.getUnsignedInt32(header, 14);
                if (crc32 != uncompressedDataCrc32FromCdRecord) {
                    throw new ZipFormatException("CRC-32 mismatch between Local File Header and Central Directory for entry " + entryName + ". LFH: " + crc32 + ", CD: " + uncompressedDataCrc32FromCdRecord);
                }
                long compressedSize = ZipUtils.getUnsignedInt32(header, 18);
                if (compressedSize != compressedDataSizeFromCdRecord) {
                    throw new ZipFormatException("Compressed size mismatch between Local File Header and Central Directory for entry " + entryName + ". LFH: " + compressedSize + ", CD: " + compressedDataSizeFromCdRecord);
                }
                long uncompressedSize = ZipUtils.getUnsignedInt32(header, 22);
                if (uncompressedSize != uncompressedDataSizeFromCdRecord) {
                    throw new ZipFormatException("Uncompressed size mismatch between Local File Header and Central Directory for entry " + entryName + ". LFH: " + uncompressedSize + ", CD: " + uncompressedDataSizeFromCdRecord);
                }
            }
            int nameLength = ZipUtils.getUnsignedInt16(header, 26);
            if (nameLength > cdRecordEntryNameSizeBytes) {
                throw new ZipFormatException("Name mismatch between Local File Header and Central Directory for entry" + entryName + ". LFH: " + nameLength + " bytes, CD: " + cdRecordEntryNameSizeBytes + " bytes");
            }
            String name = CentralDirectoryRecord.getName(header, 30, nameLength);
            if (!entryName.equals(name)) {
                throw new ZipFormatException("Name mismatch between Local File Header and Central Directory. LFH: \"" + name + "\", CD: \"" + entryName + "\"");
            }
            int extraLength = ZipUtils.getUnsignedInt16(header, 28);
            long dataStartOffset = 30 + headerStartOffset + ((long) nameLength) + ((long) extraLength);
            boolean compressed = cdRecord.getCompressionMethod() != 0;
            if (compressed) {
                dataSize = compressedDataSizeFromCdRecord;
            } else {
                dataSize = uncompressedDataSizeFromCdRecord;
            }
            long dataEndOffset = dataStartOffset + dataSize;
            if (dataEndOffset > cdStartOffset) {
                throw new ZipFormatException("Local File Header data of " + entryName + " overlaps with Central Directory. LFH data start: " + dataStartOffset + ", LFH data end: " + dataEndOffset + ", CD start: " + cdStartOffset);
            }
            ByteBuffer extra = EMPTY_BYTE_BUFFER;
            if (extraFieldContentsNeeded && extraLength > 0) {
                extra = apk.getByteBuffer(30 + headerStartOffset + ((long) nameLength), extraLength);
            }
            long recordEndOffset = dataEndOffset;
            if (dataDescriptorIncluded && (gpFlags & 8) != 0) {
                long dataDescriptorEndOffset = dataEndOffset + 12;
                if (dataDescriptorEndOffset > cdStartOffset) {
                    throw new ZipFormatException("Data Descriptor of " + entryName + " overlaps with Central Directory. Data Descriptor end: " + dataEndOffset + ", CD start: " + cdStartOffset);
                }
                ByteBuffer dataDescriptorPotentialSig = apk.getByteBuffer(dataEndOffset, 4);
                dataDescriptorPotentialSig.order(ByteOrder.LITTLE_ENDIAN);
                if (dataDescriptorPotentialSig.getInt() == DATA_DESCRIPTOR_SIGNATURE) {
                    dataDescriptorEndOffset += 4;
                    if (dataDescriptorEndOffset > cdStartOffset) {
                        throw new ZipFormatException("Data Descriptor of " + entryName + " overlaps with Central Directory. Data Descriptor end: " + dataEndOffset + ", CD start: " + cdStartOffset);
                    }
                }
                recordEndOffset = dataDescriptorEndOffset;
            }
            return new LocalFileRecord(entryName, cdRecordEntryNameSizeBytes, extra, headerStartOffset, recordEndOffset - headerStartOffset, nameLength + 30 + extraLength, dataSize, compressed, uncompressedDataSizeFromCdRecord);
        } catch (IOException e) {
            throw new IOException("Failed to read Local File Header of " + entryName, e);
        }
    }

    public long outputRecord(DataSource sourceApk, DataSink output) throws IOException {
        long size = getSize();
        sourceApk.feed(getStartOffsetInArchive(), size, output);
        return size;
    }

    public long outputRecordWithModifiedExtra(DataSource sourceApk, ByteBuffer extra, DataSink output) throws IOException {
        long recordStartOffsetInSource = getStartOffsetInArchive();
        int extraStartOffsetInRecord = getExtraFieldStartOffsetInsideRecord();
        int extraSizeBytes = extra.remaining();
        ByteBuffer header = ByteBuffer.allocate(extraStartOffsetInRecord + extraSizeBytes);
        header.order(ByteOrder.LITTLE_ENDIAN);
        sourceApk.copyTo(recordStartOffsetInSource, extraStartOffsetInRecord, header);
        header.put(extra.slice());
        header.flip();
        ZipUtils.setUnsignedInt16(header, 28, extraSizeBytes);
        long outputByteCount = (long) header.remaining();
        output.consume(header);
        long remainingRecordSize = getSize() - ((long) this.mDataStartOffset);
        sourceApk.feed(((long) this.mDataStartOffset) + recordStartOffsetInSource, remainingRecordSize, output);
        return outputByteCount + remainingRecordSize;
    }

    public static long outputRecordWithDeflateCompressedData(String name, int lastModifiedTime, int lastModifiedDate, byte[] compressedData, long crc32, long uncompressedSize, DataSink output) throws IOException {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        ByteBuffer result = ByteBuffer.allocate(nameBytes.length + 30);
        result.order(ByteOrder.LITTLE_ENDIAN);
        result.putInt(67324752);
        ZipUtils.putUnsignedInt16(result, 20);
        result.putShort(ZipUtils.GP_FLAG_EFS);
        result.putShort(8);
        ZipUtils.putUnsignedInt16(result, lastModifiedTime);
        ZipUtils.putUnsignedInt16(result, lastModifiedDate);
        ZipUtils.putUnsignedInt32(result, crc32);
        ZipUtils.putUnsignedInt32(result, (long) compressedData.length);
        ZipUtils.putUnsignedInt32(result, uncompressedSize);
        ZipUtils.putUnsignedInt16(result, nameBytes.length);
        ZipUtils.putUnsignedInt16(result, 0);
        result.put(nameBytes);
        if (result.hasRemaining()) {
            throw new RuntimeException("pos: " + result.position() + ", limit: " + result.limit());
        }
        result.flip();
        output.consume(result);
        long outputByteCount = ((long) result.remaining()) + ((long) compressedData.length);
        output.consume(compressedData, 0, compressedData.length);
        return outputByteCount;
    }

    public void outputUncompressedData(DataSource lfhSection, DataSink sink) throws IOException, ZipFormatException {
        String str;
        long dataStartOffsetInArchive = this.mStartOffsetInArchive + ((long) this.mDataStartOffset);
        try {
            if (this.mDataCompressed) {
                try {
                    InflateSinkAdapter inflateAdapter = new InflateSinkAdapter(sink);
                    try {
                        lfhSection.feed(dataStartOffsetInArchive, this.mDataSize, inflateAdapter);
                        long actualUncompressedSize = inflateAdapter.getOutputByteCount();
                        if (actualUncompressedSize != this.mUncompressedDataSize) {
                            throw new ZipFormatException("Unexpected size of uncompressed data of " + this.mName + ". Expected: " + this.mUncompressedDataSize + " bytes, actual: " + actualUncompressedSize + " bytes");
                        }
                        inflateAdapter.close();
                        return;
                    } catch (Throwable th) {
                        th.addSuppressed(th);
                    }
                } catch (IOException e) {
                    if (e.getCause() instanceof DataFormatException) {
                        throw new ZipFormatException("Data of entry " + this.mName + " malformed", e);
                    }
                    throw e;
                }
            } else {
                lfhSection.feed(dataStartOffsetInArchive, this.mDataSize, sink);
                return;
            }
            throw th;
        } catch (IOException e2) {
            StringBuilder append = new StringBuilder().append("Failed to read data of ");
            if (this.mDataCompressed) {
                str = "compressed";
            } else {
                str = "uncompressed";
            }
            throw new IOException(append.append(str).append(" entry ").append(this.mName).toString(), e2);
        }
    }

    public static void outputUncompressedData(DataSource source, CentralDirectoryRecord cdRecord, long cdStartOffsetInArchive, DataSink sink) throws ZipFormatException, IOException {
        getRecord(source, cdRecord, cdStartOffsetInArchive, false, false).outputUncompressedData(source, sink);
    }

    public static byte[] getUncompressedData(DataSource source, CentralDirectoryRecord cdRecord, long cdStartOffsetInArchive) throws ZipFormatException, IOException {
        if (cdRecord.getUncompressedSize() > 2147483647L) {
            throw new IOException(cdRecord.getName() + " too large: " + cdRecord.getUncompressedSize());
        }
        byte[] result = new byte[((int) cdRecord.getUncompressedSize())];
        outputUncompressedData(source, cdRecord, cdStartOffsetInArchive, new ByteBufferSink(ByteBuffer.wrap(result)));
        return result;
    }

    /* access modifiers changed from: private */
    public static class InflateSinkAdapter implements DataSink, Closeable {
        private boolean mClosed;
        private final DataSink mDelegate;
        private Inflater mInflater;
        private byte[] mInputBuffer;
        private byte[] mOutputBuffer;
        private long mOutputByteCount;

        private InflateSinkAdapter(DataSink delegate) {
            this.mInflater = new Inflater(true);
            this.mDelegate = delegate;
        }

        @Override // com.android.apksig.util.DataSink
        public void consume(byte[] buf, int offset, int length) throws IOException {
            checkNotClosed();
            this.mInflater.setInput(buf, offset, length);
            if (this.mOutputBuffer == null) {
                this.mOutputBuffer = new byte[65536];
            }
            while (!this.mInflater.finished()) {
                try {
                    int outputChunkSize = this.mInflater.inflate(this.mOutputBuffer);
                    if (outputChunkSize != 0) {
                        this.mDelegate.consume(this.mOutputBuffer, 0, outputChunkSize);
                        this.mOutputByteCount += (long) outputChunkSize;
                    } else {
                        return;
                    }
                } catch (DataFormatException e) {
                    throw new IOException("Failed to inflate data", e);
                }
            }
        }

        @Override // com.android.apksig.util.DataSink
        public void consume(ByteBuffer buf) throws IOException {
            checkNotClosed();
            if (buf.hasArray()) {
                consume(buf.array(), buf.arrayOffset() + buf.position(), buf.remaining());
                buf.position(buf.limit());
                return;
            }
            if (this.mInputBuffer == null) {
                this.mInputBuffer = new byte[65536];
            }
            while (buf.hasRemaining()) {
                int chunkSize = Math.min(buf.remaining(), this.mInputBuffer.length);
                buf.get(this.mInputBuffer, 0, chunkSize);
                consume(this.mInputBuffer, 0, chunkSize);
            }
        }

        public long getOutputByteCount() {
            return this.mOutputByteCount;
        }

        @Override // java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            this.mClosed = true;
            this.mInputBuffer = null;
            this.mOutputBuffer = null;
            if (this.mInflater != null) {
                this.mInflater.end();
                this.mInflater = null;
            }
        }

        private void checkNotClosed() {
            if (this.mClosed) {
                throw new IllegalStateException("Closed");
            }
        }
    }
}
