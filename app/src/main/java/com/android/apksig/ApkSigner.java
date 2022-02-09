package com.android.apksig;

import com.android.apksig.ApkSignerEngine;
import com.android.apksig.DefaultApkSignerEngine;
import com.android.apksig.Hints;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkSigningBlockNotFoundException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.apk.MinSdkVersionException;
import com.android.apksig.internal.apk.ApkSigningBlockUtils;
import com.android.apksig.internal.util.ByteBufferDataSource;
import com.android.apksig.internal.zip.CentralDirectoryRecord;
import com.android.apksig.internal.zip.EocdRecord;
import com.android.apksig.internal.zip.LocalFileRecord;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.ReadableDataSink;
import com.android.apksig.zip.ZipFormatException;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ApkSigner {
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID = -9931;
    private static final short ALIGNMENT_ZIP_EXTRA_DATA_FIELD_MIN_SIZE_BYTES = 6;
    private static final short ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;
    private static final String ANDROID_MANIFEST_ZIP_ENTRY_NAME = "AndroidManifest.xml";
    private final String mCreatedBy;
    private final boolean mDebuggableApkPermitted;
    private final boolean mForceSourceStampOverwrite;
    private final DataSource mInputApkDataSource;
    private final File mInputApkFile;
    private final Integer mMinSdkVersion;
    private final boolean mOtherSignersSignaturesPreserved;
    private final DataSink mOutputApkDataSink;
    private final DataSource mOutputApkDataSource;
    private final File mOutputApkFile;
    private final File mOutputV4File;
    private final List<SignerConfig> mSignerConfigs;
    private final ApkSignerEngine mSignerEngine;
    private final SigningCertificateLineage mSigningCertificateLineage;
    private final SignerConfig mSourceStampSignerConfig;
    private final SigningCertificateLineage mSourceStampSigningCertificateLineage;
    private final boolean mV1SigningEnabled;
    private final boolean mV2SigningEnabled;
    private final boolean mV3SigningEnabled;
    private final boolean mV4ErrorReportingEnabled;
    private final boolean mV4SigningEnabled;
    private final boolean mVerityEnabled;

    private ApkSigner(List<SignerConfig> signerConfigs, SignerConfig sourceStampSignerConfig, SigningCertificateLineage sourceStampSigningCertificateLineage, boolean forceSourceStampOverwrite, Integer minSdkVersion, boolean v1SigningEnabled, boolean v2SigningEnabled, boolean v3SigningEnabled, boolean v4SigningEnabled, boolean verityEnabled, boolean v4ErrorReportingEnabled, boolean debuggableApkPermitted, boolean otherSignersSignaturesPreserved, String createdBy, ApkSignerEngine signerEngine, File inputApkFile, DataSource inputApkDataSource, File outputApkFile, DataSink outputApkDataSink, DataSource outputApkDataSource, File outputV4File, SigningCertificateLineage signingCertificateLineage) {
        this.mSignerConfigs = signerConfigs;
        this.mSourceStampSignerConfig = sourceStampSignerConfig;
        this.mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
        this.mForceSourceStampOverwrite = forceSourceStampOverwrite;
        this.mMinSdkVersion = minSdkVersion;
        this.mV1SigningEnabled = v1SigningEnabled;
        this.mV2SigningEnabled = v2SigningEnabled;
        this.mV3SigningEnabled = v3SigningEnabled;
        this.mV4SigningEnabled = v4SigningEnabled;
        this.mVerityEnabled = verityEnabled;
        this.mV4ErrorReportingEnabled = v4ErrorReportingEnabled;
        this.mDebuggableApkPermitted = debuggableApkPermitted;
        this.mOtherSignersSignaturesPreserved = otherSignersSignaturesPreserved;
        this.mCreatedBy = createdBy;
        this.mSignerEngine = signerEngine;
        this.mInputApkFile = inputApkFile;
        this.mInputApkDataSource = inputApkDataSource;
        this.mOutputApkFile = outputApkFile;
        this.mOutputApkDataSink = outputApkDataSink;
        this.mOutputApkDataSource = outputApkDataSource;
        this.mOutputV4File = outputV4File;
        this.mSigningCertificateLineage = signingCertificateLineage;
    }

    public void sign() throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalStateException {
        DataSource inputApk;
        DataSink outputApkOut;
        DataSource outputApkIn;
        Closeable in = null;
        try {
            if (this.mInputApkDataSource != null) {
                inputApk = this.mInputApkDataSource;
            } else if (this.mInputApkFile != null) {
                RandomAccessFile inputFile = new RandomAccessFile(this.mInputApkFile, "r");
                in = inputFile;
                inputApk = DataSources.asDataSource(inputFile);
            } else {
                throw new IllegalStateException("Input APK not specified");
            }
            Closeable out = null;
            try {
                if (this.mOutputApkDataSink != null) {
                    outputApkOut = this.mOutputApkDataSink;
                    outputApkIn = this.mOutputApkDataSource;
                } else if (this.mOutputApkFile != null) {
                    RandomAccessFile outputFile = new RandomAccessFile(this.mOutputApkFile, "rw");
                    out = outputFile;
                    outputFile.setLength(0);
                    outputApkOut = DataSinks.asDataSink(outputFile);
                    outputApkIn = DataSources.asDataSource(outputFile);
                } else {
                    throw new IllegalStateException("Output APK not specified");
                }
                sign(inputApk, outputApkOut, outputApkIn);
                if (in != null) {
                    in.close();
                }
            } finally {
                if (out != null) {
                    out.close();
                }
            }
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void sign(DataSource inputApk, DataSink outputApkOut, DataSource outputApkIn) throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int minSdkVersion;
        ApkSignerEngine signerEngine;
        boolean shouldOutput;
        CentralDirectoryRecord outputCdRecord;
        Hints.ByteRange pinRange;
        try {
            ApkUtils.ZipSections inputZipSections = ApkUtils.findZipSections(inputApk);
            long inputApkSigningBlockOffset = -1;
            DataSource inputApkSigningBlock = null;
            try {
                ApkUtils.ApkSigningBlock apkSigningBlockInfo = ApkUtils.findApkSigningBlock(inputApk, inputZipSections);
                inputApkSigningBlockOffset = apkSigningBlockInfo.getStartOffset();
                inputApkSigningBlock = apkSigningBlockInfo.getContents();
            } catch (ApkSigningBlockNotFoundException e) {
            }
            if (inputApkSigningBlockOffset == -1) {
                inputApkSigningBlockOffset = inputZipSections.getZipCentralDirectoryOffset();
            }
            DataSource inputApkLfhSection = inputApk.slice(0, inputApkSigningBlockOffset);
            List<CentralDirectoryRecord> inputCdRecords = parseZipCentralDirectory(getZipCentralDirectory(inputApk, inputZipSections), inputZipSections);
            List<Hints.PatternWithRange> pinPatterns = extractPinPatterns(inputCdRecords, inputApkLfhSection);
            List<Hints.ByteRange> pinByteRanges = pinPatterns == null ? null : new ArrayList<>();
            if (this.mSignerEngine != null) {
                signerEngine = this.mSignerEngine;
            } else {
                if (this.mMinSdkVersion != null) {
                    minSdkVersion = this.mMinSdkVersion.intValue();
                } else {
                    minSdkVersion = getMinSdkVersionFromApk(inputCdRecords, inputApkLfhSection);
                }
                List<DefaultApkSignerEngine.SignerConfig> engineSignerConfigs = new ArrayList<>(this.mSignerConfigs.size());
                for (SignerConfig signerConfig : this.mSignerConfigs) {
                    engineSignerConfigs.add(new DefaultApkSignerEngine.SignerConfig.Builder(signerConfig.getName(), signerConfig.getPrivateKey(), signerConfig.getCertificates()).build());
                }
                DefaultApkSignerEngine.Builder signerEngineBuilder = new DefaultApkSignerEngine.Builder(engineSignerConfigs, minSdkVersion).setV1SigningEnabled(this.mV1SigningEnabled).setV2SigningEnabled(this.mV2SigningEnabled).setV3SigningEnabled(this.mV3SigningEnabled).setVerityEnabled(this.mVerityEnabled).setDebuggableApkPermitted(this.mDebuggableApkPermitted).setOtherSignersSignaturesPreserved(this.mOtherSignersSignaturesPreserved).setSigningCertificateLineage(this.mSigningCertificateLineage);
                if (this.mCreatedBy != null) {
                    signerEngineBuilder.setCreatedBy(this.mCreatedBy);
                }
                if (this.mSourceStampSignerConfig != null) {
                    signerEngineBuilder.setStampSignerConfig(new DefaultApkSignerEngine.SignerConfig.Builder(this.mSourceStampSignerConfig.getName(), this.mSourceStampSignerConfig.getPrivateKey(), this.mSourceStampSignerConfig.getCertificates()).build());
                }
                if (this.mSourceStampSigningCertificateLineage != null) {
                    signerEngineBuilder.setSourceStampSigningCertificateLineage(this.mSourceStampSigningCertificateLineage);
                }
                signerEngine = signerEngineBuilder.build();
            }
            if (inputApkSigningBlock != null) {
                signerEngine.inputApkSigningBlock(inputApkSigningBlock);
            }
            List<CentralDirectoryRecord> inputCdRecordsSortedByLfhOffset = new ArrayList<>(inputCdRecords);
            Collections.sort(inputCdRecordsSortedByLfhOffset, CentralDirectoryRecord.BY_LOCAL_FILE_HEADER_OFFSET_COMPARATOR);
            int lastModifiedDateForNewEntries = -1;
            int lastModifiedTimeForNewEntries = -1;
            long inputOffset = 0;
            long outputOffset = 0;
            byte[] sourceStampCertificateDigest = null;
            Map<String, CentralDirectoryRecord> outputCdRecordsByName = new HashMap<>(inputCdRecords.size());
            for (CentralDirectoryRecord inputCdRecord : inputCdRecordsSortedByLfhOffset) {
                String entryName = inputCdRecord.getName();
                if (!Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME.equals(entryName)) {
                    if ("stamp-cert-sha256".equals(entryName)) {
                        try {
                            sourceStampCertificateDigest = LocalFileRecord.getUncompressedData(inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                        } catch (ZipFormatException e2) {
                            throw new ApkFormatException("Bad source stamp entry");
                        }
                    } else {
                        ApkSignerEngine.InputJarEntryInstructions entryInstructions = signerEngine.inputJarEntry(entryName);
                        switch (entryInstructions.getOutputPolicy()) {
                            case OUTPUT:
                                shouldOutput = true;
                                break;
                            case OUTPUT_BY_ENGINE:
                            case SKIP:
                                shouldOutput = false;
                                break;
                            default:
                                throw new RuntimeException("Unknown output policy: " + entryInstructions.getOutputPolicy());
                        }
                        long inputLocalFileHeaderStartOffset = inputCdRecord.getLocalFileHeaderOffset();
                        if (inputLocalFileHeaderStartOffset > inputOffset) {
                            long chunkSize = inputLocalFileHeaderStartOffset - inputOffset;
                            inputApkLfhSection.feed(inputOffset, chunkSize, outputApkOut);
                            outputOffset += chunkSize;
                            inputOffset = inputLocalFileHeaderStartOffset;
                        }
                        try {
                            LocalFileRecord inputLocalFileRecord = LocalFileRecord.getRecord(inputApkLfhSection, inputCdRecord, inputApkLfhSection.size());
                            inputOffset += inputLocalFileRecord.getSize();
                            ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest = entryInstructions.getInspectJarEntryRequest();
                            if (inspectEntryRequest != null) {
                                fulfillInspectInputJarEntryRequest(inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest);
                            }
                            if (shouldOutput) {
                                int lastModifiedDate = inputCdRecord.getLastModificationDate();
                                int lastModifiedTime = inputCdRecord.getLastModificationTime();
                                if (lastModifiedDateForNewEntries == -1 || lastModifiedDate > lastModifiedDateForNewEntries || (lastModifiedDate == lastModifiedDateForNewEntries && lastModifiedTime > lastModifiedTimeForNewEntries)) {
                                    lastModifiedDateForNewEntries = lastModifiedDate;
                                    lastModifiedTimeForNewEntries = lastModifiedTime;
                                }
                                ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest2 = signerEngine.outputJarEntry(entryName);
                                if (inspectEntryRequest2 != null) {
                                    fulfillInspectInputJarEntryRequest(inputApkLfhSection, inputLocalFileRecord, inspectEntryRequest2);
                                }
                                OutputSizeAndDataOffset outputLfrResult = outputInputJarEntryLfhRecordPreservingDataAlignment(inputApkLfhSection, inputLocalFileRecord, outputApkOut, outputOffset);
                                outputOffset += outputLfrResult.outputBytes;
                                long outputDataOffset = outputOffset + outputLfrResult.dataOffsetBytes;
                                if (pinPatterns != null) {
                                    boolean pinFileHeader = false;
                                    for (Hints.PatternWithRange pinPattern : pinPatterns) {
                                        if (pinPattern.matcher(inputCdRecord.getName()).matches() && (pinRange = pinPattern.ClampToAbsoluteByteRange(new Hints.ByteRange(outputDataOffset, outputOffset))) != null) {
                                            pinFileHeader = true;
                                            pinByteRanges.add(pinRange);
                                        }
                                    }
                                    if (pinFileHeader) {
                                        pinByteRanges.add(new Hints.ByteRange(outputOffset, outputDataOffset));
                                    }
                                }
                                if (outputOffset == inputLocalFileRecord.getStartOffsetInArchive()) {
                                    outputCdRecord = inputCdRecord;
                                } else {
                                    outputCdRecord = inputCdRecord.createWithModifiedLocalFileHeaderOffset(outputOffset);
                                }
                                outputCdRecordsByName.put(entryName, outputCdRecord);
                            }
                        } catch (ZipFormatException e3) {
                            throw new ApkFormatException("Malformed ZIP entry: " + inputCdRecord.getName(), e3);
                        }
                    }
                }
            }
            long inputLfhSectionSize = inputApkLfhSection.size();
            if (inputOffset < inputLfhSectionSize) {
                long chunkSize2 = inputLfhSectionSize - inputOffset;
                inputApkLfhSection.feed(inputOffset, chunkSize2, outputApkOut);
                outputOffset += chunkSize2;
            }
            List<CentralDirectoryRecord> outputCdRecords = new ArrayList<>(inputCdRecords.size() + 10);
            for (CentralDirectoryRecord inputCdRecord2 : inputCdRecords) {
                CentralDirectoryRecord outputCdRecord2 = outputCdRecordsByName.get(inputCdRecord2.getName());
                if (outputCdRecord2 != null) {
                    outputCdRecords.add(outputCdRecord2);
                }
            }
            if (lastModifiedDateForNewEntries == -1) {
                lastModifiedDateForNewEntries = 14881;
                lastModifiedTimeForNewEntries = 0;
            }
            if (signerEngine.isEligibleForSourceStamp()) {
                byte[] uncompressedData = signerEngine.generateSourceStampCertificateDigest();
                if (this.mForceSourceStampOverwrite || sourceStampCertificateDigest == null || Arrays.equals(uncompressedData, sourceStampCertificateDigest)) {
                    outputOffset += outputDataToOutputApk("stamp-cert-sha256", uncompressedData, outputOffset, outputCdRecords, lastModifiedTimeForNewEntries, lastModifiedDateForNewEntries, outputApkOut);
                } else {
                    throw new ApkFormatException(String.format("Cannot generate SourceStamp. APK contains an existing entry with the name: %s, and it is different than the provided source stamp certificate", "stamp-cert-sha256"));
                }
            }
            ApkSignerEngine.OutputJarSignatureRequest outputJarSignatureRequest = signerEngine.outputJarEntries();
            if (outputJarSignatureRequest != null) {
                for (ApkSignerEngine.OutputJarSignatureRequest.JarEntry entry : outputJarSignatureRequest.getAdditionalJarEntries()) {
                    String entryName2 = entry.getName();
                    byte[] uncompressedData2 = entry.getData();
                    ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest3 = signerEngine.outputJarEntry(entryName2);
                    if (inspectEntryRequest3 != null) {
                        inspectEntryRequest3.getDataSink().consume(uncompressedData2, 0, uncompressedData2.length);
                        inspectEntryRequest3.done();
                    }
                    outputOffset += outputDataToOutputApk(entryName2, uncompressedData2, outputOffset, outputCdRecords, lastModifiedTimeForNewEntries, lastModifiedDateForNewEntries, outputApkOut);
                }
                outputJarSignatureRequest.done();
            }
            if (pinByteRanges != null) {
                pinByteRanges.add(new Hints.ByteRange(outputOffset, Long.MAX_VALUE));
                outputOffset += outputDataToOutputApk(Hints.PIN_BYTE_RANGE_ZIP_ENTRY_NAME, Hints.encodeByteRangeList(pinByteRanges), outputOffset, outputCdRecords, lastModifiedTimeForNewEntries, lastModifiedDateForNewEntries, outputApkOut);
            }
            long outputCentralDirSizeBytes = 0;
            for (CentralDirectoryRecord record : outputCdRecords) {
                outputCentralDirSizeBytes += (long) record.getSize();
            }
            if (outputCentralDirSizeBytes > 2147483647L) {
                throw new IOException("Output ZIP Central Directory too large: " + outputCentralDirSizeBytes + " bytes");
            }
            ByteBuffer outputCentralDir = ByteBuffer.allocate((int) outputCentralDirSizeBytes);
            for (CentralDirectoryRecord record2 : outputCdRecords) {
                record2.copyTo(outputCentralDir);
            }
            outputCentralDir.flip();
            DataSource outputCentralDirDataSource = new ByteBufferDataSource(outputCentralDir);
            ByteBuffer outputEocd = EocdRecord.createWithModifiedCentralDirectoryInfo(inputZipSections.getZipEndOfCentralDirectory(), outputCdRecords.size(), outputCentralDirDataSource.size(), outputOffset);
            ApkSignerEngine.OutputApkSigningBlockRequest2 outputApkSigningBlockRequest = signerEngine.outputZipSections2(outputApkIn, outputCentralDirDataSource, DataSources.asDataSource(outputEocd));
            if (outputApkSigningBlockRequest != null) {
                int padding = outputApkSigningBlockRequest.getPaddingSizeBeforeApkSigningBlock();
                outputApkOut.consume(ByteBuffer.allocate(padding));
                byte[] outputApkSigningBlock = outputApkSigningBlockRequest.getApkSigningBlock();
                outputApkOut.consume(outputApkSigningBlock, 0, outputApkSigningBlock.length);
                ZipUtils.setZipEocdCentralDirectoryOffset(outputEocd, ((long) padding) + outputOffset + ((long) outputApkSigningBlock.length));
                outputApkSigningBlockRequest.done();
            }
            outputCentralDirDataSource.feed(0, outputCentralDirDataSource.size(), outputApkOut);
            outputApkOut.consume(outputEocd);
            signerEngine.outputDone();
            if (this.mV4SigningEnabled) {
                signerEngine.signV4(outputApkIn, this.mOutputV4File, !this.mV4ErrorReportingEnabled);
            }
        } catch (ZipFormatException e4) {
            throw new ApkFormatException("Malformed APK: not a ZIP archive", e4);
        }
    }

    private static long outputDataToOutputApk(String entryName, byte[] uncompressedData, long localFileHeaderOffset, List<CentralDirectoryRecord> outputCdRecords, int lastModifiedTimeForNewEntries, int lastModifiedDateForNewEntries, DataSink outputApkOut) throws IOException {
        ZipUtils.DeflateResult deflateResult = ZipUtils.deflate(ByteBuffer.wrap(uncompressedData));
        byte[] compressedData = deflateResult.output;
        long uncompressedDataCrc32 = deflateResult.inputCrc32;
        long numOfDataBytes = LocalFileRecord.outputRecordWithDeflateCompressedData(entryName, lastModifiedTimeForNewEntries, lastModifiedDateForNewEntries, compressedData, uncompressedDataCrc32, (long) uncompressedData.length, outputApkOut);
        outputCdRecords.add(CentralDirectoryRecord.createWithDeflateCompressedData(entryName, lastModifiedTimeForNewEntries, lastModifiedDateForNewEntries, uncompressedDataCrc32, (long) compressedData.length, (long) uncompressedData.length, localFileHeaderOffset));
        return numOfDataBytes;
    }

    private static void fulfillInspectInputJarEntryRequest(DataSource lfhSection, LocalFileRecord localFileRecord, ApkSignerEngine.InspectJarEntryRequest inspectEntryRequest) throws IOException, ApkFormatException {
        try {
            localFileRecord.outputUncompressedData(lfhSection, inspectEntryRequest.getDataSink());
            inspectEntryRequest.done();
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Malformed ZIP entry: " + localFileRecord.getName(), e);
        }
    }

    /* access modifiers changed from: private */
    public static class OutputSizeAndDataOffset {
        public long dataOffsetBytes;
        public long outputBytes;

        public OutputSizeAndDataOffset(long outputBytes2, long dataOffsetBytes2) {
            this.outputBytes = outputBytes2;
            this.dataOffsetBytes = dataOffsetBytes2;
        }
    }

    private static OutputSizeAndDataOffset outputInputJarEntryLfhRecordPreservingDataAlignment(DataSource inputLfhSection, LocalFileRecord inputRecord, DataSink outputLfhSection, long outputOffset) throws IOException {
        long inputOffset = inputRecord.getStartOffsetInArchive();
        if (inputOffset == outputOffset) {
            return new OutputSizeAndDataOffset(inputRecord.outputRecord(inputLfhSection, outputLfhSection), (long) inputRecord.getDataStartOffsetInRecord());
        }
        int dataAlignmentMultiple = getInputJarEntryDataAlignmentMultiple(inputRecord);
        if (dataAlignmentMultiple <= 1 || inputOffset % ((long) dataAlignmentMultiple) == outputOffset % ((long) dataAlignmentMultiple)) {
            return new OutputSizeAndDataOffset(inputRecord.outputRecord(inputLfhSection, outputLfhSection), (long) inputRecord.getDataStartOffsetInRecord());
        }
        if ((inputOffset + ((long) inputRecord.getDataStartOffsetInRecord())) % ((long) dataAlignmentMultiple) != 0) {
            return new OutputSizeAndDataOffset(inputRecord.outputRecord(inputLfhSection, outputLfhSection), (long) inputRecord.getDataStartOffsetInRecord());
        }
        ByteBuffer aligningExtra = createExtraFieldToAlignData(inputRecord.getExtra(), ((long) inputRecord.getExtraFieldStartOffsetInsideRecord()) + outputOffset, dataAlignmentMultiple);
        return new OutputSizeAndDataOffset(inputRecord.outputRecordWithModifiedExtra(inputLfhSection, aligningExtra, outputLfhSection), (((long) inputRecord.getDataStartOffsetInRecord()) + ((long) aligningExtra.remaining())) - ((long) inputRecord.getExtra().remaining()));
    }

    private static int getInputJarEntryDataAlignmentMultiple(LocalFileRecord entry) {
        if (entry.isDataCompressed()) {
            return 1;
        }
        ByteBuffer extra = entry.getExtra();
        if (extra.hasRemaining()) {
            extra.order(ByteOrder.LITTLE_ENDIAN);
            while (true) {
                if (extra.remaining() < 4) {
                    break;
                }
                short headerId = extra.getShort();
                int dataSize = ZipUtils.getUnsignedInt16(extra);
                if (dataSize > extra.remaining()) {
                    break;
                } else if (headerId != -9931) {
                    extra.position(extra.position() + dataSize);
                } else if (dataSize >= 2) {
                    return ZipUtils.getUnsignedInt16(extra);
                }
            }
        }
        if (entry.getName().endsWith(".so")) {
            return ApkSigningBlockUtils.ANDROID_COMMON_PAGE_ALIGNMENT_BYTES;
        }
        return 4;
    }

    private static ByteBuffer createExtraFieldToAlignData(ByteBuffer original, long extraStartOffset, int dataAlignmentMultiple) {
        if (dataAlignmentMultiple <= 1) {
            return original;
        }
        ByteBuffer result = ByteBuffer.allocate(original.remaining() + 5 + dataAlignmentMultiple);
        result.order(ByteOrder.LITTLE_ENDIAN);
        while (original.remaining() >= 4) {
            short headerId = original.getShort();
            int dataSize = ZipUtils.getUnsignedInt16(original);
            if (dataSize > original.remaining()) {
                break;
            } else if ((headerId == 0 && dataSize == 0) || headerId == -9931) {
                original.position(original.position() + dataSize);
            } else {
                original.position(original.position() - 4);
                int originalLimit = original.limit();
                original.limit(original.position() + 4 + dataSize);
                result.put(original);
                original.limit(originalLimit);
            }
        }
        int paddingSizeBytes = (dataAlignmentMultiple - ((int) (((((long) result.position()) + extraStartOffset) + 6) % ((long) dataAlignmentMultiple)))) % dataAlignmentMultiple;
        result.putShort(ALIGNMENT_ZIP_EXTRA_DATA_FIELD_HEADER_ID);
        ZipUtils.putUnsignedInt16(result, paddingSizeBytes + 2);
        ZipUtils.putUnsignedInt16(result, dataAlignmentMultiple);
        result.position(result.position() + paddingSizeBytes);
        result.flip();
        return result;
    }

    private static ByteBuffer getZipCentralDirectory(DataSource apk, ApkUtils.ZipSections apkSections) throws IOException, ApkFormatException {
        long cdSizeBytes = apkSections.getZipCentralDirectorySizeBytes();
        if (cdSizeBytes > 2147483647L) {
            throw new ApkFormatException("ZIP Central Directory too large: " + cdSizeBytes);
        }
        ByteBuffer cd = apk.getByteBuffer(apkSections.getZipCentralDirectoryOffset(), (int) cdSizeBytes);
        cd.order(ByteOrder.LITTLE_ENDIAN);
        return cd;
    }

    private static List<CentralDirectoryRecord> parseZipCentralDirectory(ByteBuffer cd, ApkUtils.ZipSections apkSections) throws ApkFormatException {
        long cdOffset = apkSections.getZipCentralDirectoryOffset();
        int expectedCdRecordCount = apkSections.getZipCentralDirectoryRecordCount();
        List<CentralDirectoryRecord> cdRecords = new ArrayList<>(expectedCdRecordCount);
        Set<String> entryNames = new HashSet<>(expectedCdRecordCount);
        for (int i = 0; i < expectedCdRecordCount; i++) {
            int offsetInsideCd = cd.position();
            try {
                CentralDirectoryRecord cdRecord = CentralDirectoryRecord.getRecord(cd);
                String entryName = cdRecord.getName();
                if (!entryNames.add(entryName)) {
                    throw new ApkFormatException("Multiple ZIP entries with the same name: " + entryName);
                }
                cdRecords.add(cdRecord);
            } catch (ZipFormatException e) {
                throw new ApkFormatException("Malformed ZIP Central Directory record #" + (i + 1) + " at file offset " + (((long) offsetInsideCd) + cdOffset), e);
            }
        }
        if (!cd.hasRemaining()) {
            return cdRecords;
        }
        throw new ApkFormatException("Unused space at the end of ZIP Central Directory: " + cd.remaining() + " bytes starting at file offset " + (((long) cd.position()) + cdOffset));
    }

    private static CentralDirectoryRecord findCdRecord(List<CentralDirectoryRecord> cdRecords, String name) {
        for (CentralDirectoryRecord cdRecord : cdRecords) {
            if (name.equals(cdRecord.getName())) {
                return cdRecord;
            }
        }
        return null;
    }

    static ByteBuffer getAndroidManifestFromApk(List<CentralDirectoryRecord> cdRecords, DataSource lhfSection) throws IOException, ApkFormatException, ZipFormatException {
        CentralDirectoryRecord androidManifestCdRecord = findCdRecord(cdRecords, "AndroidManifest.xml");
        if (androidManifestCdRecord != null) {
            return ByteBuffer.wrap(LocalFileRecord.getUncompressedData(lhfSection, androidManifestCdRecord, lhfSection.size()));
        }
        throw new ApkFormatException("Missing AndroidManifest.xml");
    }

    private static List<Hints.PatternWithRange> extractPinPatterns(List<CentralDirectoryRecord> cdRecords, DataSource lhfSection) throws IOException, ApkFormatException {
        CentralDirectoryRecord pinListCdRecord = findCdRecord(cdRecords, Hints.PIN_HINT_ASSET_ZIP_ENTRY_NAME);
        if (pinListCdRecord == null) {
            return null;
        }
        new ArrayList<>();
        try {
            return Hints.parsePinPatterns(LocalFileRecord.getUncompressedData(lhfSection, pinListCdRecord, lhfSection.size()));
        } catch (ZipFormatException e) {
            throw new ApkFormatException("Bad " + pinListCdRecord);
        }
    }

    private static int getMinSdkVersionFromApk(List<CentralDirectoryRecord> cdRecords, DataSource lhfSection) throws IOException, MinSdkVersionException {
        try {
            return ApkUtils.getMinSdkVersionFromBinaryAndroidManifest(getAndroidManifestFromApk(cdRecords, lhfSection));
        } catch (ApkFormatException | ZipFormatException e) {
            throw new MinSdkVersionException("Failed to determine APK's minimum supported Android platform version", e);
        }
    }

    public static class SignerConfig {
        private final List<X509Certificate> mCertificates;
        private final String mName;
        private final PrivateKey mPrivateKey;

        private SignerConfig(String name, PrivateKey privateKey, List<X509Certificate> certificates) {
            this.mName = name;
            this.mPrivateKey = privateKey;
            this.mCertificates = Collections.unmodifiableList(new ArrayList(certificates));
        }

        public String getName() {
            return this.mName;
        }

        public PrivateKey getPrivateKey() {
            return this.mPrivateKey;
        }

        public List<X509Certificate> getCertificates() {
            return this.mCertificates;
        }

        public static class Builder {
            private final List<X509Certificate> mCertificates;
            private final String mName;
            private final PrivateKey mPrivateKey;

            public Builder(String name, PrivateKey privateKey, List<X509Certificate> certificates) {
                if (name.isEmpty()) {
                    throw new IllegalArgumentException("Empty name");
                }
                this.mName = name;
                this.mPrivateKey = privateKey;
                this.mCertificates = new ArrayList(certificates);
            }

            public SignerConfig build() {
                return new SignerConfig(this.mName, this.mPrivateKey, this.mCertificates);
            }
        }
    }

    public static class Builder {
        private String mCreatedBy;
        private boolean mDebuggableApkPermitted = true;
        private boolean mForceSourceStampOverwrite = false;
        private DataSource mInputApkDataSource;
        private File mInputApkFile;
        private Integer mMinSdkVersion;
        private boolean mOtherSignersSignaturesPreserved;
        private DataSink mOutputApkDataSink;
        private DataSource mOutputApkDataSource;
        private File mOutputApkFile;
        private File mOutputV4File;
        private final List<SignerConfig> mSignerConfigs;
        private final ApkSignerEngine mSignerEngine;
        private SigningCertificateLineage mSigningCertificateLineage;
        private SignerConfig mSourceStampSignerConfig;
        private SigningCertificateLineage mSourceStampSigningCertificateLineage;
        private boolean mV1SigningEnabled = true;
        private boolean mV2SigningEnabled = true;
        private boolean mV3SigningEnabled = true;
        private boolean mV3SigningExplicitlyDisabled = false;
        private boolean mV3SigningExplicitlyEnabled = false;
        private boolean mV4ErrorReportingEnabled = false;
        private boolean mV4SigningEnabled = true;
        private boolean mVerityEnabled = false;

        public Builder(List<SignerConfig> signerConfigs) {
            if (signerConfigs.isEmpty()) {
                throw new IllegalArgumentException("At least one signer config must be provided");
            }
            if (signerConfigs.size() > 1) {
                this.mV3SigningEnabled = false;
            }
            this.mSignerConfigs = new ArrayList(signerConfigs);
            this.mSignerEngine = null;
        }

        public Builder(ApkSignerEngine signerEngine) {
            if (signerEngine == null) {
                throw new NullPointerException("signerEngine == null");
            }
            this.mSignerEngine = signerEngine;
            this.mSignerConfigs = null;
        }

        public Builder setSourceStampSignerConfig(SignerConfig sourceStampSignerConfig) {
            this.mSourceStampSignerConfig = sourceStampSignerConfig;
            return this;
        }

        public Builder setSourceStampSigningCertificateLineage(SigningCertificateLineage sourceStampSigningCertificateLineage) {
            this.mSourceStampSigningCertificateLineage = sourceStampSigningCertificateLineage;
            return this;
        }

        public Builder setForceSourceStampOverwrite(boolean force) {
            this.mForceSourceStampOverwrite = force;
            return this;
        }

        public Builder setInputApk(File inputApk) {
            if (inputApk == null) {
                throw new NullPointerException("inputApk == null");
            }
            this.mInputApkFile = inputApk;
            this.mInputApkDataSource = null;
            return this;
        }

        public Builder setInputApk(DataSource inputApk) {
            if (inputApk == null) {
                throw new NullPointerException("inputApk == null");
            }
            this.mInputApkDataSource = inputApk;
            this.mInputApkFile = null;
            return this;
        }

        public Builder setOutputApk(File outputApk) {
            if (outputApk == null) {
                throw new NullPointerException("outputApk == null");
            }
            this.mOutputApkFile = outputApk;
            this.mOutputApkDataSink = null;
            this.mOutputApkDataSource = null;
            return this;
        }

        public Builder setOutputApk(ReadableDataSink outputApk) {
            if (outputApk != null) {
                return setOutputApk(outputApk, outputApk);
            }
            throw new NullPointerException("outputApk == null");
        }

        public Builder setOutputApk(DataSink outputApkOut, DataSource outputApkIn) {
            if (outputApkOut == null) {
                throw new NullPointerException("outputApkOut == null");
            } else if (outputApkIn == null) {
                throw new NullPointerException("outputApkIn == null");
            } else {
                this.mOutputApkFile = null;
                this.mOutputApkDataSink = outputApkOut;
                this.mOutputApkDataSource = outputApkIn;
                return this;
            }
        }

        public Builder setV4SignatureOutputFile(File v4SignatureOutputFile) {
            if (v4SignatureOutputFile == null) {
                throw new NullPointerException("v4HashRootOutputFile == null");
            }
            this.mOutputV4File = v4SignatureOutputFile;
            return this;
        }

        public Builder setMinSdkVersion(int minSdkVersion) {
            checkInitializedWithoutEngine();
            this.mMinSdkVersion = Integer.valueOf(minSdkVersion);
            return this;
        }

        public Builder setV1SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mV1SigningEnabled = enabled;
            return this;
        }

        public Builder setV2SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mV2SigningEnabled = enabled;
            return this;
        }

        public Builder setV3SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mV3SigningEnabled = enabled;
            if (enabled) {
                this.mV3SigningExplicitlyEnabled = true;
            } else {
                this.mV3SigningExplicitlyDisabled = true;
            }
            return this;
        }

        public Builder setV4SigningEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mV4SigningEnabled = enabled;
            this.mV4ErrorReportingEnabled = enabled;
            return this;
        }

        public Builder setV4ErrorReportingEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mV4ErrorReportingEnabled = enabled;
            return this;
        }

        public Builder setVerityEnabled(boolean enabled) {
            checkInitializedWithoutEngine();
            this.mVerityEnabled = enabled;
            return this;
        }

        public Builder setDebuggableApkPermitted(boolean permitted) {
            checkInitializedWithoutEngine();
            this.mDebuggableApkPermitted = permitted;
            return this;
        }

        public Builder setOtherSignersSignaturesPreserved(boolean preserved) {
            checkInitializedWithoutEngine();
            this.mOtherSignersSignaturesPreserved = preserved;
            return this;
        }

        public Builder setCreatedBy(String createdBy) {
            checkInitializedWithoutEngine();
            if (createdBy == null) {
                throw new NullPointerException();
            }
            this.mCreatedBy = createdBy;
            return this;
        }

        private void checkInitializedWithoutEngine() {
            if (this.mSignerEngine != null) {
                throw new IllegalStateException("Operation is not available when builder initialized with an engine");
            }
        }

        public Builder setSigningCertificateLineage(SigningCertificateLineage signingCertificateLineage) {
            if (signingCertificateLineage != null) {
                this.mV3SigningEnabled = true;
                this.mSigningCertificateLineage = signingCertificateLineage;
            }
            return this;
        }

        public ApkSigner build() {
            if (!this.mV3SigningExplicitlyDisabled || !this.mV3SigningExplicitlyEnabled) {
                if (this.mV3SigningExplicitlyDisabled) {
                    this.mV3SigningEnabled = false;
                }
                if (this.mV3SigningExplicitlyEnabled) {
                    this.mV3SigningEnabled = true;
                }
                if (this.mV4SigningEnabled && !this.mV2SigningEnabled && !this.mV3SigningEnabled) {
                    if (!this.mV4ErrorReportingEnabled) {
                        this.mV4SigningEnabled = false;
                    } else {
                        throw new IllegalStateException("APK Signature Scheme v4 signing requires at least v2 or v3 signing to be enabled");
                    }
                }
                return new ApkSigner(this.mSignerConfigs, this.mSourceStampSignerConfig, this.mSourceStampSigningCertificateLineage, this.mForceSourceStampOverwrite, this.mMinSdkVersion, this.mV1SigningEnabled, this.mV2SigningEnabled, this.mV3SigningEnabled, this.mV4SigningEnabled, this.mVerityEnabled, this.mV4ErrorReportingEnabled, this.mDebuggableApkPermitted, this.mOtherSignersSignaturesPreserved, this.mCreatedBy, this.mSignerEngine, this.mInputApkFile, this.mInputApkDataSource, this.mOutputApkFile, this.mOutputApkDataSink, this.mOutputApkDataSource, this.mOutputV4File, this.mSigningCertificateLineage);
            }
            throw new IllegalStateException("Builder configured to both enable and disable APK Signature Scheme v3 signing");
        }
    }
}
