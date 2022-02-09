package com.android.apksig.apk;

import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSource;
import com.android.apksig.zip.ZipFormatException;
import com.android.apksig.zip.ZipSections;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ApkUtilsLite {
    private static final long APK_SIG_BLOCK_MAGIC_HI = 3617552046287187010L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 2334950737559900225L;
    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;

    private ApkUtilsLite() {
    }

    public static ZipSections findZipSections(DataSource apk) throws IOException, ZipFormatException {
        Pair<ByteBuffer, Long> eocdAndOffsetInFile = ZipUtils.findZipEndOfCentralDirectoryRecord(apk);
        if (eocdAndOffsetInFile == null) {
            throw new ZipFormatException("ZIP End of Central Directory record not found");
        }
        ByteBuffer eocdBuf = eocdAndOffsetInFile.getFirst();
        long eocdOffset = eocdAndOffsetInFile.getSecond().longValue();
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
        long cdStartOffset = ZipUtils.getZipEocdCentralDirectoryOffset(eocdBuf);
        if (cdStartOffset > eocdOffset) {
            throw new ZipFormatException("ZIP Central Directory start offset out of range: " + cdStartOffset + ". ZIP End of Central Directory offset: " + eocdOffset);
        }
        long cdSizeBytes = ZipUtils.getZipEocdCentralDirectorySizeBytes(eocdBuf);
        long cdEndOffset = cdStartOffset + cdSizeBytes;
        if (cdEndOffset <= eocdOffset) {
            return new ZipSections(cdStartOffset, cdSizeBytes, ZipUtils.getZipEocdCentralDirectoryTotalRecordCount(eocdBuf), eocdOffset, eocdBuf);
        }
        throw new ZipFormatException("ZIP Central Directory overlaps with End of Central Directory. CD end: " + cdEndOffset + ", EoCD start: " + eocdOffset);
    }

    public static ApkSigningBlock findApkSigningBlock(DataSource apk, ZipSections zipSections) throws IOException, ApkSigningBlockNotFoundException {
        long centralDirStartOffset = zipSections.getZipCentralDirectoryOffset();
        long centralDirEndOffset = centralDirStartOffset + zipSections.getZipCentralDirectorySizeBytes();
        long eocdStartOffset = zipSections.getZipEndOfCentralDirectoryOffset();
        if (centralDirEndOffset != eocdStartOffset) {
            throw new ApkSigningBlockNotFoundException("ZIP Central Directory is not immediately followed by End of Central Directory. CD end: " + centralDirEndOffset + ", EoCD start: " + eocdStartOffset);
        } else if (centralDirStartOffset < 32) {
            throw new ApkSigningBlockNotFoundException("APK too small for APK Signing Block. ZIP Central Directory offset: " + centralDirStartOffset);
        } else {
            ByteBuffer footer = apk.getByteBuffer(centralDirStartOffset - 24, 24);
            footer.order(ByteOrder.LITTLE_ENDIAN);
            if (footer.getLong(8) == APK_SIG_BLOCK_MAGIC_LO && footer.getLong(16) == APK_SIG_BLOCK_MAGIC_HI) {
                long apkSigBlockSizeInFooter = footer.getLong(0);
                if (apkSigBlockSizeInFooter < ((long) footer.capacity()) || apkSigBlockSizeInFooter > 2147483639) {
                    throw new ApkSigningBlockNotFoundException("APK Signing Block size out of range: " + apkSigBlockSizeInFooter);
                }
                int totalSize = (int) (8 + apkSigBlockSizeInFooter);
                long apkSigBlockOffset = centralDirStartOffset - ((long) totalSize);
                if (apkSigBlockOffset < 0) {
                    throw new ApkSigningBlockNotFoundException("APK Signing Block offset out of range: " + apkSigBlockOffset);
                }
                ByteBuffer apkSigBlock = apk.getByteBuffer(apkSigBlockOffset, 8);
                apkSigBlock.order(ByteOrder.LITTLE_ENDIAN);
                long apkSigBlockSizeInHeader = apkSigBlock.getLong(0);
                if (apkSigBlockSizeInHeader == apkSigBlockSizeInFooter) {
                    return new ApkSigningBlock(apkSigBlockOffset, apk.slice(apkSigBlockOffset, (long) totalSize));
                }
                throw new ApkSigningBlockNotFoundException("APK Signing Block sizes in header and footer do not match: " + apkSigBlockSizeInHeader + " vs " + apkSigBlockSizeInFooter);
            }
            throw new ApkSigningBlockNotFoundException("No APK Signing Block before ZIP Central Directory");
        }
    }

    public static class ApkSigningBlock {
        private final DataSource mContents;
        private final long mStartOffsetInApk;

        public ApkSigningBlock(long startOffsetInApk, DataSource contents) {
            this.mStartOffsetInApk = startOffsetInApk;
            this.mContents = contents;
        }

        public long getStartOffset() {
            return this.mStartOffsetInApk;
        }

        public DataSource getContents() {
            return this.mContents;
        }
    }

    public static byte[] computeSha256DigestBytes(byte[] data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not found", e);
        }
    }
}
