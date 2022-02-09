package com.android.apksig.internal.util;

import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Phaser;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class VerityTreeBuilder implements AutoCloseable {
    private static final int CHUNK_SIZE = 4096;
    private static final int DIGEST_PARALLELISM = Math.min(32, Runtime.getRuntime().availableProcessors());
    private static final String JCA_ALGORITHM = "SHA-256";
    private static final int MAX_OUTSTANDING_CHUNKS = 4;
    private static final int MAX_PREFETCH_CHUNKS = 1024;
    private static final int MIN_CHUNKS_PER_WORKER = 8;
    private final ExecutorService mExecutor = new ThreadPoolExecutor(DIGEST_PARALLELISM, DIGEST_PARALLELISM, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue(4), new ThreadPoolExecutor.CallerRunsPolicy());
    private final MessageDigest mMd;
    private final byte[] mSalt;

    public VerityTreeBuilder(byte[] salt) throws NoSuchAlgorithmException {
        this.mSalt = salt;
        this.mMd = getNewMessageDigest();
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        this.mExecutor.shutdownNow();
    }

    public byte[] generateVerityTreeRootHash(DataSource beforeApkSigningBlock, DataSource centralDir, DataSource eocd) throws IOException {
        if (beforeApkSigningBlock.size() % 4096 != 0) {
            throw new IllegalStateException("APK Signing Block size not a multiple of 4096: " + beforeApkSigningBlock.size());
        }
        long centralDirOffsetForDigesting = beforeApkSigningBlock.size();
        ByteBuffer eocdBuf = ByteBuffer.allocate((int) eocd.size());
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
        eocd.copyTo(0, (int) eocd.size(), eocdBuf);
        eocdBuf.flip();
        ZipUtils.setZipEocdCentralDirectoryOffset(eocdBuf, centralDirOffsetForDigesting);
        return generateVerityTreeRootHash(new ChainedDataSource(beforeApkSigningBlock, centralDir, DataSources.asDataSource(eocdBuf)));
    }

    public byte[] generateVerityTreeRootHash(DataSource fileSource) throws IOException {
        return getRootHashFromTree(generateVerityTree(fileSource));
    }

    public ByteBuffer generateVerityTree(DataSource fileSource) throws IOException {
        DataSource src;
        int digestSize = this.mMd.getDigestLength();
        int[] levelOffset = calculateLevelOffset(fileSource.size(), digestSize);
        ByteBuffer verityBuffer = ByteBuffer.allocate(levelOffset[levelOffset.length - 1]);
        for (int i = levelOffset.length - 2; i >= 0; i--) {
            DataSink middleBufferSink = new ByteBufferSink(slice(verityBuffer, levelOffset[i], levelOffset[i + 1]));
            if (i == levelOffset.length - 2) {
                src = fileSource;
                digestDataByChunks(src, middleBufferSink);
            } else {
                src = DataSources.asDataSource(slice(verityBuffer.asReadOnlyBuffer(), levelOffset[i + 1], levelOffset[i + 2]));
                digestDataByChunks(src, middleBufferSink);
            }
            int incomplete = (int) ((divideRoundup(src.size(), 4096) * ((long) digestSize)) % 4096);
            if (incomplete > 0) {
                byte[] padding = new byte[(4096 - incomplete)];
                middleBufferSink.consume(padding, 0, padding.length);
            }
        }
        return verityBuffer;
    }

    public byte[] getRootHashFromTree(ByteBuffer verityBuffer) throws IOException {
        return saltedDigest(slice(verityBuffer.asReadOnlyBuffer(), 0, 4096));
    }

    private static int[] calculateLevelOffset(long dataSize, int digestSize) {
        ArrayList<Long> levelSize = new ArrayList<>();
        while (true) {
            long chunkCount = divideRoundup(dataSize, 4096);
            levelSize.add(Long.valueOf(4096 * divideRoundup(((long) digestSize) * chunkCount, 4096)));
            if (((long) digestSize) * chunkCount <= 4096) {
                break;
            }
            dataSize = chunkCount * ((long) digestSize);
        }
        int[] levelOffset = new int[(levelSize.size() + 1)];
        levelOffset[0] = 0;
        for (int i = 0; i < levelSize.size(); i++) {
            levelOffset[i + 1] = Math.toIntExact(levelSize.get((levelSize.size() - i) - 1).longValue()) + levelOffset[i];
        }
        return levelOffset;
    }

    /*  JADX ERROR: MOVE_RESULT instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: MOVE_RESULT instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:604)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:542)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:249)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:217)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:110)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:56)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:93)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:59)
        	at jadx.core.codegen.RegionGen.makeRegionIndent(RegionGen.java:99)
        	at jadx.core.codegen.RegionGen.makeLoop(RegionGen.java:239)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:67)
        	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:93)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:59)
        	at jadx.core.codegen.MethodGen.addRegionInsns(MethodGen.java:244)
        	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:237)
        	at jadx.core.codegen.ClassGen.addMethodCode(ClassGen.java:342)
        	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:295)
        	at jadx.core.codegen.ClassGen.lambda$addInnerClsAndMethods$3(ClassGen.java:264)
        	at java.base/java.util.stream.ForEachOps$ForEachOp$OfRef.accept(Unknown Source)
        	at java.base/java.util.ArrayList.forEach(Unknown Source)
        	at java.base/java.util.stream.SortedOps$RefSortingSink.end(Unknown Source)
        	at java.base/java.util.stream.Sink$ChainedReference.end(Unknown Source)
        */
    private void digestDataByChunks(com.android.apksig.util.DataSource r29, com.android.apksig.util.DataSink r30) throws java.io.IOException {
        /*
        // Method dump skipped, instructions count: 155
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.util.VerityTreeBuilder.digestDataByChunks(com.android.apksig.util.DataSource, com.android.apksig.util.DataSink):void");
    }

    private /* synthetic */ void lambda$digestDataByChunks$0(ByteBuffer buffer, int readChunkIndex, byte[][] hashes, Phaser tasks) {
        MessageDigest md = cloneMessageDigest();
        int offset = 0;
        int finish = buffer.capacity();
        int chunkIndex = readChunkIndex;
        while (offset < finish) {
            hashes[chunkIndex] = saltedDigest(md, slice(buffer, offset, offset + 4096));
            offset += 4096;
            chunkIndex++;
        }
        tasks.arriveAndDeregister();
    }

    private byte[] saltedDigest(ByteBuffer data) {
        return saltedDigest(this.mMd, data);
    }

    private byte[] saltedDigest(MessageDigest md, ByteBuffer data) {
        md.reset();
        if (this.mSalt != null) {
            md.update(this.mSalt);
        }
        md.update(data);
        return md.digest();
    }

    private static long divideRoundup(long dividend, long divisor) {
        return ((dividend + divisor) - 1) / divisor;
    }

    private static ByteBuffer slice(ByteBuffer buffer, int begin, int end) {
        ByteBuffer b = buffer.duplicate();
        b.position(0);
        b.limit(end);
        b.position(begin);
        return b.slice();
    }

    private static MessageDigest getNewMessageDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(JCA_ALGORITHM);
    }

    private MessageDigest cloneMessageDigest() {
        try {
            return (MessageDigest) this.mMd.clone();
        } catch (CloneNotSupportedException e) {
            try {
                return getNewMessageDigest();
            } catch (NoSuchAlgorithmException e2) {
                throw new IllegalStateException("Failed to obtain an instance of a previously available message digest", e2);
            }
        }
    }
}
