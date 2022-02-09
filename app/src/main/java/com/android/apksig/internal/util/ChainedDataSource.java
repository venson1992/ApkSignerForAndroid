package com.android.apksig.internal.util;

import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class ChainedDataSource implements DataSource {
    private final DataSource[] mSources;
    private final long mTotalSize;

    /*  JADX ERROR: MOVE_RESULT instruction can be used only in fallback mode
        jadx.core.utils.exceptions.CodegenException: MOVE_RESULT instruction can be used only in fallback mode
        	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:604)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:542)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:230)
        	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:119)
        	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:103)
        	at jadx.core.codegen.InsnGen.generateMethodArguments(InsnGen.java:806)
        	at jadx.core.codegen.InsnGen.makeInvoke(InsnGen.java:746)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:367)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:230)
        	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:119)
        	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:103)
        	at jadx.core.codegen.InsnGen.addArgDot(InsnGen.java:87)
        	at jadx.core.codegen.InsnGen.makeInvoke(InsnGen.java:715)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:367)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:230)
        	at jadx.core.codegen.InsnGen.addWrappedArg(InsnGen.java:119)
        	at jadx.core.codegen.InsnGen.addArg(InsnGen.java:103)
        	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:428)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:249)
        	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:217)
        	at jadx.core.codegen.RegionGen.makeSimpleBlock(RegionGen.java:110)
        	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:56)
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
    public ChainedDataSource(com.android.apksig.util.DataSource... r3) {
        /*
            r2 = this;
            r2.<init>()
            r2.mSources = r3
            java.util.stream.Stream r0 = java.util.Arrays.stream(r3)
            r1 = move-result
            java.util.stream.LongStream r0 = r0.mapToLong(r1)
            long r0 = r0.sum()
            r2.mTotalSize = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.util.ChainedDataSource.<init>(com.android.apksig.util.DataSource[]):void");
    }

    @Override // com.android.apksig.util.DataSource
    public long size() {
        return this.mTotalSize;
    }

    @Override // com.android.apksig.util.DataSource
    public void feed(long offset, long size, DataSink sink) throws IOException {
        if (offset + size > this.mTotalSize) {
            throw new IndexOutOfBoundsException("Requested more than available");
        }
        DataSource[] dataSourceArr = this.mSources;
        for (DataSource src : dataSourceArr) {
            if (offset >= src.size()) {
                offset -= src.size();
            } else {
                long remaining = src.size() - offset;
                if (remaining >= size) {
                    src.feed(offset, size, sink);
                    return;
                }
                src.feed(offset, remaining, sink);
                size -= remaining;
                offset = 0;
            }
        }
    }

    @Override // com.android.apksig.util.DataSource
    public ByteBuffer getByteBuffer(long offset, int size) throws IOException {
        if (((long) size) + offset > this.mTotalSize) {
            throw new IndexOutOfBoundsException("Requested more than available");
        }
        Pair<Integer, Long> firstSource = locateDataSource(offset);
        int i = firstSource.getFirst().intValue();
        long offset2 = firstSource.getSecond().longValue();
        if (((long) size) + offset2 <= this.mSources[i].size()) {
            return this.mSources[i].getByteBuffer(offset2, size);
        }
        ByteBuffer buffer = ByteBuffer.allocate(size);
        while (i < this.mSources.length && buffer.hasRemaining()) {
            this.mSources[i].copyTo(offset2, Math.toIntExact(Math.min(this.mSources[i].size() - offset2, (long) buffer.remaining())), buffer);
            offset2 = 0;
            i++;
        }
        buffer.rewind();
        return buffer;
    }

    @Override // com.android.apksig.util.DataSource
    public void copyTo(long offset, int size, ByteBuffer dest) throws IOException {
        feed(offset, (long) size, new ByteBufferSink(dest));
    }

    @Override // com.android.apksig.util.DataSource
    public DataSource slice(long offset, long size) {
        Pair<Integer, Long> firstSource = locateDataSource(offset);
        int beginIndex = firstSource.getFirst().intValue();
        long beginLocalOffset = firstSource.getSecond().longValue();
        DataSource beginSource = this.mSources[beginIndex];
        if (beginLocalOffset + size <= beginSource.size()) {
            return beginSource.slice(beginLocalOffset, size);
        }
        ArrayList<DataSource> sources = new ArrayList<>();
        sources.add(beginSource.slice(beginLocalOffset, beginSource.size() - beginLocalOffset));
        Pair<Integer, Long> lastSource = locateDataSource((offset + size) - 1);
        int endIndex = lastSource.getFirst().intValue();
        long endLocalOffset = lastSource.getSecond().longValue();
        for (int i = beginIndex + 1; i < endIndex; i++) {
            sources.add(this.mSources[i]);
        }
        sources.add(this.mSources[endIndex].slice(0, 1 + endLocalOffset));
        return new ChainedDataSource((DataSource[]) sources.toArray(new DataSource[0]));
    }

    private Pair<Integer, Long> locateDataSource(long offset) {
        long localOffset = offset;
        for (int i = 0; i < this.mSources.length; i++) {
            if (localOffset < this.mSources[i].size()) {
                return Pair.of(Integer.valueOf(i), Long.valueOf(localOffset));
            }
            localOffset -= this.mSources[i].size();
        }
        throw new IndexOutOfBoundsException("Access is out of bound, offset: " + offset + ", totalSize: " + this.mTotalSize);
    }
}
