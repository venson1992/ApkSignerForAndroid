package com.android.apksig;

import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.RunnablesExecutor;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;
import java.util.Set;

public interface ApkSignerEngine extends Closeable {

    public interface InspectJarEntryRequest {
        void done();

        DataSink getDataSink();

        String getEntryName();
    }

    @Deprecated
    public interface OutputApkSigningBlockRequest {
        void done();

        byte[] getApkSigningBlock();
    }

    public interface OutputApkSigningBlockRequest2 {
        void done();

        byte[] getApkSigningBlock();

        int getPaddingSizeBeforeApkSigningBlock();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    void close();

    void inputApkSigningBlock(DataSource dataSource) throws IOException, ApkFormatException, IllegalStateException;

    InputJarEntryInstructions inputJarEntry(String str) throws IllegalStateException;

    InputJarEntryInstructions.OutputPolicy inputJarEntryRemoved(String str) throws IllegalStateException;

    void outputDone() throws IllegalStateException;

    OutputJarSignatureRequest outputJarEntries() throws ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalStateException;

    InspectJarEntryRequest outputJarEntry(String str) throws IllegalStateException;

    void outputJarEntryRemoved(String str) throws IllegalStateException;

    @Deprecated
    OutputApkSigningBlockRequest outputZipSections(DataSource dataSource, DataSource dataSource2, DataSource dataSource3) throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalStateException;

    OutputApkSigningBlockRequest2 outputZipSections2(DataSource dataSource, DataSource dataSource2, DataSource dataSource3) throws IOException, ApkFormatException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalStateException;

    void signV4(DataSource dataSource, File file, boolean z) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException;

    default void setExecutor(RunnablesExecutor executor) {
        throw new UnsupportedOperationException("setExecutor method is not implemented");
    }

    default Set<String> initWith(byte[] manifestBytes, Set<String> set) {
        throw new UnsupportedOperationException("initWith method is not implemented");
    }

    default boolean isEligibleForSourceStamp() {
        return false;
    }

    default byte[] generateSourceStampCertificateDigest() throws SignatureException {
        return new byte[0];
    }

    public static class InputJarEntryInstructions {
        private final InspectJarEntryRequest mInspectJarEntryRequest;
        private final OutputPolicy mOutputPolicy;

        public enum OutputPolicy {
            SKIP,
            OUTPUT,
            OUTPUT_BY_ENGINE
        }

        public InputJarEntryInstructions(OutputPolicy outputPolicy) {
            this(outputPolicy, null);
        }

        public InputJarEntryInstructions(OutputPolicy outputPolicy, InspectJarEntryRequest inspectJarEntryRequest) {
            this.mOutputPolicy = outputPolicy;
            this.mInspectJarEntryRequest = inspectJarEntryRequest;
        }

        public OutputPolicy getOutputPolicy() {
            return this.mOutputPolicy;
        }

        public InspectJarEntryRequest getInspectJarEntryRequest() {
            return this.mInspectJarEntryRequest;
        }
    }

    public interface OutputJarSignatureRequest {
        void done();

        List<JarEntry> getAdditionalJarEntries();

        public static class JarEntry {
            private final byte[] mData;
            private final String mName;

            public JarEntry(String name, byte[] data) {
                this.mName = name;
                this.mData = (byte[]) data.clone();
            }

            public String getName() {
                return this.mName;
            }

            public byte[] getData() {
                return (byte[]) this.mData.clone();
            }
        }
    }
}
