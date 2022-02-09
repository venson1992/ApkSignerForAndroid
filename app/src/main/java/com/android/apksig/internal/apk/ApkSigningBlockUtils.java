package com.android.apksig.internal.apk;

import com.android.apksig.ApkVerifier;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.ApkFormatException;
import com.android.apksig.apk.ApkUtils;
import com.android.apksig.internal.asn1.Asn1BerParser;
import com.android.apksig.internal.asn1.Asn1DecodingException;
import com.android.apksig.internal.asn1.Asn1DerEncoder;
import com.android.apksig.internal.asn1.Asn1EncodingException;
import com.android.apksig.internal.asn1.Asn1OpaqueObject;
import com.android.apksig.internal.pkcs7.AlgorithmIdentifier;
import com.android.apksig.internal.pkcs7.ContentInfo;
import com.android.apksig.internal.pkcs7.EncapsulatedContentInfo;
import com.android.apksig.internal.pkcs7.IssuerAndSerialNumber;
import com.android.apksig.internal.pkcs7.Pkcs7Constants;
import com.android.apksig.internal.pkcs7.SignedData;
import com.android.apksig.internal.pkcs7.SignerIdentifier;
import com.android.apksig.internal.pkcs7.SignerInfo;
import com.android.apksig.internal.util.ByteBufferDataSource;
import com.android.apksig.internal.util.ChainedDataSource;
import com.android.apksig.internal.util.Pair;
import com.android.apksig.internal.util.VerityTreeBuilder;
import com.android.apksig.internal.x509.RSAPublicKey;
import com.android.apksig.internal.x509.SubjectPublicKeyInfo;
import com.android.apksig.internal.zip.ZipUtils;
import com.android.apksig.util.DataSink;
import com.android.apksig.util.DataSinks;
import com.android.apksig.util.DataSource;
import com.android.apksig.util.DataSources;
import com.android.apksig.util.RunnablesExecutor;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public class ApkSigningBlockUtils {
    public static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 4096;
    private static final byte[] APK_SIGNING_BLOCK_MAGIC = {65, 80, 75, 32, 83, 105, 103, 32, 66, 108, 111, 99, 107, 32, 52, 50};
    private static final long CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1048576;
    private static final ContentDigestAlgorithm[] V4_CONTENT_DIGEST_ALGORITHMS = {ContentDigestAlgorithm.CHUNKED_SHA512, ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, ContentDigestAlgorithm.CHUNKED_SHA256};
    private static final int VERITY_PADDING_BLOCK_ID = 1114793335;
    public static final int VERSION_APK_SIGNATURE_SCHEME_V2 = 2;
    public static final int VERSION_APK_SIGNATURE_SCHEME_V3 = 3;
    public static final int VERSION_APK_SIGNATURE_SCHEME_V4 = 4;
    public static final int VERSION_JAR_SIGNATURE_SCHEME = 1;
    public static final int VERSION_SOURCE_STAMP = 0;

    public static class SignerConfig {
        public List<X509Certificate> certificates;
        public SigningCertificateLineage mSigningCertificateLineage;
        public int maxSdkVersion;
        public int minSdkVersion;
        public PrivateKey privateKey;
        public List<SignatureAlgorithm> signatureAlgorithms;
    }

    public static int compareSignatureAlgorithm(SignatureAlgorithm alg1, SignatureAlgorithm alg2) {
        return ApkSigningBlockUtilsLite.compareSignatureAlgorithm(alg1, alg2);
    }

    public static void verifyIntegrity(RunnablesExecutor executor, DataSource beforeApkSigningBlock, DataSource centralDir, ByteBuffer eocd, Set<ContentDigestAlgorithm> contentDigestAlgorithms, Result result) throws IOException, NoSuchAlgorithmException {
        if (contentDigestAlgorithms.isEmpty()) {
            throw new RuntimeException("No content digests found");
        }
        ByteBuffer modifiedEocd = ByteBuffer.allocate(eocd.remaining());
        int eocdSavedPos = eocd.position();
        modifiedEocd.order(ByteOrder.LITTLE_ENDIAN);
        modifiedEocd.put(eocd);
        modifiedEocd.flip();
        eocd.position(eocdSavedPos);
        ZipUtils.setZipEocdCentralDirectoryOffset(modifiedEocd, beforeApkSigningBlock.size());
        try {
            Map<ContentDigestAlgorithm, byte[]> actualContentDigests = computeContentDigests(executor, contentDigestAlgorithms, beforeApkSigningBlock, centralDir, new ByteBufferDataSource(modifiedEocd));
            if (actualContentDigests.containsKey(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)) {
                if (beforeApkSigningBlock.size() % 4096 != 0) {
                    throw new RuntimeException("APK Signing Block is not aligned on 4k boundary: " + beforeApkSigningBlock.size());
                }
                long signingBlockSize = ZipUtils.getZipEocdCentralDirectoryOffset(eocd) - beforeApkSigningBlock.size();
                if (signingBlockSize % 4096 != 0) {
                    throw new RuntimeException("APK Signing Block size is not multiple of page size: " + signingBlockSize);
                }
            }
            if (!contentDigestAlgorithms.equals(actualContentDigests.keySet())) {
                throw new RuntimeException("Mismatch between sets of requested and computed content digests . Requested: " + contentDigestAlgorithms + ", computed: " + actualContentDigests.keySet());
            }
            for (Result.SignerInfo signerInfo : result.signers) {
                for (Result.SignerInfo.ContentDigest expected : signerInfo.contentDigests) {
                    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.findById(expected.getSignatureAlgorithmId());
                    if (signatureAlgorithm != null) {
                        ContentDigestAlgorithm contentDigestAlgorithm = signatureAlgorithm.getContentDigestAlgorithm();
                        if (contentDigestAlgorithms.contains(contentDigestAlgorithm)) {
                            byte[] expectedDigest = expected.getValue();
                            byte[] actualDigest = actualContentDigests.get(contentDigestAlgorithm);
                            if (Arrays.equals(expectedDigest, actualDigest)) {
                                signerInfo.verifiedContentDigests.put(contentDigestAlgorithm, actualDigest);
                            } else if (result.signatureSchemeVersion == 2) {
                                signerInfo.addError(ApkVerifier.Issue.V2_SIG_APK_DIGEST_DID_NOT_VERIFY, contentDigestAlgorithm, toHex(expectedDigest), toHex(actualDigest));
                            } else if (result.signatureSchemeVersion == 3) {
                                signerInfo.addError(ApkVerifier.Issue.V3_SIG_APK_DIGEST_DID_NOT_VERIFY, contentDigestAlgorithm, toHex(expectedDigest), toHex(actualDigest));
                            }
                        }
                    }
                }
            }
        } catch (DigestException e) {
            throw new RuntimeException("Failed to compute content digests", e);
        }
    }

    public static ByteBuffer findApkSignatureSchemeBlock(ByteBuffer apkSigningBlock, int blockId, Result result) throws SignatureNotFoundException {
        try {
            return ApkSigningBlockUtilsLite.findApkSignatureSchemeBlock(apkSigningBlock, blockId);
        } catch (SignatureNotFoundException e) {
            throw new SignatureNotFoundException(e.getMessage());
        }
    }

    public static void checkByteOrderLittleEndian(ByteBuffer buffer) {
        ApkSigningBlockUtilsLite.checkByteOrderLittleEndian(buffer);
    }

    public static ByteBuffer getLengthPrefixedSlice(ByteBuffer source) throws ApkFormatException {
        return ApkSigningBlockUtilsLite.getLengthPrefixedSlice(source);
    }

    public static byte[] readLengthPrefixedByteArray(ByteBuffer buf) throws ApkFormatException {
        return ApkSigningBlockUtilsLite.readLengthPrefixedByteArray(buf);
    }

    public static String toHex(byte[] value) {
        return ApkSigningBlockUtilsLite.toHex(value);
    }

    public static Map<ContentDigestAlgorithm, byte[]> computeContentDigests(RunnablesExecutor executor, Set<ContentDigestAlgorithm> digestAlgorithms, DataSource beforeCentralDir, DataSource centralDir, DataSource eocd) throws IOException, NoSuchAlgorithmException, DigestException {
        Map<ContentDigestAlgorithm, byte[]> contentDigests = new HashMap<>();
        Set<ContentDigestAlgorithm> oneMbChunkBasedAlgorithm = new HashSet<>();
        for (ContentDigestAlgorithm digestAlgorithm : digestAlgorithms) {
            if (digestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA256 || digestAlgorithm == ContentDigestAlgorithm.CHUNKED_SHA512) {
                oneMbChunkBasedAlgorithm.add(digestAlgorithm);
            }
        }
        computeOneMbChunkContentDigests(executor, oneMbChunkBasedAlgorithm, new DataSource[]{beforeCentralDir, centralDir, eocd}, contentDigests);
        if (digestAlgorithms.contains(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256)) {
            computeApkVerityDigest(beforeCentralDir, centralDir, eocd, contentDigests);
        }
        return contentDigests;
    }

    static void computeOneMbChunkContentDigests(Set<ContentDigestAlgorithm> digestAlgorithms, DataSource[] contents, Map<ContentDigestAlgorithm, byte[]> outputContentDigests) throws IOException, NoSuchAlgorithmException, DigestException {
        long chunkCountLong = 0;
        for (DataSource input : contents) {
            chunkCountLong += getChunkCount(input.size(), CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
        }
        if (chunkCountLong > 2147483647L) {
            throw new DigestException("Input too long: " + chunkCountLong + " chunks");
        }
        int chunkCount = (int) chunkCountLong;
        ContentDigestAlgorithm[] digestAlgorithmsArray = (ContentDigestAlgorithm[]) digestAlgorithms.toArray(new ContentDigestAlgorithm[digestAlgorithms.size()]);
        MessageDigest[] mds = new MessageDigest[digestAlgorithmsArray.length];
        byte[][] digestsOfChunks = new byte[digestAlgorithmsArray.length][];
        int[] digestOutputSizes = new int[digestAlgorithmsArray.length];
        for (int i = 0; i < digestAlgorithmsArray.length; i++) {
            ContentDigestAlgorithm digestAlgorithm = digestAlgorithmsArray[i];
            int digestOutputSizeBytes = digestAlgorithm.getChunkDigestOutputSizeBytes();
            digestOutputSizes[i] = digestOutputSizeBytes;
            byte[] concatenationOfChunkCountAndChunkDigests = new byte[((chunkCount * digestOutputSizeBytes) + 5)];
            concatenationOfChunkCountAndChunkDigests[0] = 90;
            setUnsignedInt32LittleEndian(chunkCount, concatenationOfChunkCountAndChunkDigests, 1);
            digestsOfChunks[i] = concatenationOfChunkCountAndChunkDigests;
            mds[i] = MessageDigest.getInstance(digestAlgorithm.getJcaMessageDigestAlgorithm());
        }
        DataSink mdSink = DataSinks.asDataSink(mds);
        byte[] chunkContentPrefix = new byte[5];
        chunkContentPrefix[0] = -91;
        int chunkIndex = 0;
        int length = contents.length;
        for (int i2 = 0; i2 < length; i2++) {
            DataSource input2 = contents[i2];
            long inputOffset = 0;
            long inputRemaining = input2.size();
            while (inputRemaining > 0) {
                int chunkSize = (int) Math.min(inputRemaining, (long) CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
                setUnsignedInt32LittleEndian(chunkSize, chunkContentPrefix, 1);
                for (int i3 = 0; i3 < mds.length; i3++) {
                    mds[i3].update(chunkContentPrefix);
                }
                try {
                    input2.feed(inputOffset, (long) chunkSize, mdSink);
                    for (int i4 = 0; i4 < digestAlgorithmsArray.length; i4++) {
                        MessageDigest md = mds[i4];
                        byte[] concatenationOfChunkCountAndChunkDigests2 = digestsOfChunks[i4];
                        int expectedDigestSizeBytes = digestOutputSizes[i4];
                        int actualDigestSizeBytes = md.digest(concatenationOfChunkCountAndChunkDigests2, (chunkIndex * expectedDigestSizeBytes) + 5, expectedDigestSizeBytes);
                        if (actualDigestSizeBytes != expectedDigestSizeBytes) {
                            throw new RuntimeException("Unexpected output size of " + md.getAlgorithm() + " digest: " + actualDigestSizeBytes);
                        }
                    }
                    inputOffset += (long) chunkSize;
                    inputRemaining -= (long) chunkSize;
                    chunkIndex++;
                } catch (IOException e) {
                    throw new IOException("Failed to read chunk #" + chunkIndex, e);
                }
            }
        }
        for (int i5 = 0; i5 < digestAlgorithmsArray.length; i5++) {
            outputContentDigests.put(digestAlgorithmsArray[i5], mds[i5].digest(digestsOfChunks[i5]));
        }
    }

    /* JADX DEBUG: Multi-variable search result rejected for r18v0, resolved type: com.android.apksig.util.RunnablesExecutor */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v6, types: [void, com.android.apksig.util.RunnablesProvider] */
    /* JADX WARNING: Unknown variable types count: 1 */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    static void computeOneMbChunkContentDigests(com.android.apksig.util.RunnablesExecutor r18, java.util.Set<com.android.apksig.internal.apk.ContentDigestAlgorithm> r19, com.android.apksig.util.DataSource[] r20, java.util.Map<com.android.apksig.internal.apk.ContentDigestAlgorithm, byte[]> r21) throws java.security.NoSuchAlgorithmException, java.security.DigestException {
        /*
        // Method dump skipped, instructions count: 155
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.apk.ApkSigningBlockUtils.computeOneMbChunkContentDigests(com.android.apksig.util.RunnablesExecutor, java.util.Set, com.android.apksig.util.DataSource[], java.util.Map):void");
    }

    private static /* synthetic */ Runnable lambda$computeOneMbChunkContentDigests$0(ChunkSupplier chunkSupplier, List chunkDigestsList) {
        return new ChunkDigester(chunkSupplier, chunkDigestsList);
    }

    /* access modifiers changed from: private */
    public static class ChunkDigests {
        private final ContentDigestAlgorithm algorithm;
        private final byte[] concatOfDigestsOfChunks;
        private final int digestOutputSize;

        private ChunkDigests(ContentDigestAlgorithm algorithm2, int chunkCount) {
            this.algorithm = algorithm2;
            this.digestOutputSize = this.algorithm.getChunkDigestOutputSizeBytes();
            this.concatOfDigestsOfChunks = new byte[((this.digestOutputSize * chunkCount) + 5)];
            this.concatOfDigestsOfChunks[0] = 90;
            ApkSigningBlockUtils.setUnsignedInt32LittleEndian(chunkCount, this.concatOfDigestsOfChunks, 1);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private MessageDigest createMessageDigest() throws NoSuchAlgorithmException {
            return MessageDigest.getInstance(this.algorithm.getJcaMessageDigestAlgorithm());
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private int getOffset(int chunkIndex) {
            return (this.digestOutputSize * chunkIndex) + 5;
        }
    }

    private static class ChunkDigester implements Runnable {
        private final List<ChunkDigests> chunkDigests;
        private final ChunkSupplier dataSupplier;
        private final DataSink mdSink;
        private final List<MessageDigest> messageDigests;

        private ChunkDigester(ChunkSupplier dataSupplier2, List<ChunkDigests> chunkDigests2) {
            this.dataSupplier = dataSupplier2;
            this.chunkDigests = chunkDigests2;
            this.messageDigests = new ArrayList(chunkDigests2.size());
            for (ChunkDigests chunkDigest : chunkDigests2) {
                try {
                    this.messageDigests.add(chunkDigest.createMessageDigest());
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                }
            }
            this.mdSink = DataSinks.asDataSink((MessageDigest[]) this.messageDigests.toArray(new MessageDigest[0]));
        }

        public void run() {
            byte[] chunkContentPrefix = new byte[5];
            chunkContentPrefix[0] = -91;
            try {
                ChunkSupplier.Chunk chunk = this.dataSupplier.get();
                while (chunk != null) {
                    int size = chunk.size;
                    if (((long) size) > ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES) {
                        throw new RuntimeException("Chunk size greater than expected: " + size);
                    }
                    ApkSigningBlockUtils.setUnsignedInt32LittleEndian(size, chunkContentPrefix, 1);
                    this.mdSink.consume(chunkContentPrefix, 0, chunkContentPrefix.length);
                    this.mdSink.consume(chunk.data);
                    for (int i = 0; i < this.chunkDigests.size(); i++) {
                        ChunkDigests chunkDigest = this.chunkDigests.get(i);
                        int actualDigestSize = this.messageDigests.get(i).digest(chunkDigest.concatOfDigestsOfChunks, chunkDigest.getOffset(chunk.chunkIndex), chunkDigest.digestOutputSize);
                        if (actualDigestSize != chunkDigest.digestOutputSize) {
                            throw new RuntimeException("Unexpected output size of " + chunkDigest.algorithm + " digest: " + actualDigestSize);
                        }
                    }
                    chunk = this.dataSupplier.get();
                }
            } catch (IOException | DigestException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /* access modifiers changed from: private */
    public static class ChunkSupplier implements Supplier<Chunk> {
        private final int[] chunkCounts;
        private final DataSource[] dataSources;
        private final AtomicInteger nextIndex;
        private final int totalChunkCount;

        private ChunkSupplier(DataSource[] dataSources2) {
            this.dataSources = dataSources2;
            this.chunkCounts = new int[dataSources2.length];
            int totalChunkCount2 = 0;
            for (int i = 0; i < dataSources2.length; i++) {
                long chunkCount = ApkSigningBlockUtils.getChunkCount(dataSources2[i].size(), ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
                if (chunkCount > 2147483647L) {
                    throw new RuntimeException(String.format("Number of chunks in dataSource[%d] is greater than max int.", Integer.valueOf(i)));
                }
                this.chunkCounts[i] = (int) chunkCount;
                totalChunkCount2 = (int) (((long) totalChunkCount2) + chunkCount);
            }
            this.totalChunkCount = totalChunkCount2;
            this.nextIndex = new AtomicInteger(0);
        }

        @Override // java.util.function.Supplier
        public Chunk get() {
            int index = this.nextIndex.getAndIncrement();
            if (index < 0 || index >= this.totalChunkCount) {
                return null;
            }
            int dataSourceIndex = 0;
            long dataSourceChunkOffset = (long) index;
            while (dataSourceIndex < this.dataSources.length && dataSourceChunkOffset >= ((long) this.chunkCounts[dataSourceIndex])) {
                dataSourceChunkOffset -= (long) this.chunkCounts[dataSourceIndex];
                dataSourceIndex++;
            }
            int size = (int) Math.min(this.dataSources[dataSourceIndex].size() - (ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES * dataSourceChunkOffset), (long) ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES);
            ByteBuffer buffer = ByteBuffer.allocate(size);
            try {
                this.dataSources[dataSourceIndex].copyTo(ApkSigningBlockUtils.CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES * dataSourceChunkOffset, size, buffer);
                buffer.rewind();
                return new Chunk(index, buffer, size);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read chunk", e);
            }
        }

        /* access modifiers changed from: package-private */
        public static class Chunk {
            private final int chunkIndex;
            private final ByteBuffer data;
            private final int size;

            private Chunk(int chunkIndex2, ByteBuffer data2, int size2) {
                this.chunkIndex = chunkIndex2;
                this.data = data2;
                this.size = size2;
            }
        }
    }

    private static void computeApkVerityDigest(DataSource beforeCentralDir, DataSource centralDir, DataSource eocd, Map<ContentDigestAlgorithm, byte[]> outputContentDigests) throws IOException, NoSuchAlgorithmException {
        ByteBuffer encoded = createVerityDigestBuffer(true);
        VerityTreeBuilder builder = new VerityTreeBuilder(new byte[8]);
        try {
            encoded.put(builder.generateVerityTreeRootHash(beforeCentralDir, centralDir, eocd));
            encoded.putLong(beforeCentralDir.size() + centralDir.size() + eocd.size());
            outputContentDigests.put(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, encoded.array());
            builder.close();
            return;
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    }

    private static ByteBuffer createVerityDigestBuffer(boolean includeSourceDataSize) {
        int backBufferSize = ContentDigestAlgorithm.VERITY_CHUNKED_SHA256.getChunkDigestOutputSizeBytes();
        if (includeSourceDataSize) {
            backBufferSize += 8;
        }
        ByteBuffer encoded = ByteBuffer.allocate(backBufferSize);
        encoded.order(ByteOrder.LITTLE_ENDIAN);
        return encoded;
    }

    public static class VerityTreeAndDigest {
        public final ContentDigestAlgorithm contentDigestAlgorithm;
        public final byte[] rootHash;
        public final byte[] tree;

        VerityTreeAndDigest(ContentDigestAlgorithm contentDigestAlgorithm2, byte[] rootHash2, byte[] tree2) {
            this.contentDigestAlgorithm = contentDigestAlgorithm2;
            this.rootHash = rootHash2;
            this.tree = tree2;
        }
    }

    public static VerityTreeAndDigest computeChunkVerityTreeAndDigest(DataSource dataSource) throws IOException, NoSuchAlgorithmException {
        ByteBuffer encoded = createVerityDigestBuffer(false);
        VerityTreeBuilder builder = new VerityTreeBuilder(null);
        try {
            ByteBuffer tree = builder.generateVerityTree(dataSource);
            encoded.put(builder.getRootHashFromTree(tree));
            VerityTreeAndDigest verityTreeAndDigest = new VerityTreeAndDigest(ContentDigestAlgorithm.VERITY_CHUNKED_SHA256, encoded.array(), tree.array());
            builder.close();
            return verityTreeAndDigest;
        } catch (Throwable th) {
            th.addSuppressed(th);
        }
        throw th;
    }

    /* access modifiers changed from: private */
    public static long getChunkCount(long inputSize, long chunkSize) {
        return ((inputSize + chunkSize) - 1) / chunkSize;
    }

    /* access modifiers changed from: private */
    public static void setUnsignedInt32LittleEndian(int value, byte[] result, int offset) {
        result[offset] = (byte) (value & 255);
        result[offset + 1] = (byte) ((value >> 8) & 255);
        result[offset + 2] = (byte) ((value >> 16) & 255);
        result[offset + 3] = (byte) ((value >> 24) & 255);
    }

    public static byte[] encodePublicKey(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] encodedPublicKey = null;
        if ("X.509".equals(publicKey.getFormat())) {
            encodedPublicKey = publicKey.getEncoded();
            if ("RSA".equals(publicKey.getAlgorithm())) {
                try {
                    SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) Asn1BerParser.parse(ByteBuffer.wrap(encodedPublicKey), SubjectPublicKeyInfo.class);
                    ByteBuffer subjectPublicKeyBuffer = subjectPublicKeyInfo.subjectPublicKey;
                    byte padding = subjectPublicKeyBuffer.get();
                    RSAPublicKey rsaPublicKey = (RSAPublicKey) Asn1BerParser.parse(subjectPublicKeyBuffer, RSAPublicKey.class);
                    if (rsaPublicKey.modulus.compareTo(BigInteger.ZERO) < 0) {
                        byte[] encodedModulus = rsaPublicKey.modulus.toByteArray();
                        byte[] reencodedModulus = new byte[(encodedModulus.length + 1)];
                        reencodedModulus[0] = 0;
                        System.arraycopy(encodedModulus, 0, reencodedModulus, 1, encodedModulus.length);
                        rsaPublicKey.modulus = new BigInteger(reencodedModulus);
                        byte[] reencodedRSAPublicKey = Asn1DerEncoder.encode(rsaPublicKey);
                        byte[] reencodedSubjectPublicKey = new byte[(reencodedRSAPublicKey.length + 1)];
                        reencodedSubjectPublicKey[0] = padding;
                        System.arraycopy(reencodedRSAPublicKey, 0, reencodedSubjectPublicKey, 1, reencodedRSAPublicKey.length);
                        subjectPublicKeyInfo.subjectPublicKey = ByteBuffer.wrap(reencodedSubjectPublicKey);
                        encodedPublicKey = Asn1DerEncoder.encode(subjectPublicKeyInfo);
                    }
                } catch (Asn1DecodingException | Asn1EncodingException e) {
                    System.out.println("Caught a exception encoding the public key: " + e);
                    e.printStackTrace();
                    encodedPublicKey = null;
                }
            }
        }
        if (encodedPublicKey == null) {
            try {
                encodedPublicKey = ((X509EncodedKeySpec) KeyFactory.getInstance(publicKey.getAlgorithm()).getKeySpec(publicKey, X509EncodedKeySpec.class)).getEncoded();
            } catch (InvalidKeySpecException e2) {
                throw new InvalidKeyException("Failed to obtain X.509 encoded form of public key " + publicKey + " of class " + publicKey.getClass().getName(), e2);
            }
        }
        if (encodedPublicKey != null && encodedPublicKey.length != 0) {
            return encodedPublicKey;
        }
        throw new InvalidKeyException("Failed to obtain X.509 encoded form of public key " + publicKey + " of class " + publicKey.getClass().getName());
    }

    public static List<byte[]> encodeCertificates(List<X509Certificate> certificates) throws CertificateEncodingException {
        List<byte[]> result = new ArrayList<>(certificates.size());
        for (X509Certificate certificate : certificates) {
            result.add(certificate.getEncoded());
        }
        return result;
    }

    public static byte[] encodeAsLengthPrefixedElement(byte[] bytes) {
        return encodeAsSequenceOfLengthPrefixedElements(new byte[][]{bytes});
    }

    public static byte[] encodeAsSequenceOfLengthPrefixedElements(List<byte[]> sequence) {
        return encodeAsSequenceOfLengthPrefixedElements((byte[][]) sequence.toArray(new byte[sequence.size()][]));
    }

    public static byte[] encodeAsSequenceOfLengthPrefixedElements(byte[][] sequence) {
        int payloadSize = 0;
        for (byte[] element : sequence) {
            payloadSize += element.length + 4;
        }
        ByteBuffer result = ByteBuffer.allocate(payloadSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        for (byte[] element2 : sequence) {
            result.putInt(element2.length);
            result.put(element2);
        }
        return result.array();
    }

    public static byte[] encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(List<Pair<Integer, byte[]>> sequence) {
        return ApkSigningBlockUtilsLite.encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(sequence);
    }

    public static SignatureInfo findSignature(DataSource apk, ApkUtils.ZipSections zipSections, int blockId, Result result) throws IOException, SignatureNotFoundException {
        try {
            return ApkSigningBlockUtilsLite.findSignature(apk, zipSections, blockId);
        } catch (SignatureNotFoundException e) {
            throw new SignatureNotFoundException(e.getMessage());
        }
    }

    public static Pair<DataSource, Integer> generateApkSigningBlockPadding(DataSource beforeCentralDir, boolean apkSigningBlockPaddingSupported) {
        int padSizeBeforeSigningBlock = 0;
        if (apkSigningBlockPaddingSupported && beforeCentralDir.size() % 4096 != 0) {
            padSizeBeforeSigningBlock = (int) (4096 - (beforeCentralDir.size() % 4096));
            beforeCentralDir = new ChainedDataSource(beforeCentralDir, DataSources.asDataSource(ByteBuffer.allocate(padSizeBeforeSigningBlock)));
        }
        return Pair.of(beforeCentralDir, Integer.valueOf(padSizeBeforeSigningBlock));
    }

    public static DataSource copyWithModifiedCDOffset(DataSource beforeCentralDir, DataSource eocd) throws IOException {
        long centralDirOffsetForDigesting = beforeCentralDir.size();
        ByteBuffer eocdBuf = ByteBuffer.allocate((int) eocd.size());
        eocdBuf.order(ByteOrder.LITTLE_ENDIAN);
        eocd.copyTo(0, (int) eocd.size(), eocdBuf);
        eocdBuf.flip();
        ZipUtils.setZipEocdCentralDirectoryOffset(eocdBuf, centralDirOffsetForDigesting);
        return DataSources.asDataSource(eocdBuf);
    }

    public static byte[] generateApkSigningBlock(List<Pair<byte[], Integer>> apkSignatureSchemeBlockPairs) {
        int blocksSize = 0;
        for (Pair<byte[], Integer> schemeBlockPair : apkSignatureSchemeBlockPairs) {
            blocksSize += schemeBlockPair.getFirst().length + 12;
        }
        int resultSize = blocksSize + 8 + 8 + 16;
        ByteBuffer paddingPair = null;
        if (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0) {
            int padding = 4096 - (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
            if (padding < 12) {
                padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES;
            }
            paddingPair = ByteBuffer.allocate(padding).order(ByteOrder.LITTLE_ENDIAN);
            paddingPair.putLong((long) (padding - 8));
            paddingPair.putInt(VERITY_PADDING_BLOCK_ID);
            paddingPair.rewind();
            resultSize += padding;
        }
        ByteBuffer result = ByteBuffer.allocate(resultSize);
        result.order(ByteOrder.LITTLE_ENDIAN);
        long blockSizeFieldValue = ((long) resultSize) - 8;
        result.putLong(blockSizeFieldValue);
        for (Pair<byte[], Integer> schemeBlockPair2 : apkSignatureSchemeBlockPairs) {
            byte[] apkSignatureSchemeBlock = schemeBlockPair2.getFirst();
            int apkSignatureSchemeId = schemeBlockPair2.getSecond().intValue();
            result.putLong(4 + ((long) apkSignatureSchemeBlock.length));
            result.putInt(apkSignatureSchemeId);
            result.put(apkSignatureSchemeBlock);
        }
        if (paddingPair != null) {
            result.put(paddingPair);
        }
        result.putLong(blockSizeFieldValue);
        result.put(APK_SIGNING_BLOCK_MAGIC);
        return result.array();
    }

    public static Pair<List<SignerConfig>, Map<ContentDigestAlgorithm, byte[]>> computeContentDigests(RunnablesExecutor executor, DataSource beforeCentralDir, DataSource centralDir, DataSource eocd, List<SignerConfig> signerConfigs) throws IOException, NoSuchAlgorithmException, SignatureException {
        if (signerConfigs.isEmpty()) {
            throw new IllegalArgumentException("No signer configs provided. At least one is required");
        }
        Set<ContentDigestAlgorithm> contentDigestAlgorithms = new HashSet<>(1);
        for (SignerConfig signerConfig : signerConfigs) {
            for (SignatureAlgorithm signatureAlgorithm : signerConfig.signatureAlgorithms) {
                contentDigestAlgorithms.add(signatureAlgorithm.getContentDigestAlgorithm());
            }
        }
        try {
            return Pair.of(signerConfigs, computeContentDigests(executor, contentDigestAlgorithms, beforeCentralDir, centralDir, eocd));
        } catch (IOException e) {
            throw new IOException("Failed to read APK being signed", e);
        } catch (DigestException e2) {
            throw new SignatureException("Failed to compute digests of APK", e2);
        }
    }

    public static <T extends ApkSupportedSignature> List<T> getSignaturesToVerify(List<T> signatures, int minSdkVersion, int maxSdkVersion) throws NoSupportedSignaturesException {
        return getSignaturesToVerify(signatures, minSdkVersion, maxSdkVersion, false);
    }

    public static <T extends ApkSupportedSignature> List<T> getSignaturesToVerify(List<T> signatures, int minSdkVersion, int maxSdkVersion, boolean onlyRequireJcaSupport) throws NoSupportedSignaturesException {
        try {
            return ApkSigningBlockUtilsLite.getSignaturesToVerify(signatures, minSdkVersion, maxSdkVersion, onlyRequireJcaSupport);
        } catch (NoApkSupportedSignaturesException e) {
            throw new NoSupportedSignaturesException(e.getMessage());
        }
    }

    public static class NoSupportedSignaturesException extends NoApkSupportedSignaturesException {
        public NoSupportedSignaturesException(String message) {
            super(message);
        }
    }

    public static class SignatureNotFoundException extends Exception {
        private static final long serialVersionUID = 1;

        public SignatureNotFoundException(String message) {
            super(message);
        }

        public SignatureNotFoundException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static List<Pair<Integer, byte[]>> generateSignaturesOverData(SignerConfig signerConfig, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        List<Pair<Integer, byte[]>> signatures = new ArrayList<>(signerConfig.signatureAlgorithms.size());
        PublicKey publicKey = signerConfig.certificates.get(0).getPublicKey();
        for (SignatureAlgorithm signatureAlgorithm : signerConfig.signatureAlgorithms) {
            Pair<String, ? extends AlgorithmParameterSpec> sigAlgAndParams = signatureAlgorithm.getJcaSignatureAlgorithmAndParams();
            String jcaSignatureAlgorithm = sigAlgAndParams.getFirst();
            AlgorithmParameterSpec jcaSignatureAlgorithmParams = (AlgorithmParameterSpec) sigAlgAndParams.getSecond();
            try {
                Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
                signature.initSign(signerConfig.privateKey);
                if (jcaSignatureAlgorithmParams != null) {
                    signature.setParameter(jcaSignatureAlgorithmParams);
                }
                signature.update(data);
                byte[] signatureBytes = signature.sign();
                try {
                    Signature signature2 = Signature.getInstance(jcaSignatureAlgorithm);
                    signature2.initVerify(publicKey);
                    if (jcaSignatureAlgorithmParams != null) {
                        signature2.setParameter(jcaSignatureAlgorithmParams);
                    }
                    signature2.update(data);
                    if (!signature2.verify(signatureBytes)) {
                        throw new SignatureException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using public key from certificate");
                    }
                    signatures.add(Pair.of(Integer.valueOf(signatureAlgorithm.getId()), signatureBytes));
                } catch (InvalidKeyException e) {
                    throw new InvalidKeyException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using public key from certificate", e);
                } catch (InvalidAlgorithmParameterException | SignatureException e2) {
                    throw new SignatureException("Failed to verify generated " + jcaSignatureAlgorithm + " signature using public key from certificate", e2);
                }
            } catch (InvalidKeyException e3) {
                throw new InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e3);
            } catch (InvalidAlgorithmParameterException | SignatureException e4) {
                throw new SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e4);
            }
        }
        return signatures;
    }

    public static byte[] generatePkcs7DerEncodedMessage(byte[] signatureBytes, ByteBuffer data, List<X509Certificate> signerCerts, AlgorithmIdentifier digestAlgorithmId, AlgorithmIdentifier signatureAlgorithmId) throws Asn1EncodingException, CertificateEncodingException {
        SignerInfo signerInfo = new SignerInfo();
        signerInfo.version = 1;
        X509Certificate signingCert = signerCerts.get(0);
        signerInfo.sid = new SignerIdentifier(new IssuerAndSerialNumber(new Asn1OpaqueObject(signingCert.getIssuerX500Principal().getEncoded()), signingCert.getSerialNumber()));
        signerInfo.digestAlgorithm = digestAlgorithmId;
        signerInfo.signatureAlgorithm = signatureAlgorithmId;
        signerInfo.signature = ByteBuffer.wrap(signatureBytes);
        SignedData signedData = new SignedData();
        signedData.certificates = new ArrayList(signerCerts.size());
        for (X509Certificate cert : signerCerts) {
            signedData.certificates.add(new Asn1OpaqueObject(cert.getEncoded()));
        }
        signedData.version = 1;
        signedData.digestAlgorithms = Collections.singletonList(digestAlgorithmId);
        signedData.encapContentInfo = new EncapsulatedContentInfo(Pkcs7Constants.OID_DATA);
        signedData.encapContentInfo.content = data;
        signedData.signerInfos = Collections.singletonList(signerInfo);
        ContentInfo contentInfo = new ContentInfo();
        contentInfo.contentType = Pkcs7Constants.OID_SIGNED_DATA;
        contentInfo.content = new Asn1OpaqueObject(Asn1DerEncoder.encode(signedData));
        return Asn1DerEncoder.encode(contentInfo);
    }

    public static byte[] pickBestDigestForV4(Map<ContentDigestAlgorithm, byte[]> contentDigests) {
        ContentDigestAlgorithm[] contentDigestAlgorithmArr = V4_CONTENT_DIGEST_ALGORITHMS;
        for (ContentDigestAlgorithm algo : contentDigestAlgorithmArr) {
            if (contentDigests.containsKey(algo)) {
                return contentDigests.get(algo);
            }
        }
        return null;
    }

    public static class Result extends ApkSigResult {
        private final List<ApkVerifier.IssueWithParams> mErrors = new ArrayList();
        private final List<ApkVerifier.IssueWithParams> mWarnings = new ArrayList();
        public final List<SignerInfo> signers = new ArrayList();
        public SigningCertificateLineage signingCertificateLineage = null;

        public Result(int signatureSchemeVersion) {
            super(signatureSchemeVersion);
        }

        @Override // com.android.apksig.internal.apk.ApkSigResult
        public boolean containsErrors() {
            if (!this.mErrors.isEmpty()) {
                return true;
            }
            if (!this.signers.isEmpty()) {
                for (SignerInfo signer : this.signers) {
                    if (signer.containsErrors()) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override // com.android.apksig.internal.apk.ApkSigResult
        public boolean containsWarnings() {
            if (!this.mWarnings.isEmpty()) {
                return true;
            }
            if (!this.signers.isEmpty()) {
                for (SignerInfo signer : this.signers) {
                    if (signer.containsWarnings()) {
                        return true;
                    }
                }
            }
            return false;
        }

        public void addError(ApkVerifier.Issue msg, Object... parameters) {
            this.mErrors.add(new ApkVerifier.IssueWithParams(msg, parameters));
        }

        public void addWarning(ApkVerifier.Issue msg, Object... parameters) {
            this.mWarnings.add(new ApkVerifier.IssueWithParams(msg, parameters));
        }

        @Override // com.android.apksig.internal.apk.ApkSigResult
        public List<ApkVerifier.IssueWithParams> getErrors() {
            return this.mErrors;
        }

        @Override // com.android.apksig.internal.apk.ApkSigResult
        public List<ApkVerifier.IssueWithParams> getWarnings() {
            return this.mWarnings;
        }

        public static class SignerInfo extends ApkSignerInfo {
            public List<AdditionalAttribute> additionalAttributes = new ArrayList();
            public List<ContentDigest> contentDigests = new ArrayList();
            private final List<ApkVerifier.IssueWithParams> mErrors = new ArrayList();
            private final List<ApkVerifier.IssueWithParams> mWarnings = new ArrayList();
            public int maxSdkVersion;
            public int minSdkVersion;
            public List<Signature> signatures = new ArrayList();
            public byte[] signedData;
            public SigningCertificateLineage signingCertificateLineage;
            public Map<ContentDigestAlgorithm, byte[]> verifiedContentDigests = new HashMap();
            public Map<SignatureAlgorithm, byte[]> verifiedSignatures = new HashMap();

            public void addError(ApkVerifier.Issue msg, Object... parameters) {
                this.mErrors.add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            public void addWarning(ApkVerifier.Issue msg, Object... parameters) {
                this.mWarnings.add(new ApkVerifier.IssueWithParams(msg, parameters));
            }

            @Override // com.android.apksig.internal.apk.ApkSignerInfo
            public boolean containsErrors() {
                return !this.mErrors.isEmpty();
            }

            @Override // com.android.apksig.internal.apk.ApkSignerInfo
            public boolean containsWarnings() {
                return !this.mWarnings.isEmpty();
            }

            @Override // com.android.apksig.internal.apk.ApkSignerInfo
            public List<ApkVerifier.IssueWithParams> getErrors() {
                return this.mErrors;
            }

            @Override // com.android.apksig.internal.apk.ApkSignerInfo
            public List<ApkVerifier.IssueWithParams> getWarnings() {
                return this.mWarnings;
            }

            public static class ContentDigest {
                private final int mSignatureAlgorithmId;
                private final byte[] mValue;

                public ContentDigest(int signatureAlgorithmId, byte[] value) {
                    this.mSignatureAlgorithmId = signatureAlgorithmId;
                    this.mValue = value;
                }

                public int getSignatureAlgorithmId() {
                    return this.mSignatureAlgorithmId;
                }

                public byte[] getValue() {
                    return this.mValue;
                }
            }

            public static class Signature {
                private final int mAlgorithmId;
                private final byte[] mValue;

                public Signature(int algorithmId, byte[] value) {
                    this.mAlgorithmId = algorithmId;
                    this.mValue = value;
                }

                public int getAlgorithmId() {
                    return this.mAlgorithmId;
                }

                public byte[] getValue() {
                    return this.mValue;
                }
            }

            public static class AdditionalAttribute {
                private final int mId;
                private final byte[] mValue;

                public AdditionalAttribute(int id, byte[] value) {
                    this.mId = id;
                    this.mValue = (byte[]) value.clone();
                }

                public int getId() {
                    return this.mId;
                }

                public byte[] getValue() {
                    return (byte[]) this.mValue.clone();
                }
            }
        }
    }

    public static class SupportedSignature extends ApkSupportedSignature {
        public SupportedSignature(SignatureAlgorithm algorithm, byte[] signature) {
            super(algorithm, signature);
        }
    }

    public static class SigningSchemeBlockAndDigests {
        public final Map<ContentDigestAlgorithm, byte[]> digestInfo;
        public final Pair<byte[], Integer> signingSchemeBlock;

        public SigningSchemeBlockAndDigests(Pair<byte[], Integer> signingSchemeBlock2, Map<ContentDigestAlgorithm, byte[]> digestInfo2) {
            this.signingSchemeBlock = signingSchemeBlock2;
            this.digestInfo = digestInfo2;
        }
    }
}
