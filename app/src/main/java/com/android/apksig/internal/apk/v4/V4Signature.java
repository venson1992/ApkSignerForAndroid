package com.android.apksig.internal.apk.v4;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class V4Signature {
    public static final int CURRENT_VERSION = 2;
    public static final int HASHING_ALGORITHM_SHA256 = 1;
    public static final byte LOG2_BLOCK_SIZE_4096_BYTES = 12;
    public final byte[] hashingInfo;
    public final byte[] signingInfo;
    public final int version;

    public static class HashingInfo {
        public final int hashAlgorithm;
        public final byte log2BlockSize;
        public final byte[] rawRootHash;
        public final byte[] salt;

        HashingInfo(int hashAlgorithm2, byte log2BlockSize2, byte[] salt2, byte[] rawRootHash2) {
            this.hashAlgorithm = hashAlgorithm2;
            this.log2BlockSize = log2BlockSize2;
            this.salt = salt2;
            this.rawRootHash = rawRootHash2;
        }

        static HashingInfo fromByteArray(byte[] bytes) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            return new HashingInfo(buffer.getInt(), buffer.get(), V4Signature.readBytes(buffer), V4Signature.readBytes(buffer));
        }

        /* access modifiers changed from: package-private */
        public byte[] toByteArray() {
            ByteBuffer buffer = ByteBuffer.allocate(V4Signature.bytesSize(this.salt) + 5 + V4Signature.bytesSize(this.rawRootHash)).order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(this.hashAlgorithm);
            buffer.put(this.log2BlockSize);
            V4Signature.writeBytes(buffer, this.salt);
            V4Signature.writeBytes(buffer, this.rawRootHash);
            return buffer.array();
        }
    }

    public static class SigningInfo {
        public final byte[] additionalData;
        public final byte[] apkDigest;
        public final byte[] certificate;
        public final byte[] publicKey;
        public final byte[] signature;
        public final int signatureAlgorithmId;

        SigningInfo(byte[] apkDigest2, byte[] certificate2, byte[] additionalData2, byte[] publicKey2, int signatureAlgorithmId2, byte[] signature2) {
            this.apkDigest = apkDigest2;
            this.certificate = certificate2;
            this.additionalData = additionalData2;
            this.publicKey = publicKey2;
            this.signatureAlgorithmId = signatureAlgorithmId2;
            this.signature = signature2;
        }

        static SigningInfo fromByteArray(byte[] bytes) throws IOException {
            ByteBuffer buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            return new SigningInfo(V4Signature.readBytes(buffer), V4Signature.readBytes(buffer), V4Signature.readBytes(buffer), V4Signature.readBytes(buffer), buffer.getInt(), V4Signature.readBytes(buffer));
        }

        /* access modifiers changed from: package-private */
        public byte[] toByteArray() {
            ByteBuffer buffer = ByteBuffer.allocate(V4Signature.bytesSize(this.apkDigest) + V4Signature.bytesSize(this.certificate) + V4Signature.bytesSize(this.additionalData) + V4Signature.bytesSize(this.publicKey) + 4 + V4Signature.bytesSize(this.signature)).order(ByteOrder.LITTLE_ENDIAN);
            V4Signature.writeBytes(buffer, this.apkDigest);
            V4Signature.writeBytes(buffer, this.certificate);
            V4Signature.writeBytes(buffer, this.additionalData);
            V4Signature.writeBytes(buffer, this.publicKey);
            buffer.putInt(this.signatureAlgorithmId);
            V4Signature.writeBytes(buffer, this.signature);
            return buffer.array();
        }
    }

    V4Signature(int version2, byte[] hashingInfo2, byte[] signingInfo2) {
        this.version = version2;
        this.hashingInfo = hashingInfo2;
        this.signingInfo = signingInfo2;
    }

    static V4Signature readFrom(InputStream stream) throws IOException {
        int version2 = readIntLE(stream);
        if (version2 == 2) {
            return new V4Signature(version2, readBytes(stream), readBytes(stream));
        }
        throw new IOException("Invalid signature version.");
    }

    public void writeTo(OutputStream stream) throws IOException {
        writeIntLE(stream, this.version);
        writeBytes(stream, this.hashingInfo);
        writeBytes(stream, this.signingInfo);
    }

    static byte[] getSigningData(long fileSize, HashingInfo hashingInfo2, SigningInfo signingInfo2) {
        int size = bytesSize(hashingInfo2.salt) + 17 + bytesSize(hashingInfo2.rawRootHash) + bytesSize(signingInfo2.apkDigest) + bytesSize(signingInfo2.certificate) + bytesSize(signingInfo2.additionalData);
        ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(size);
        buffer.putLong(fileSize);
        buffer.putInt(hashingInfo2.hashAlgorithm);
        buffer.put(hashingInfo2.log2BlockSize);
        writeBytes(buffer, hashingInfo2.salt);
        writeBytes(buffer, hashingInfo2.rawRootHash);
        writeBytes(buffer, signingInfo2.apkDigest);
        writeBytes(buffer, signingInfo2.certificate);
        writeBytes(buffer, signingInfo2.additionalData);
        return buffer.array();
    }

    static int bytesSize(byte[] bytes) {
        return (bytes == null ? 0 : bytes.length) + 4;
    }

    static void readFully(InputStream stream, byte[] buffer) throws IOException {
        int len = buffer.length;
        int n = 0;
        while (n < len) {
            int count = stream.read(buffer, n, len - n);
            if (count < 0) {
                throw new EOFException();
            }
            n += count;
        }
    }

    static int readIntLE(InputStream stream) throws IOException {
        byte[] buffer = new byte[4];
        readFully(stream, buffer);
        return ByteBuffer.wrap(buffer).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    static void writeIntLE(OutputStream stream, int v) throws IOException {
        stream.write(ByteBuffer.wrap(new byte[4]).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array());
    }

    static byte[] readBytes(InputStream stream) throws IOException {
        try {
            byte[] bytes = new byte[readIntLE(stream)];
            readFully(stream, bytes);
            return bytes;
        } catch (EOFException e) {
            return null;
        }
    }

    static byte[] readBytes(ByteBuffer buffer) throws IOException {
        if (buffer.remaining() < 4) {
            throw new EOFException();
        }
        int size = buffer.getInt();
        if (buffer.remaining() < size) {
            throw new EOFException();
        }
        byte[] bytes = new byte[size];
        buffer.get(bytes);
        return bytes;
    }

    static void writeBytes(OutputStream stream, byte[] bytes) throws IOException {
        if (bytes == null) {
            writeIntLE(stream, 0);
            return;
        }
        writeIntLE(stream, bytes.length);
        stream.write(bytes);
    }

    static void writeBytes(ByteBuffer buffer, byte[] bytes) {
        if (bytes == null) {
            buffer.putInt(0);
            return;
        }
        buffer.putInt(bytes.length);
        buffer.put(bytes);
    }
}
