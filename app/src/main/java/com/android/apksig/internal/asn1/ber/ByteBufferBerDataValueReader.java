package com.android.apksig.internal.asn1.ber;

import java.nio.ByteBuffer;

public class ByteBufferBerDataValueReader implements BerDataValueReader {
    private final ByteBuffer mBuf;

    public ByteBufferBerDataValueReader(ByteBuffer buf) {
        if (buf == null) {
            throw new NullPointerException("buf == null");
        }
        this.mBuf = buf;
    }

    @Override // com.android.apksig.internal.asn1.ber.BerDataValueReader
    public BerDataValue readDataValue() throws BerDataValueFormatException {
        int contentsOffsetInTag;
        int contentsLength;
        int startPosition = this.mBuf.position();
        if (!this.mBuf.hasRemaining()) {
            return null;
        }
        byte firstIdentifierByte = this.mBuf.get();
        int tagNumber = readTagNumber(firstIdentifierByte);
        boolean constructed = BerEncoding.isConstructed(firstIdentifierByte);
        if (!this.mBuf.hasRemaining()) {
            throw new BerDataValueFormatException("Missing length");
        }
        int firstLengthByte = this.mBuf.get() & 255;
        if ((firstLengthByte & 128) == 0) {
            contentsLength = readShortFormLength(firstLengthByte);
            contentsOffsetInTag = this.mBuf.position() - startPosition;
            skipDefiniteLengthContents(contentsLength);
        } else if (firstLengthByte != 128) {
            contentsLength = readLongFormLength(firstLengthByte);
            contentsOffsetInTag = this.mBuf.position() - startPosition;
            skipDefiniteLengthContents(contentsLength);
        } else {
            contentsOffsetInTag = this.mBuf.position() - startPosition;
            if (constructed) {
                contentsLength = skipConstructedIndefiniteLengthContents();
            } else {
                contentsLength = skipPrimitiveIndefiniteLengthContents();
            }
        }
        int endPosition = this.mBuf.position();
        this.mBuf.position(startPosition);
        int bufOriginalLimit = this.mBuf.limit();
        this.mBuf.limit(endPosition);
        ByteBuffer encoded = this.mBuf.slice();
        this.mBuf.position(this.mBuf.limit());
        this.mBuf.limit(bufOriginalLimit);
        encoded.position(contentsOffsetInTag);
        encoded.limit(contentsOffsetInTag + contentsLength);
        ByteBuffer encodedContents = encoded.slice();
        encoded.clear();
        return new BerDataValue(encoded, encodedContents, BerEncoding.getTagClass(firstIdentifierByte), constructed, tagNumber);
    }

    private int readTagNumber(byte firstIdentifierByte) throws BerDataValueFormatException {
        int tagNumber = BerEncoding.getTagNumber(firstIdentifierByte);
        if (tagNumber == 31) {
            return readHighTagNumber();
        }
        return tagNumber;
    }

    private int readHighTagNumber() throws BerDataValueFormatException {
        int result = 0;
        while (this.mBuf.hasRemaining()) {
            int b = this.mBuf.get();
            if (result > 16777215) {
                throw new BerDataValueFormatException("Tag number too large");
            }
            result = (result << 7) | (b & 127);
            if ((b & 128) == 0) {
                return result;
            }
        }
        throw new BerDataValueFormatException("Truncated tag number");
    }

    private int readShortFormLength(int firstLengthByte) {
        return firstLengthByte & 127;
    }

    private int readLongFormLength(int firstLengthByte) throws BerDataValueFormatException {
        int byteCount = firstLengthByte & 127;
        if (byteCount > 4) {
            throw new BerDataValueFormatException("Length too large: " + byteCount + " bytes");
        }
        int result = 0;
        for (int i = 0; i < byteCount; i++) {
            if (!this.mBuf.hasRemaining()) {
                throw new BerDataValueFormatException("Truncated length");
            }
            int b = this.mBuf.get();
            if (result > 8388607) {
                throw new BerDataValueFormatException("Length too large");
            }
            result = (result << 8) | (b & 255);
        }
        return result;
    }

    private void skipDefiniteLengthContents(int contentsLength) throws BerDataValueFormatException {
        if (this.mBuf.remaining() < contentsLength) {
            throw new BerDataValueFormatException("Truncated contents. Need: " + contentsLength + " bytes, available: " + this.mBuf.remaining());
        }
        this.mBuf.position(this.mBuf.position() + contentsLength);
    }

    private int skipPrimitiveIndefiniteLengthContents() throws BerDataValueFormatException {
        boolean prevZeroByte = false;
        int bytesRead = 0;
        while (this.mBuf.hasRemaining()) {
            int b = this.mBuf.get();
            bytesRead++;
            if (bytesRead < 0) {
                throw new BerDataValueFormatException("Indefinite-length contents too long");
            } else if (b != 0) {
                prevZeroByte = false;
            } else if (prevZeroByte) {
                return bytesRead - 2;
            } else {
                prevZeroByte = true;
            }
        }
        throw new BerDataValueFormatException("Truncated indefinite-length contents: " + bytesRead + " bytes read");
    }

    private int skipConstructedIndefiniteLengthContents() throws BerDataValueFormatException {
        int startPos = this.mBuf.position();
        while (this.mBuf.hasRemaining()) {
            if (this.mBuf.remaining() <= 1 || this.mBuf.getShort(this.mBuf.position()) != 0) {
                readDataValue();
            } else {
                int contentsLength = this.mBuf.position() - startPos;
                this.mBuf.position(this.mBuf.position() + 2);
                return contentsLength;
            }
        }
        throw new BerDataValueFormatException("Truncated indefinite-length contents: " + (this.mBuf.position() - startPos) + " bytes read");
    }
}
