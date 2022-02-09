package com.android.apksig.internal.apk;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AndroidBinXmlParser {
    public static final int EVENT_END_DOCUMENT = 2;
    public static final int EVENT_END_ELEMENT = 4;
    public static final int EVENT_START_DOCUMENT = 1;
    public static final int EVENT_START_ELEMENT = 3;
    private static final long NO_NAMESPACE = 4294967295L;
    public static final int VALUE_TYPE_BOOLEAN = 4;
    public static final int VALUE_TYPE_INT = 2;
    public static final int VALUE_TYPE_REFERENCE = 3;
    public static final int VALUE_TYPE_STRING = 1;
    public static final int VALUE_TYPE_UNSUPPORTED = 0;
    private int mCurrentElementAttrSizeBytes;
    private int mCurrentElementAttributeCount;
    private List<Attribute> mCurrentElementAttributes;
    private ByteBuffer mCurrentElementAttributesContents;
    private String mCurrentElementName;
    private String mCurrentElementNamespace;
    private int mCurrentEvent = 1;
    private int mDepth;
    private ResourceMap mResourceMap;
    private StringPool mStringPool;
    private final ByteBuffer mXml;

    public AndroidBinXmlParser(ByteBuffer xml) throws XmlParserException {
        Chunk chunk;
        xml.order(ByteOrder.LITTLE_ENDIAN);
        Chunk resXmlChunk = null;
        while (true) {
            if (xml.hasRemaining() && (chunk = Chunk.get(xml)) != null) {
                if (chunk.getType() == 3) {
                    resXmlChunk = chunk;
                    break;
                }
            } else {
                break;
            }
        }
        if (resXmlChunk == null) {
            throw new XmlParserException("No XML chunk in file");
        }
        this.mXml = resXmlChunk.getContents();
    }

    public int getDepth() {
        return this.mDepth;
    }

    public int getEventType() {
        return this.mCurrentEvent;
    }

    public String getName() {
        if (this.mCurrentEvent == 3 || this.mCurrentEvent == 4) {
            return this.mCurrentElementName;
        }
        return null;
    }

    public String getNamespace() {
        if (this.mCurrentEvent == 3 || this.mCurrentEvent == 4) {
            return this.mCurrentElementNamespace;
        }
        return null;
    }

    public int getAttributeCount() {
        if (this.mCurrentEvent != 3) {
            return -1;
        }
        return this.mCurrentElementAttributeCount;
    }

    public int getAttributeNameResourceId(int index) throws XmlParserException {
        return getAttribute(index).getNameResourceId();
    }

    public String getAttributeName(int index) throws XmlParserException {
        return getAttribute(index).getName();
    }

    public String getAttributeNamespace(int index) throws XmlParserException {
        return getAttribute(index).getNamespace();
    }

    public int getAttributeValueType(int index) throws XmlParserException {
        switch (getAttribute(index).getValueType()) {
            case 1:
                return 3;
            case 3:
                return 1;
            case 16:
            case 17:
                return 2;
            case 18:
                return 4;
            default:
                return 0;
        }
    }

    public int getAttributeIntValue(int index) throws XmlParserException {
        return getAttribute(index).getIntValue();
    }

    public boolean getAttributeBooleanValue(int index) throws XmlParserException {
        return getAttribute(index).getBooleanValue();
    }

    public String getAttributeStringValue(int index) throws XmlParserException {
        return getAttribute(index).getStringValue();
    }

    private Attribute getAttribute(int index) {
        if (this.mCurrentEvent != 3) {
            throw new IndexOutOfBoundsException("Current event not a START_ELEMENT");
        } else if (index < 0) {
            throw new IndexOutOfBoundsException("index must be >= 0");
        } else if (index >= this.mCurrentElementAttributeCount) {
            throw new IndexOutOfBoundsException("index must be <= attr count (" + this.mCurrentElementAttributeCount + ")");
        } else {
            parseCurrentElementAttributesIfNotParsed();
            return this.mCurrentElementAttributes.get(index);
        }
    }

    public int next() throws XmlParserException {
        Chunk chunk;
        String string;
        if (this.mCurrentEvent == 4) {
            this.mDepth--;
        }
        while (this.mXml.hasRemaining() && (chunk = Chunk.get(this.mXml)) != null) {
            switch (chunk.getType()) {
                case 1:
                    if (this.mStringPool == null) {
                        this.mStringPool = new StringPool(chunk);
                        break;
                    } else {
                        throw new XmlParserException("Multiple string pools not supported");
                    }
                case Chunk.RES_XML_TYPE_START_ELEMENT /*{ENCODED_INT: 258}*/:
                    if (this.mStringPool == null) {
                        throw new XmlParserException("Named element encountered before string pool");
                    }
                    ByteBuffer contents = chunk.getContents();
                    if (contents.remaining() < 20) {
                        throw new XmlParserException("Start element chunk too short. Need at least 20 bytes. Available: " + contents.remaining() + " bytes");
                    }
                    long nsId = getUnsignedInt32(contents);
                    long nameId = getUnsignedInt32(contents);
                    int attrStartOffset = getUnsignedInt16(contents);
                    int attrSizeBytes = getUnsignedInt16(contents);
                    int attrCount = getUnsignedInt16(contents);
                    long attrEndOffset = ((long) attrStartOffset) + (((long) attrCount) * ((long) attrSizeBytes));
                    contents.position(0);
                    if (attrStartOffset > contents.remaining()) {
                        throw new XmlParserException("Attributes start offset out of bounds: " + attrStartOffset + ", max: " + contents.remaining());
                    } else if (attrEndOffset > ((long) contents.remaining())) {
                        throw new XmlParserException("Attributes end offset out of bounds: " + attrEndOffset + ", max: " + contents.remaining());
                    } else {
                        this.mCurrentElementName = this.mStringPool.getString(nameId);
                        if (nsId == NO_NAMESPACE) {
                            string = "";
                        } else {
                            string = this.mStringPool.getString(nsId);
                        }
                        this.mCurrentElementNamespace = string;
                        this.mCurrentElementAttributeCount = attrCount;
                        this.mCurrentElementAttributes = null;
                        this.mCurrentElementAttrSizeBytes = attrSizeBytes;
                        this.mCurrentElementAttributesContents = sliceFromTo(contents, (long) attrStartOffset, attrEndOffset);
                        this.mDepth++;
                        this.mCurrentEvent = 3;
                        return this.mCurrentEvent;
                    }
                case Chunk.RES_XML_TYPE_END_ELEMENT /*{ENCODED_INT: 259}*/:
                    if (this.mStringPool == null) {
                        throw new XmlParserException("Named element encountered before string pool");
                    }
                    ByteBuffer contents2 = chunk.getContents();
                    if (contents2.remaining() < 8) {
                        throw new XmlParserException("End element chunk too short. Need at least 8 bytes. Available: " + contents2.remaining() + " bytes");
                    }
                    long nsId2 = getUnsignedInt32(contents2);
                    this.mCurrentElementName = this.mStringPool.getString(getUnsignedInt32(contents2));
                    this.mCurrentElementNamespace = nsId2 == NO_NAMESPACE ? "" : this.mStringPool.getString(nsId2);
                    this.mCurrentEvent = 4;
                    this.mCurrentElementAttributes = null;
                    this.mCurrentElementAttributesContents = null;
                    return this.mCurrentEvent;
                case Chunk.RES_XML_TYPE_RESOURCE_MAP /*{ENCODED_INT: 384}*/:
                    if (this.mResourceMap == null) {
                        this.mResourceMap = new ResourceMap(chunk);
                        break;
                    } else {
                        throw new XmlParserException("Multiple resource maps not supported");
                    }
            }
        }
        this.mCurrentEvent = 2;
        return this.mCurrentEvent;
    }

    private void parseCurrentElementAttributesIfNotParsed() {
        if (this.mCurrentElementAttributes == null) {
            this.mCurrentElementAttributes = new ArrayList(this.mCurrentElementAttributeCount);
            for (int i = 0; i < this.mCurrentElementAttributeCount; i++) {
                int startPosition = i * this.mCurrentElementAttrSizeBytes;
                ByteBuffer attr = sliceFromTo(this.mCurrentElementAttributesContents, startPosition, this.mCurrentElementAttrSizeBytes + startPosition);
                long nsId = getUnsignedInt32(attr);
                long nameId = getUnsignedInt32(attr);
                attr.position(attr.position() + 7);
                this.mCurrentElementAttributes.add(new Attribute(nsId, nameId, getUnsignedInt8(attr), (int) getUnsignedInt32(attr), this.mStringPool, this.mResourceMap));
            }
        }
    }

    /* access modifiers changed from: private */
    public static class Attribute {
        private static final int TYPE_INT_BOOLEAN = 18;
        private static final int TYPE_INT_DEC = 16;
        private static final int TYPE_INT_HEX = 17;
        private static final int TYPE_REFERENCE = 1;
        private static final int TYPE_STRING = 3;
        private final long mNameId;
        private final long mNsId;
        private final ResourceMap mResourceMap;
        private final StringPool mStringPool;
        private final int mValueData;
        private final int mValueType;

        private Attribute(long nsId, long nameId, int valueType, int valueData, StringPool stringPool, ResourceMap resourceMap) {
            this.mNsId = nsId;
            this.mNameId = nameId;
            this.mValueType = valueType;
            this.mValueData = valueData;
            this.mStringPool = stringPool;
            this.mResourceMap = resourceMap;
        }

        public int getNameResourceId() {
            if (this.mResourceMap != null) {
                return this.mResourceMap.getResourceId(this.mNameId);
            }
            return 0;
        }

        public String getName() throws XmlParserException {
            return this.mStringPool.getString(this.mNameId);
        }

        public String getNamespace() throws XmlParserException {
            return this.mNsId != AndroidBinXmlParser.NO_NAMESPACE ? this.mStringPool.getString(this.mNsId) : "";
        }

        public int getValueType() {
            return this.mValueType;
        }

        public int getIntValue() throws XmlParserException {
            switch (this.mValueType) {
                case 1:
                case 16:
                case 17:
                case 18:
                    return this.mValueData;
                default:
                    throw new XmlParserException("Cannot coerce to int: value type " + this.mValueType);
            }
        }

        public boolean getBooleanValue() throws XmlParserException {
            switch (this.mValueType) {
                case 18:
                    return this.mValueData != 0;
                default:
                    throw new XmlParserException("Cannot coerce to boolean: value type " + this.mValueType);
            }
        }

        public String getStringValue() throws XmlParserException {
            switch (this.mValueType) {
                case 1:
                    return "@" + Integer.toHexString(this.mValueData);
                case 3:
                    return this.mStringPool.getString(((long) this.mValueData) & AndroidBinXmlParser.NO_NAMESPACE);
                case 16:
                    return Integer.toString(this.mValueData);
                case 17:
                    return "0x" + Integer.toHexString(this.mValueData);
                case 18:
                    return Boolean.toString(this.mValueData != 0);
                default:
                    throw new XmlParserException("Cannot coerce to string: value type " + this.mValueType);
            }
        }
    }

    /* access modifiers changed from: private */
    public static class Chunk {
        static final int HEADER_MIN_SIZE_BYTES = 8;
        public static final int RES_XML_TYPE_END_ELEMENT = 259;
        public static final int RES_XML_TYPE_RESOURCE_MAP = 384;
        public static final int RES_XML_TYPE_START_ELEMENT = 258;
        public static final int TYPE_RES_XML = 3;
        public static final int TYPE_STRING_POOL = 1;
        private final ByteBuffer mContents;
        private final ByteBuffer mHeader;
        private final int mType;

        public Chunk(int type, ByteBuffer header, ByteBuffer contents) {
            this.mType = type;
            this.mHeader = header;
            this.mContents = contents;
        }

        public ByteBuffer getContents() {
            ByteBuffer result = this.mContents.slice();
            result.order(this.mContents.order());
            return result;
        }

        public ByteBuffer getHeader() {
            ByteBuffer result = this.mHeader.slice();
            result.order(this.mHeader.order());
            return result;
        }

        public int getType() {
            return this.mType;
        }

        public static Chunk get(ByteBuffer input) throws XmlParserException {
            if (input.remaining() < 8) {
                input.position(input.limit());
                return null;
            }
            int originalPosition = input.position();
            int type = AndroidBinXmlParser.getUnsignedInt16(input);
            int headerSize = AndroidBinXmlParser.getUnsignedInt16(input);
            long chunkSize = AndroidBinXmlParser.getUnsignedInt32(input);
            if (chunkSize - 8 > ((long) input.remaining())) {
                input.position(input.limit());
                return null;
            } else if (headerSize < 8) {
                throw new XmlParserException("Malformed chunk: header too short: " + headerSize + " bytes");
            } else if (((long) headerSize) > chunkSize) {
                throw new XmlParserException("Malformed chunk: header too long: " + headerSize + " bytes. Chunk size: " + chunkSize + " bytes");
            } else {
                int contentStartPosition = originalPosition + headerSize;
                long chunkEndPosition = ((long) originalPosition) + chunkSize;
                Chunk chunk = new Chunk(type, AndroidBinXmlParser.sliceFromTo(input, originalPosition, contentStartPosition), AndroidBinXmlParser.sliceFromTo(input, (long) contentStartPosition, chunkEndPosition));
                input.position((int) chunkEndPosition);
                return chunk;
            }
        }
    }

    /* access modifiers changed from: private */
    public static class StringPool {
        private static final int FLAG_UTF8 = 256;
        private final Map<Integer, String> mCachedStrings = new HashMap();
        private final ByteBuffer mChunkContents;
        private final int mStringCount;
        private final ByteBuffer mStringsSection;
        private final boolean mUtf8Encoded;

        public StringPool(Chunk chunk) throws XmlParserException {
            int stringsSectionEndOffsetInContents;
            ByteBuffer header = chunk.getHeader();
            int headerSizeBytes = header.remaining();
            header.position(8);
            if (header.remaining() < 20) {
                throw new XmlParserException("XML chunk's header too short. Required at least 20 bytes. Available: " + header.remaining() + " bytes");
            }
            long stringCount = AndroidBinXmlParser.getUnsignedInt32(header);
            if (stringCount > 2147483647L) {
                throw new XmlParserException("Too many strings: " + stringCount);
            }
            this.mStringCount = (int) stringCount;
            long styleCount = AndroidBinXmlParser.getUnsignedInt32(header);
            if (styleCount > 2147483647L) {
                throw new XmlParserException("Too many styles: " + styleCount);
            }
            long flags = AndroidBinXmlParser.getUnsignedInt32(header);
            long stringsStartOffset = AndroidBinXmlParser.getUnsignedInt32(header);
            long stylesStartOffset = AndroidBinXmlParser.getUnsignedInt32(header);
            ByteBuffer contents = chunk.getContents();
            if (this.mStringCount > 0) {
                int stringsSectionStartOffsetInContents = (int) (stringsStartOffset - ((long) headerSizeBytes));
                if (styleCount <= 0) {
                    stringsSectionEndOffsetInContents = contents.remaining();
                } else if (stylesStartOffset < stringsStartOffset) {
                    throw new XmlParserException("Styles offset (" + stylesStartOffset + ") < strings offset (" + stringsStartOffset + ")");
                } else {
                    stringsSectionEndOffsetInContents = (int) (stylesStartOffset - ((long) headerSizeBytes));
                }
                this.mStringsSection = AndroidBinXmlParser.sliceFromTo(contents, stringsSectionStartOffsetInContents, stringsSectionEndOffsetInContents);
            } else {
                this.mStringsSection = ByteBuffer.allocate(0);
            }
            this.mUtf8Encoded = (256 & flags) != 0;
            this.mChunkContents = contents;
        }

        public String getString(long index) throws XmlParserException {
            String result;
            if (index < 0) {
                throw new XmlParserException("Unsuported string index: " + index);
            } else if (index >= ((long) this.mStringCount)) {
                throw new XmlParserException("Unsuported string index: " + index + ", max: " + (this.mStringCount - 1));
            } else {
                int idx = (int) index;
                String result2 = this.mCachedStrings.get(Integer.valueOf(idx));
                if (result2 != null) {
                    return result2;
                }
                long offsetInStringsSection = AndroidBinXmlParser.getUnsignedInt32(this.mChunkContents, idx * 4);
                if (offsetInStringsSection >= ((long) this.mStringsSection.capacity())) {
                    throw new XmlParserException("Offset of string idx " + idx + " out of bounds: " + offsetInStringsSection + ", max: " + (this.mStringsSection.capacity() - 1));
                }
                this.mStringsSection.position((int) offsetInStringsSection);
                if (this.mUtf8Encoded) {
                    result = getLengthPrefixedUtf8EncodedString(this.mStringsSection);
                } else {
                    result = getLengthPrefixedUtf16EncodedString(this.mStringsSection);
                }
                this.mCachedStrings.put(Integer.valueOf(idx), result);
                return result;
            }
        }

        private static String getLengthPrefixedUtf16EncodedString(ByteBuffer encoded) throws XmlParserException {
            byte[] arr;
            int arrOffset;
            int lengthChars = AndroidBinXmlParser.getUnsignedInt16(encoded);
            if ((32768 & lengthChars) != 0) {
                lengthChars = ((lengthChars & 32767) << 16) | AndroidBinXmlParser.getUnsignedInt16(encoded);
            }
            if (lengthChars > 1073741823) {
                throw new XmlParserException("String too long: " + lengthChars + " uint16s");
            }
            int lengthBytes = lengthChars * 2;
            if (encoded.hasArray()) {
                arr = encoded.array();
                arrOffset = encoded.arrayOffset() + encoded.position();
                encoded.position(encoded.position() + lengthBytes);
            } else {
                arr = new byte[lengthBytes];
                arrOffset = 0;
                encoded.get(arr);
            }
            if (arr[arrOffset + lengthBytes] == 0 && arr[arrOffset + lengthBytes + 1] == 0) {
                try {
                    return new String(arr, arrOffset, lengthBytes, "UTF-16LE");
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException("UTF-16LE character encoding not supported", e);
                }
            } else {
                throw new XmlParserException("UTF-16 encoded form of string not NULL terminated");
            }
        }

        private static String getLengthPrefixedUtf8EncodedString(ByteBuffer encoded) throws XmlParserException {
            byte[] arr;
            int arrOffset;
            int lengthBytes = AndroidBinXmlParser.getUnsignedInt8(encoded);
            if ((lengthBytes & 128) != 0) {
                int lengthBytes2 = ((lengthBytes & 127) << 8) | AndroidBinXmlParser.getUnsignedInt8(encoded);
            }
            int lengthBytes3 = AndroidBinXmlParser.getUnsignedInt8(encoded);
            if ((lengthBytes3 & 128) != 0) {
                lengthBytes3 = ((lengthBytes3 & 127) << 8) | AndroidBinXmlParser.getUnsignedInt8(encoded);
            }
            if (encoded.hasArray()) {
                arr = encoded.array();
                arrOffset = encoded.arrayOffset() + encoded.position();
                encoded.position(encoded.position() + lengthBytes3);
            } else {
                arr = new byte[lengthBytes3];
                arrOffset = 0;
                encoded.get(arr);
            }
            if (arr[arrOffset + lengthBytes3] != 0) {
                throw new XmlParserException("UTF-8 encoded form of string not NULL terminated");
            }
            try {
                return new String(arr, arrOffset, lengthBytes3, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 character encoding not supported", e);
            }
        }
    }

    /* access modifiers changed from: private */
    public static class ResourceMap {
        private final ByteBuffer mChunkContents;
        private final int mEntryCount = (this.mChunkContents.remaining() / 4);

        public ResourceMap(Chunk chunk) throws XmlParserException {
            this.mChunkContents = chunk.getContents().slice();
            this.mChunkContents.order(chunk.getContents().order());
        }

        public int getResourceId(long index) {
            if (index < 0 || index >= ((long) this.mEntryCount)) {
                return 0;
            }
            return this.mChunkContents.getInt(((int) index) * 4);
        }
    }

    /* access modifiers changed from: private */
    public static ByteBuffer sliceFromTo(ByteBuffer source, long start, long end) {
        if (start < 0) {
            throw new IllegalArgumentException("start: " + start);
        } else if (end < start) {
            throw new IllegalArgumentException("end < start: " + end + " < " + start);
        } else {
            int capacity = source.capacity();
            if (end <= ((long) source.capacity())) {
                return sliceFromTo(source, (int) start, (int) end);
            }
            throw new IllegalArgumentException("end > capacity: " + end + " > " + capacity);
        }
    }

    /* JADX INFO: finally extract failed */
    /* access modifiers changed from: private */
    public static ByteBuffer sliceFromTo(ByteBuffer source, int start, int end) {
        if (start < 0) {
            throw new IllegalArgumentException("start: " + start);
        } else if (end < start) {
            throw new IllegalArgumentException("end < start: " + end + " < " + start);
        } else {
            int capacity = source.capacity();
            if (end > source.capacity()) {
                throw new IllegalArgumentException("end > capacity: " + end + " > " + capacity);
            }
            int originalLimit = source.limit();
            int originalPosition = source.position();
            try {
                source.position(0);
                source.limit(end);
                source.position(start);
                ByteBuffer result = source.slice();
                result.order(source.order());
                source.position(0);
                source.limit(originalLimit);
                source.position(originalPosition);
                return result;
            } catch (Throwable th) {
                source.position(0);
                source.limit(originalLimit);
                source.position(originalPosition);
                throw th;
            }
        }
    }

    /* access modifiers changed from: private */
    public static int getUnsignedInt8(ByteBuffer buffer) {
        return buffer.get() & 255;
    }

    /* access modifiers changed from: private */
    public static int getUnsignedInt16(ByteBuffer buffer) {
        return buffer.getShort() & 65535;
    }

    /* access modifiers changed from: private */
    public static long getUnsignedInt32(ByteBuffer buffer) {
        return ((long) buffer.getInt()) & NO_NAMESPACE;
    }

    /* access modifiers changed from: private */
    public static long getUnsignedInt32(ByteBuffer buffer, int position) {
        return ((long) buffer.getInt(position)) & NO_NAMESPACE;
    }

    public static class XmlParserException extends Exception {
        private static final long serialVersionUID = 1;

        public XmlParserException(String message) {
            super(message);
        }

        public XmlParserException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
