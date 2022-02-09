package com.android.apksig.internal.jar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.jar.Attributes;

public class ManifestParser {
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private byte[] mBufferedLine;
    private int mEndOffset;
    private final byte[] mManifest;
    private int mOffset;

    public ManifestParser(byte[] data) {
        this(data, 0, data.length);
    }

    public ManifestParser(byte[] data, int offset, int length) {
        this.mManifest = data;
        this.mOffset = offset;
        this.mEndOffset = offset + length;
    }

    public List<Section> readAllSections() {
        List<Section> sections = new ArrayList<>();
        while (true) {
            Section section = readSection();
            if (section == null) {
                return sections;
            }
            sections.add(section);
        }
    }

    public Section readSection() {
        int sectionStartOffset;
        String attr;
        do {
            sectionStartOffset = this.mOffset;
            attr = readAttribute();
            if (attr == null) {
                return null;
            }
        } while (attr.length() == 0);
        List<Attribute> attrs = new ArrayList<>();
        attrs.add(parseAttr(attr));
        while (true) {
            String attr2 = readAttribute();
            if (attr2 != null && attr2.length() != 0) {
                attrs.add(parseAttr(attr2));
            }
        }
        return new Section(sectionStartOffset, this.mOffset - sectionStartOffset, attrs);
    }

    private static Attribute parseAttr(String attr) {
        int delimiterIndex = attr.indexOf(": ");
        if (delimiterIndex == -1) {
            return new Attribute(attr, "");
        }
        return new Attribute(attr.substring(0, delimiterIndex), attr.substring(": ".length() + delimiterIndex));
    }

    private String readAttribute() {
        byte[] bytes = readAttributeBytes();
        if (bytes == null) {
            return null;
        }
        if (bytes.length == 0) {
            return "";
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private byte[] readAttributeBytes() {
        byte[] attrLine;
        if (this.mBufferedLine == null || this.mBufferedLine.length != 0) {
            byte[] line = readLine();
            if (line == null) {
                if (this.mBufferedLine == null) {
                    return null;
                }
                byte[] bArr = this.mBufferedLine;
                this.mBufferedLine = null;
                return bArr;
            } else if (line.length != 0) {
                if (this.mBufferedLine == null) {
                    attrLine = line;
                } else if (line.length == 0 || line[0] != 32) {
                    byte[] bArr2 = this.mBufferedLine;
                    this.mBufferedLine = line;
                    return bArr2;
                } else {
                    byte[] attrLine2 = this.mBufferedLine;
                    this.mBufferedLine = null;
                    attrLine = concat(attrLine2, line, 1, line.length - 1);
                }
                while (true) {
                    byte[] line2 = readLine();
                    if (line2 == null) {
                        return attrLine;
                    }
                    if (line2.length == 0) {
                        this.mBufferedLine = EMPTY_BYTE_ARRAY;
                        return attrLine;
                    } else if (line2[0] == 32) {
                        attrLine = concat(attrLine, line2, 1, line2.length - 1);
                    } else {
                        this.mBufferedLine = line2;
                        return attrLine;
                    }
                }
            } else if (this.mBufferedLine == null) {
                return EMPTY_BYTE_ARRAY;
            } else {
                byte[] bArr3 = this.mBufferedLine;
                this.mBufferedLine = EMPTY_BYTE_ARRAY;
                return bArr3;
            }
        } else {
            this.mBufferedLine = null;
            return EMPTY_BYTE_ARRAY;
        }
    }

    private static byte[] concat(byte[] arr1, byte[] arr2, int offset2, int length2) {
        byte[] result = new byte[(arr1.length + length2)];
        System.arraycopy(arr1, 0, result, 0, arr1.length);
        System.arraycopy(arr2, offset2, result, arr1.length, length2);
        return result;
    }

    private byte[] readLine() {
        if (this.mOffset >= this.mEndOffset) {
            return null;
        }
        int startOffset = this.mOffset;
        int newlineStartOffset = -1;
        int newlineEndOffset = -1;
        int i = startOffset;
        while (true) {
            if (i >= this.mEndOffset) {
                break;
            }
            byte b = this.mManifest[i];
            if (b == 13) {
                newlineStartOffset = i;
                int nextIndex = i + 1;
                if (nextIndex >= this.mEndOffset || this.mManifest[nextIndex] != 10) {
                    newlineEndOffset = nextIndex;
                } else {
                    newlineEndOffset = nextIndex + 1;
                }
            } else if (b == 10) {
                newlineStartOffset = i;
                newlineEndOffset = i + 1;
                break;
            } else {
                i++;
            }
        }
        if (newlineStartOffset == -1) {
            newlineStartOffset = this.mEndOffset;
            newlineEndOffset = this.mEndOffset;
        }
        this.mOffset = newlineEndOffset;
        if (newlineStartOffset == startOffset) {
            return EMPTY_BYTE_ARRAY;
        }
        return Arrays.copyOfRange(this.mManifest, startOffset, newlineStartOffset);
    }

    public static class Attribute {
        private final String mName;
        private final String mValue;

        public Attribute(String name, String value) {
            this.mName = name;
            this.mValue = value;
        }

        public String getName() {
            return this.mName;
        }

        public String getValue() {
            return this.mValue;
        }
    }

    public static class Section {
        private final List<Attribute> mAttributes;
        private final String mName;
        private final int mSizeBytes;
        private final int mStartOffset;

        public Section(int startOffset, int sizeBytes, List<Attribute> attrs) {
            this.mStartOffset = startOffset;
            this.mSizeBytes = sizeBytes;
            String sectionName = null;
            if (!attrs.isEmpty()) {
                Attribute firstAttr = attrs.get(0);
                if ("Name".equalsIgnoreCase(firstAttr.getName())) {
                    sectionName = firstAttr.getValue();
                }
            }
            this.mName = sectionName;
            this.mAttributes = Collections.unmodifiableList(new ArrayList(attrs));
        }

        public String getName() {
            return this.mName;
        }

        public int getStartOffset() {
            return this.mStartOffset;
        }

        public int getSizeBytes() {
            return this.mSizeBytes;
        }

        public List<Attribute> getAttributes() {
            return this.mAttributes;
        }

        public String getAttributeValue(Attributes.Name name) {
            return getAttributeValue(name.toString());
        }

        public String getAttributeValue(String name) {
            for (Attribute attr : this.mAttributes) {
                if (attr.getName().equalsIgnoreCase(name)) {
                    return attr.getValue();
                }
            }
            return null;
        }
    }
}
