package com.android.apksig;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Hints {
    public static final String PIN_BYTE_RANGE_ZIP_ENTRY_NAME = "pinlist.meta";
    public static final String PIN_HINT_ASSET_ZIP_ENTRY_NAME = "assets/com.android.hints.pins.txt";

    private static int clampToInt(long value) {
        return (int) Math.max(0L, Math.min(value, 2147483647L));
    }

    public static final class ByteRange {
        final long end;
        final long start;

        public ByteRange(long start2, long end2) {
            this.start = start2;
            this.end = end2;
        }
    }

    public static final class PatternWithRange {
        final long offset;
        final Pattern pattern;
        final long size;

        public PatternWithRange(String pattern2) {
            this.pattern = Pattern.compile(pattern2);
            this.offset = 0;
            this.size = Long.MAX_VALUE;
        }

        public PatternWithRange(String pattern2, long offset2, long size2) {
            this.pattern = Pattern.compile(pattern2);
            this.offset = offset2;
            this.size = size2;
        }

        public Matcher matcher(CharSequence input) {
            return this.pattern.matcher(input);
        }

        public ByteRange ClampToAbsoluteByteRange(ByteRange rangeIn) {
            if (rangeIn.end - rangeIn.start < this.offset) {
                return null;
            }
            long rangeOutStart = rangeIn.start + this.offset;
            return new ByteRange(rangeOutStart, rangeOutStart + Math.min(rangeIn.end - rangeOutStart, this.size));
        }
    }

    public static byte[] encodeByteRangeList(List<ByteRange> pinByteRanges) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(pinByteRanges.size() * 8);
        DataOutputStream out = new DataOutputStream(bos);
        try {
            for (ByteRange pinByteRange : pinByteRanges) {
                out.writeInt(clampToInt(pinByteRange.start));
                out.writeInt(clampToInt(pinByteRange.end - pinByteRange.start));
            }
            return bos.toByteArray();
        } catch (IOException ex) {
            throw new AssertionError("impossible", ex);
        }
    }

    public static ArrayList<PatternWithRange> parsePinPatterns(byte[] patternBlob) {
        ArrayList<PatternWithRange> pinPatterns = new ArrayList<>();
        try {
            for (String rawLine : new String(patternBlob, "UTF-8").split("\n")) {
                String line = rawLine.replaceFirst("#.*", "");
                String[] fields = line.split(" ");
                if (fields.length == 1) {
                    pinPatterns.add(new PatternWithRange(fields[0]));
                } else if (fields.length == 3) {
                    long start = Long.parseLong(fields[1]);
                    pinPatterns.add(new PatternWithRange(fields[0], start, Long.parseLong(fields[2]) - start));
                } else {
                    throw new AssertionError("bad pin pattern line " + line);
                }
            }
            return pinPatterns;
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException("UTF-8 must be supported", ex);
        }
    }
}
