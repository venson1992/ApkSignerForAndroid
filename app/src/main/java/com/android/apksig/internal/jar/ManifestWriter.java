package com.android.apksig.internal.jar;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.jar.Attributes;

public abstract class ManifestWriter {
    private static final byte[] CRLF = {13, 10};
    private static final int MAX_LINE_LENGTH = 70;

    private ManifestWriter() {
    }

    public static void writeMainSection(OutputStream out, Attributes attributes) throws IOException {
        String manifestVersion = attributes.getValue(Attributes.Name.MANIFEST_VERSION);
        if (manifestVersion == null) {
            throw new IllegalArgumentException("Mandatory " + Attributes.Name.MANIFEST_VERSION + " attribute missing");
        }
        writeAttribute(out, Attributes.Name.MANIFEST_VERSION, manifestVersion);
        if (attributes.size() > 1) {
            SortedMap<String, String> namedAttributes = getAttributesSortedByName(attributes);
            namedAttributes.remove(Attributes.Name.MANIFEST_VERSION.toString());
            writeAttributes(out, namedAttributes);
        }
        writeSectionDelimiter(out);
    }

    public static void writeIndividualSection(OutputStream out, String name, Attributes attributes) throws IOException {
        writeAttribute(out, "Name", name);
        if (!attributes.isEmpty()) {
            writeAttributes(out, getAttributesSortedByName(attributes));
        }
        writeSectionDelimiter(out);
    }

    static void writeSectionDelimiter(OutputStream out) throws IOException {
        out.write(CRLF);
    }

    static void writeAttribute(OutputStream out, Attributes.Name name, String value) throws IOException {
        writeAttribute(out, name.toString(), value);
    }

    private static void writeAttribute(OutputStream out, String name, String value) throws IOException {
        writeLine(out, name + ": " + value);
    }

    private static void writeLine(OutputStream out, String line) throws IOException {
        int chunkLength;
        byte[] lineBytes = line.getBytes(StandardCharsets.UTF_8);
        int offset = 0;
        int remaining = lineBytes.length;
        boolean firstLine = true;
        while (remaining > 0) {
            if (firstLine) {
                chunkLength = Math.min(remaining, (int) MAX_LINE_LENGTH);
            } else {
                out.write(CRLF);
                out.write(32);
                chunkLength = Math.min(remaining, 69);
            }
            out.write(lineBytes, offset, chunkLength);
            offset += chunkLength;
            remaining -= chunkLength;
            firstLine = false;
        }
        out.write(CRLF);
    }

    static SortedMap<String, String> getAttributesSortedByName(Attributes attributes) {
        Set<Map.Entry<Object, Object>> attributesEntries = attributes.entrySet();
        SortedMap<String, String> namedAttributes = new TreeMap<>();
        for (Map.Entry<Object, Object> attribute : attributesEntries) {
            namedAttributes.put(attribute.getKey().toString(), attribute.getValue().toString());
        }
        return namedAttributes;
    }

    static void writeAttributes(OutputStream out, SortedMap<String, String> attributesSortedByName) throws IOException {
        for (Map.Entry<String, String> attribute : attributesSortedByName.entrySet()) {
            writeAttribute(out, attribute.getKey(), attribute.getValue());
        }
    }
}
