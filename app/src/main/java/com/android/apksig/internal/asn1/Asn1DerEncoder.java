package com.android.apksig.internal.asn1;

import com.android.apksig.ApkVerificationIssue;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public final class Asn1DerEncoder {
    public static final Asn1OpaqueObject ASN1_DER_NULL = new Asn1OpaqueObject(new byte[]{5, 0});

    private Asn1DerEncoder() {
    }

    public static byte[] encode(Object container) throws Asn1EncodingException {
        Class<?> containerClass = container.getClass();
        Asn1Class containerAnnotation = (Asn1Class) containerClass.getDeclaredAnnotation(Asn1Class.class);
        if (containerAnnotation == null) {
            throw new Asn1EncodingException(containerClass.getName() + " not annotated with " + Asn1Class.class.getName());
        }
        Asn1Type containerType = containerAnnotation.type();
        switch (containerType) {
            case CHOICE:
                return toChoice(container);
            case SEQUENCE:
                return toSequence(container);
            case UNENCODED_CONTAINER:
                return toSequence(container, true);
            default:
                throw new Asn1EncodingException("Unsupported container type: " + containerType);
        }
    }

    /* access modifiers changed from: private */
    public static byte[] toChoice(Object container) throws Asn1EncodingException {
        Class<?> containerClass = container.getClass();
        List<AnnotatedField> fields = getAnnotatedFields(container);
        if (fields.isEmpty()) {
            throw new Asn1EncodingException("No fields annotated with " + Asn1Field.class.getName() + " in CHOICE class " + containerClass.getName());
        }
        AnnotatedField resultField = null;
        for (AnnotatedField field : fields) {
            if (getMemberFieldValue(container, field.getField()) != null) {
                if (resultField != null) {
                    throw new Asn1EncodingException("Multiple non-null fields in CHOICE class " + containerClass.getName() + ": " + resultField.getField().getName() + ", " + field.getField().getName());
                }
                resultField = field;
            }
        }
        if (resultField != null) {
            return resultField.toDer();
        }
        throw new Asn1EncodingException("No non-null fields in CHOICE class " + containerClass.getName());
    }

    /* access modifiers changed from: private */
    public static byte[] toSequence(Object container) throws Asn1EncodingException {
        return toSequence(container, false);
    }

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
    private static byte[] toSequence(java.lang.Object r14, boolean r15) throws com.android.apksig.internal.asn1.Asn1EncodingException {
        /*
        // Method dump skipped, instructions count: 259
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.asn1.Asn1DerEncoder.toSequence(java.lang.Object, boolean):byte[]");
    }

    private static /* synthetic */ int lambda$toSequence$0(AnnotatedField f1, AnnotatedField f2) {
        return f1.getAnnotation().index() - f2.getAnnotation().index();
    }

    /* access modifiers changed from: private */
    public static byte[] toSetOf(Collection<?> values, Asn1Type elementType) throws Asn1EncodingException {
        return toSequenceOrSetOf(values, elementType, true);
    }

    /* access modifiers changed from: private */
    public static byte[] toSequenceOf(Collection<?> values, Asn1Type elementType) throws Asn1EncodingException {
        return toSequenceOrSetOf(values, elementType, false);
    }

    private static byte[] toSequenceOrSetOf(Collection<?> values, Asn1Type elementType, boolean toSet) throws Asn1EncodingException {
        int tagNumber;
        List<byte[]> serializedValues = new ArrayList<>(values.size());
        Iterator<?> it = values.iterator();
        while (it.hasNext()) {
            serializedValues.add(JavaToDerConverter.toDer(it.next(), elementType, null));
        }
        if (toSet) {
            if (serializedValues.size() > 1) {
                Collections.sort(serializedValues, ByteArrayLexicographicComparator.INSTANCE);
            }
            tagNumber = 17;
        } else {
            tagNumber = 16;
        }
        return createTag(0, true, tagNumber, (byte[][]) serializedValues.toArray(new byte[0][]));
    }

    /* access modifiers changed from: private */
    public static class ByteArrayLexicographicComparator implements Comparator<byte[]> {
        private static final ByteArrayLexicographicComparator INSTANCE = new ByteArrayLexicographicComparator();

        private ByteArrayLexicographicComparator() {
        }

        public int compare(byte[] arr1, byte[] arr2) {
            int commonLength = Math.min(arr1.length, arr2.length);
            for (int i = 0; i < commonLength; i++) {
                int diff = (arr1[i] & 255) - (arr2[i] & 255);
                if (diff != 0) {
                    return diff;
                }
            }
            return arr1.length - arr2.length;
        }
    }

    private static List<AnnotatedField> getAnnotatedFields(Object container) throws Asn1EncodingException {
        Class<?> containerClass = container.getClass();
        Field[] declaredFields = containerClass.getDeclaredFields();
        List<AnnotatedField> result = new ArrayList<>(declaredFields.length);
        for (Field field : declaredFields) {
            Asn1Field annotation = (Asn1Field) field.getDeclaredAnnotation(Asn1Field.class);
            if (annotation != null) {
                if (Modifier.isStatic(field.getModifiers())) {
                    throw new Asn1EncodingException(Asn1Field.class.getName() + " used on a static field: " + containerClass.getName() + "." + field.getName());
                }
                try {
                    result.add(new AnnotatedField(container, field, annotation));
                } catch (Asn1EncodingException e) {
                    throw new Asn1EncodingException("Invalid ASN.1 annotation on " + containerClass.getName() + "." + field.getName(), e);
                }
            }
        }
        return result;
    }

    /* access modifiers changed from: private */
    public static byte[] toInteger(int value) {
        return toInteger((long) value);
    }

    /* access modifiers changed from: private */
    public static byte[] toInteger(long value) {
        return toInteger(BigInteger.valueOf(value));
    }

    /* access modifiers changed from: private */
    public static byte[] toInteger(BigInteger value) {
        return createTag(0, false, 2, value.toByteArray());
    }

    /* access modifiers changed from: private */
    public static byte[] toBoolean(boolean value) {
        byte[] result = new byte[1];
        if (!value) {
            result[0] = 0;
        } else {
            result[0] = 1;
        }
        return createTag(0, false, 1, result);
    }

    /* access modifiers changed from: private */
    public static byte[] toOid(String oid) throws Asn1EncodingException {
        ByteArrayOutputStream encodedValue = new ByteArrayOutputStream();
        String[] nodes = oid.split("\\.");
        if (nodes.length < 2) {
            throw new Asn1EncodingException("OBJECT IDENTIFIER must contain at least two nodes: " + oid);
        }
        try {
            int firstNode = Integer.parseInt(nodes[0]);
            if (firstNode > 6 || firstNode < 0) {
                throw new Asn1EncodingException("Invalid value for node #1: " + firstNode);
            }
            try {
                int secondNode = Integer.parseInt(nodes[1]);
                if (secondNode >= 40 || secondNode < 0) {
                    throw new Asn1EncodingException("Invalid value for node #2: " + secondNode);
                }
                int firstByte = (firstNode * 40) + secondNode;
                if (firstByte > 255) {
                    throw new Asn1EncodingException("First two nodes out of range: " + firstNode + "." + secondNode);
                }
                encodedValue.write(firstByte);
                for (int i = 2; i < nodes.length; i++) {
                    String nodeString = nodes[i];
                    try {
                        int node = Integer.parseInt(nodeString);
                        if (node < 0) {
                            throw new Asn1EncodingException("Invalid value for node #" + (i + 1) + ": " + node);
                        }
                        if (node <= 127) {
                            encodedValue.write(node);
                        } else if (node < 16384) {
                            encodedValue.write((node >> 7) | 128);
                            encodedValue.write(node & 127);
                        } else if (node < 2097152) {
                            encodedValue.write((node >> 14) | 128);
                            encodedValue.write(((node >> 7) & 127) | 128);
                            encodedValue.write(node & 127);
                        } else {
                            throw new Asn1EncodingException("Node #" + (i + 1) + " too large: " + node);
                        }
                    } catch (NumberFormatException e) {
                        throw new Asn1EncodingException("Node #" + (i + 1) + " not numeric: " + nodeString);
                    }
                }
                return createTag(0, false, 6, encodedValue.toByteArray());
            } catch (NumberFormatException e2) {
                throw new Asn1EncodingException("Node #2 not numeric: " + nodes[1]);
            }
        } catch (NumberFormatException e3) {
            throw new Asn1EncodingException("Node #1 not numeric: " + nodes[0]);
        }
    }

    /* access modifiers changed from: private */
    public static Object getMemberFieldValue(Object obj, Field field) throws Asn1EncodingException {
        try {
            return field.get(obj);
        } catch (ReflectiveOperationException e) {
            throw new Asn1EncodingException("Failed to read " + obj.getClass().getName() + "." + field.getName(), e);
        }
    }

    /* access modifiers changed from: private */
    public static final class AnnotatedField {
        private final Asn1Field mAnnotation;
        private final Asn1Type mDataType;
        private final int mDerTagClass;
        private final int mDerTagNumber;
        private final Asn1Type mElementDataType;
        private final Field mField;
        private final Object mObject;
        private final boolean mOptional;
        private final Asn1TagClass mTagClass;
        private final Asn1Tagging mTagging;

        public AnnotatedField(Object obj, Field field, Asn1Field annotation) throws Asn1EncodingException {
            int tagNumber;
            this.mObject = obj;
            this.mField = field;
            this.mAnnotation = annotation;
            this.mDataType = annotation.type();
            this.mElementDataType = annotation.elementType();
            Asn1TagClass tagClass = annotation.cls();
            if (tagClass == Asn1TagClass.AUTOMATIC) {
                if (annotation.tagNumber() != -1) {
                    tagClass = Asn1TagClass.CONTEXT_SPECIFIC;
                } else {
                    tagClass = Asn1TagClass.UNIVERSAL;
                }
            }
            this.mTagClass = tagClass;
            this.mDerTagClass = BerEncoding.getTagClass(this.mTagClass);
            if (annotation.tagNumber() != -1) {
                tagNumber = annotation.tagNumber();
            } else if (this.mDataType == Asn1Type.CHOICE || this.mDataType == Asn1Type.ANY) {
                tagNumber = -1;
            } else {
                tagNumber = BerEncoding.getTagNumber(this.mDataType);
            }
            this.mDerTagNumber = tagNumber;
            this.mTagging = annotation.tagging();
            if ((this.mTagging == Asn1Tagging.EXPLICIT || this.mTagging == Asn1Tagging.IMPLICIT) && annotation.tagNumber() == -1) {
                throw new Asn1EncodingException("Tag number must be specified when tagging mode is " + this.mTagging);
            }
            this.mOptional = annotation.optional();
        }

        public Field getField() {
            return this.mField;
        }

        public Asn1Field getAnnotation() {
            return this.mAnnotation;
        }

        public byte[] toDer() throws Asn1EncodingException {
            Object fieldValue = Asn1DerEncoder.getMemberFieldValue(this.mObject, this.mField);
            if (fieldValue != null) {
                byte[] encoded = JavaToDerConverter.toDer(fieldValue, this.mDataType, this.mElementDataType);
                switch (this.mTagging) {
                    case NORMAL:
                        return encoded;
                    case EXPLICIT:
                        return Asn1DerEncoder.createTag(this.mDerTagClass, true, this.mDerTagNumber, new byte[][]{encoded});
                    case IMPLICIT:
                        if (BerEncoding.getTagNumber(encoded[0]) == 31) {
                            throw new Asn1EncodingException("High-tag-number form not supported");
                        } else if (this.mDerTagNumber >= 31) {
                            throw new Asn1EncodingException("Unsupported high tag number: " + this.mDerTagNumber);
                        } else {
                            encoded[0] = BerEncoding.setTagNumber(encoded[0], this.mDerTagNumber);
                            encoded[0] = BerEncoding.setTagClass(encoded[0], this.mDerTagClass);
                            return encoded;
                        }
                    default:
                        throw new RuntimeException("Unknown tagging mode: " + this.mTagging);
                }
            } else if (this.mOptional) {
                return null;
            } else {
                throw new Asn1EncodingException("Required field not set");
            }
        }
    }

    /* access modifiers changed from: private */
    public static byte[] createTag(int tagClass, boolean constructed, int tagNumber, byte[]... contents) {
        int contentsPosInResult;
        byte[] result;
        if (tagNumber >= 31) {
            throw new IllegalArgumentException("High tag numbers not supported: " + tagNumber);
        }
        byte firstIdentifierByte = (byte) ((constructed ? 32 : 0) | (tagClass << 6) | tagNumber);
        int contentsLength = 0;
        for (byte[] c : contents) {
            contentsLength += c.length;
        }
        if (contentsLength < 128) {
            contentsPosInResult = 2;
            result = new byte[(2 + contentsLength)];
            result[0] = firstIdentifierByte;
            result[1] = (byte) contentsLength;
        } else {
            if (contentsLength <= 255) {
                contentsPosInResult = 3;
                result = new byte[(3 + contentsLength)];
                result[1] = -127;
                result[2] = (byte) contentsLength;
            } else if (contentsLength <= 65535) {
                contentsPosInResult = 4;
                result = new byte[(4 + contentsLength)];
                result[1] = -126;
                result[2] = (byte) (contentsLength >> 8);
                result[3] = (byte) (contentsLength & 255);
            } else if (contentsLength <= 16777215) {
                contentsPosInResult = 5;
                result = new byte[(5 + contentsLength)];
                result[1] = -125;
                result[2] = (byte) (contentsLength >> 16);
                result[3] = (byte) ((contentsLength >> 8) & 255);
                result[4] = (byte) (contentsLength & 255);
            } else {
                contentsPosInResult = 6;
                result = new byte[(6 + contentsLength)];
                result[1] = -124;
                result[2] = (byte) (contentsLength >> 24);
                result[3] = (byte) ((contentsLength >> 16) & 255);
                result[4] = (byte) ((contentsLength >> 8) & 255);
                result[5] = (byte) (contentsLength & 255);
            }
            result[0] = firstIdentifierByte;
        }
        for (byte[] c2 : contents) {
            System.arraycopy(c2, 0, result, contentsPosInResult, c2.length);
            contentsPosInResult += c2.length;
        }
        return result;
    }

    /* access modifiers changed from: private */
    public static final class JavaToDerConverter {
        private JavaToDerConverter() {
        }

        public static byte[] toDer(Object source, Asn1Type targetType, Asn1Type targetElementType) throws Asn1EncodingException {
            Class<?> sourceType = source.getClass();
            if (Asn1OpaqueObject.class.equals(sourceType)) {
                ByteBuffer buf = ((Asn1OpaqueObject) source).getEncoded();
                byte[] result = new byte[buf.remaining()];
                buf.get(result);
                return result;
            } else if (targetType == null || targetType == Asn1Type.ANY) {
                return Asn1DerEncoder.encode(source);
            } else {
                switch (AnonymousClass1.$SwitchMap$com$android$apksig$internal$asn1$Asn1Type[targetType.ordinal()]) {
                    case 1:
                        Asn1Class containerAnnotation = (Asn1Class) sourceType.getDeclaredAnnotation(Asn1Class.class);
                        if (containerAnnotation != null && containerAnnotation.type() == Asn1Type.CHOICE) {
                            return Asn1DerEncoder.toChoice(source);
                        }
                    case 2:
                        Asn1Class containerAnnotation2 = (Asn1Class) sourceType.getDeclaredAnnotation(Asn1Class.class);
                        if (containerAnnotation2 != null && containerAnnotation2.type() == Asn1Type.SEQUENCE) {
                            return Asn1DerEncoder.toSequence(source);
                        }
                    case 4:
                    case 5:
                        byte[] value = null;
                        if (source instanceof ByteBuffer) {
                            ByteBuffer buf2 = (ByteBuffer) source;
                            value = new byte[buf2.remaining()];
                            buf2.slice().get(value);
                        } else if (source instanceof byte[]) {
                            value = (byte[]) source;
                        }
                        if (value != null) {
                            return Asn1DerEncoder.createTag(0, false, BerEncoding.getTagNumber(targetType), new byte[][]{value});
                        }
                        break;
                    case 6:
                        if (source instanceof Integer) {
                            return Asn1DerEncoder.toInteger(((Integer) source).intValue());
                        }
                        if (source instanceof Long) {
                            return Asn1DerEncoder.toInteger(((Long) source).longValue());
                        }
                        if (source instanceof BigInteger) {
                            return Asn1DerEncoder.toInteger((BigInteger) source);
                        }
                        break;
                    case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
                        if (source instanceof Boolean) {
                            return Asn1DerEncoder.toBoolean(((Boolean) source).booleanValue());
                        }
                        break;
                    case 8:
                    case 9:
                        if (source instanceof String) {
                            return Asn1DerEncoder.createTag(0, false, BerEncoding.getTagNumber(targetType), new byte[][]{((String) source).getBytes()});
                        }
                        break;
                    case ApkVerificationIssue.V3_SIG_NO_SIGNERS:
                        if (source instanceof String) {
                            return Asn1DerEncoder.toOid((String) source);
                        }
                        break;
                    case 11:
                        return Asn1DerEncoder.toSetOf((Collection) source, targetElementType);
                    case 12:
                        return Asn1DerEncoder.toSequenceOf((Collection) source, targetElementType);
                }
                throw new Asn1EncodingException("Unsupported conversion: " + sourceType.getName() + " to ASN.1 " + targetType);
            }
        }
    }
}
