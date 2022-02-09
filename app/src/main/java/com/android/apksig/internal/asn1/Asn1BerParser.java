package com.android.apksig.internal.asn1;

import com.android.apksig.internal.asn1.ber.BerDataValue;
import com.android.apksig.internal.asn1.ber.BerDataValueFormatException;
import com.android.apksig.internal.asn1.ber.BerDataValueReader;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.asn1.ber.ByteBufferBerDataValueReader;
import com.android.apksig.internal.util.ByteBufferUtils;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Asn1BerParser {
    private Asn1BerParser() {
    }

    public static <T> T parse(ByteBuffer encoded, Class<T> containerClass) throws Asn1DecodingException {
        try {
            BerDataValue containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
            if (containerDataValue != null) {
                return (T) parse(containerDataValue, containerClass);
            }
            throw new Asn1DecodingException("Empty input");
        } catch (BerDataValueFormatException e) {
            throw new Asn1DecodingException("Failed to decode top-level data value", e);
        }
    }

    public static <T> List<T> parseImplicitSetOf(ByteBuffer encoded, Class<T> elementClass) throws Asn1DecodingException {
        try {
            BerDataValue containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
            if (containerDataValue != null) {
                return parseSetOf(containerDataValue, elementClass);
            }
            throw new Asn1DecodingException("Empty input");
        } catch (BerDataValueFormatException e) {
            throw new Asn1DecodingException("Failed to decode top-level data value", e);
        }
    }

    private static <T> T parse(BerDataValue container, Class<T> containerClass) throws Asn1DecodingException {
        if (container == null) {
            throw new NullPointerException("container == null");
        } else if (containerClass == null) {
            throw new NullPointerException("containerClass == null");
        } else {
            Asn1Type dataType = getContainerAsn1Type(containerClass);
            switch (dataType) {
                case CHOICE:
                    return (T) parseChoice(container, containerClass);
                case SEQUENCE:
                    int expectedTagNumber = BerEncoding.getTagNumber(dataType);
                    if (container.getTagClass() == 0 && container.getTagNumber() == expectedTagNumber) {
                        return (T) parseSequence(container, containerClass);
                    }
                    throw new Asn1UnexpectedTagException("Unexpected data value read as " + containerClass.getName() + ". Expected " + BerEncoding.tagClassAndNumberToString(0, expectedTagNumber) + ", but read: " + BerEncoding.tagClassAndNumberToString(container.getTagClass(), container.getTagNumber()));
                case UNENCODED_CONTAINER:
                    return (T) parseSequence(container, containerClass, true);
                default:
                    throw new Asn1DecodingException("Parsing container " + dataType + " not supported");
            }
        }
    }

    /* access modifiers changed from: private */
    public static <T> T parseChoice(BerDataValue dataValue, Class<T> containerClass) throws Asn1DecodingException {
        List<AnnotatedField> fields = getAnnotatedFields(containerClass);
        if (fields.isEmpty()) {
            throw new Asn1DecodingException("No fields annotated with " + Asn1Field.class.getName() + " in CHOICE class " + containerClass.getName());
        }
        for (int i = 0; i < fields.size() - 1; i++) {
            AnnotatedField f1 = fields.get(i);
            int tagNumber1 = f1.getBerTagNumber();
            int tagClass1 = f1.getBerTagClass();
            for (int j = i + 1; j < fields.size(); j++) {
                AnnotatedField f2 = fields.get(j);
                int tagNumber2 = f2.getBerTagNumber();
                int tagClass2 = f2.getBerTagClass();
                if (tagNumber1 == tagNumber2 && tagClass1 == tagClass2) {
                    throw new Asn1DecodingException("CHOICE fields are indistinguishable because they have the same tag class and number: " + containerClass.getName() + "." + f1.getField().getName() + " and ." + f2.getField().getName());
                }
            }
        }
        try {
            T obj = containerClass.getConstructor(new Class[0]).newInstance(new Object[0]);
            for (AnnotatedField field : fields) {
                try {
                    field.setValueFrom(dataValue, obj);
                    return obj;
                } catch (Asn1UnexpectedTagException e) {
                }
            }
            throw new Asn1DecodingException("No options of CHOICE " + containerClass.getName() + " matched");
        } catch (IllegalArgumentException | ReflectiveOperationException e2) {
            throw new Asn1DecodingException("Failed to instantiate " + containerClass.getName(), e2);
        }
    }

    /* access modifiers changed from: private */
    public static <T> T parseSequence(BerDataValue container, Class<T> containerClass) throws Asn1DecodingException {
        return (T) parseSequence(container, containerClass, false);
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
    private static <T> T parseSequence(com.android.apksig.internal.asn1.ber.BerDataValue r12, java.lang.Class<T> r13, boolean r14) throws com.android.apksig.internal.asn1.Asn1DecodingException {
        /*
        // Method dump skipped, instructions count: 284
        */
        throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.asn1.Asn1BerParser.parseSequence(com.android.apksig.internal.asn1.ber.BerDataValue, java.lang.Class, boolean):java.lang.Object");
    }

    private static /* synthetic */ int lambda$parseSequence$0(AnnotatedField f1, AnnotatedField f2) {
        return f1.getAnnotation().index() - f2.getAnnotation().index();
    }

    /* access modifiers changed from: private */
    public static <T> List<T> parseSetOf(BerDataValue container, Class<T> elementClass) throws Asn1DecodingException {
        Object parse;
        ArrayList arrayList = new ArrayList();
        BerDataValueReader elementsReader = container.contentsReader();
        while (true) {
            try {
                BerDataValue dataValue = elementsReader.readDataValue();
                if (dataValue == null) {
                    return arrayList;
                }
                if (ByteBuffer.class.equals(elementClass)) {
                    parse = dataValue.getEncodedContents();
                } else if (Asn1OpaqueObject.class.equals(elementClass)) {
                    parse = new Asn1OpaqueObject(dataValue.getEncoded());
                } else {
                    parse = parse(dataValue, elementClass);
                }
                arrayList.add(parse);
            } catch (BerDataValueFormatException e) {
                throw new Asn1DecodingException("Malformed data value", e);
            }
        }
    }

    private static Asn1Type getContainerAsn1Type(Class<?> containerClass) throws Asn1DecodingException {
        Asn1Class containerAnnotation = (Asn1Class) containerClass.getDeclaredAnnotation(Asn1Class.class);
        if (containerAnnotation == null) {
            throw new Asn1DecodingException(containerClass.getName() + " is not annotated with " + Asn1Class.class.getName());
        }
        switch (containerAnnotation.type()) {
            case CHOICE:
            case SEQUENCE:
            case UNENCODED_CONTAINER:
                return containerAnnotation.type();
            default:
                throw new Asn1DecodingException("Unsupported ASN.1 container annotation type: " + containerAnnotation.type());
        }
    }

    /* access modifiers changed from: private */
    public static Class<?> getElementType(Field field) throws Asn1DecodingException, ClassNotFoundException {
        String type = field.getGenericType().getTypeName();
        int delimiterIndex = type.indexOf(60);
        if (delimiterIndex == -1) {
            throw new Asn1DecodingException("Not a container type: " + field.getGenericType());
        }
        int startIndex = delimiterIndex + 1;
        int endIndex = type.indexOf(62, startIndex);
        if (endIndex != -1) {
            return Class.forName(type.substring(startIndex, endIndex));
        }
        throw new Asn1DecodingException("Not a container type: " + field.getGenericType());
    }

    /* access modifiers changed from: private */
    public static final class AnnotatedField {
        private final Asn1Field mAnnotation;
        private final int mBerTagClass;
        private final int mBerTagNumber;
        private final Asn1Type mDataType;
        private final Field mField;
        private final boolean mOptional;
        private final Asn1TagClass mTagClass;
        private final Asn1Tagging mTagging;

        public AnnotatedField(Field field, Asn1Field annotation) throws Asn1DecodingException {
            int tagNumber;
            this.mField = field;
            this.mAnnotation = annotation;
            this.mDataType = annotation.type();
            Asn1TagClass tagClass = annotation.cls();
            if (tagClass == Asn1TagClass.AUTOMATIC) {
                if (annotation.tagNumber() != -1) {
                    tagClass = Asn1TagClass.CONTEXT_SPECIFIC;
                } else {
                    tagClass = Asn1TagClass.UNIVERSAL;
                }
            }
            this.mTagClass = tagClass;
            this.mBerTagClass = BerEncoding.getTagClass(this.mTagClass);
            if (annotation.tagNumber() != -1) {
                tagNumber = annotation.tagNumber();
            } else if (this.mDataType == Asn1Type.CHOICE || this.mDataType == Asn1Type.ANY) {
                tagNumber = -1;
            } else {
                tagNumber = BerEncoding.getTagNumber(this.mDataType);
            }
            this.mBerTagNumber = tagNumber;
            this.mTagging = annotation.tagging();
            if ((this.mTagging == Asn1Tagging.EXPLICIT || this.mTagging == Asn1Tagging.IMPLICIT) && annotation.tagNumber() == -1) {
                throw new Asn1DecodingException("Tag number must be specified when tagging mode is " + this.mTagging);
            }
            this.mOptional = annotation.optional();
        }

        public Field getField() {
            return this.mField;
        }

        public Asn1Field getAnnotation() {
            return this.mAnnotation;
        }

        public boolean isOptional() {
            return this.mOptional;
        }

        public int getBerTagClass() {
            return this.mBerTagClass;
        }

        public int getBerTagNumber() {
            return this.mBerTagNumber;
        }

        public void setValueFrom(BerDataValue dataValue, Object obj) throws Asn1DecodingException {
            int readTagClass = dataValue.getTagClass();
            if (this.mBerTagNumber != -1) {
                int readTagNumber = dataValue.getTagNumber();
                if (!(readTagClass == this.mBerTagClass && readTagNumber == this.mBerTagNumber)) {
                    throw new Asn1UnexpectedTagException("Tag mismatch. Expected: " + BerEncoding.tagClassAndNumberToString(this.mBerTagClass, this.mBerTagNumber) + ", but found " + BerEncoding.tagClassAndNumberToString(readTagClass, readTagNumber));
                }
            } else if (readTagClass != this.mBerTagClass) {
                throw new Asn1UnexpectedTagException("Tag mismatch. Expected class: " + BerEncoding.tagClassToString(this.mBerTagClass) + ", but found " + BerEncoding.tagClassToString(readTagClass));
            }
            if (this.mTagging == Asn1Tagging.EXPLICIT) {
                try {
                    dataValue = dataValue.contentsReader().readDataValue();
                } catch (BerDataValueFormatException e) {
                    throw new Asn1DecodingException("Failed to read contents of EXPLICIT data value", e);
                }
            }
            BerToJavaConverter.setFieldValue(obj, this.mField, this.mDataType, dataValue);
        }
    }

    /* access modifiers changed from: private */
    public static class Asn1UnexpectedTagException extends Asn1DecodingException {
        private static final long serialVersionUID = 1;

        public Asn1UnexpectedTagException(String message) {
            super(message);
        }
    }

    /* access modifiers changed from: private */
    public static String oidToString(ByteBuffer encodedOid) throws Asn1DecodingException {
        if (!encodedOid.hasRemaining()) {
            throw new Asn1DecodingException("Empty OBJECT IDENTIFIER");
        }
        long firstComponent = decodeBase128UnsignedLong(encodedOid);
        int firstNode = (int) Math.min(firstComponent / 40, 2L);
        StringBuilder result = new StringBuilder();
        result.append(Long.toString((long) firstNode)).append('.').append(Long.toString(firstComponent - ((long) (firstNode * 40))));
        while (encodedOid.hasRemaining()) {
            result.append('.').append(Long.toString(decodeBase128UnsignedLong(encodedOid)));
        }
        return result.toString();
    }

    private static long decodeBase128UnsignedLong(ByteBuffer encoded) throws Asn1DecodingException {
        if (!encoded.hasRemaining()) {
            return 0;
        }
        long result = 0;
        while (encoded.hasRemaining()) {
            if (result > 72057594037927935L) {
                throw new Asn1DecodingException("Base-128 number too large");
            }
            int b = encoded.get() & 255;
            result = (result << 7) | ((long) (b & 127));
            if ((b & 128) == 0) {
                return result;
            }
        }
        throw new Asn1DecodingException("Truncated base-128 encoded input: missing terminating byte, with highest bit not set");
    }

    /* access modifiers changed from: private */
    public static BigInteger integerToBigInteger(ByteBuffer encoded) {
        if (!encoded.hasRemaining()) {
            return BigInteger.ZERO;
        }
        return new BigInteger(ByteBufferUtils.toByteArray(encoded));
    }

    /* access modifiers changed from: private */
    public static int integerToInt(ByteBuffer encoded) throws Asn1DecodingException {
        BigInteger value = integerToBigInteger(encoded);
        if (value.compareTo(BigInteger.valueOf(-2147483648L)) >= 0 && value.compareTo(BigInteger.valueOf(2147483647L)) <= 0) {
            return value.intValue();
        }
        throw new Asn1DecodingException(String.format("INTEGER cannot be represented as int: %1$d (0x%1$x)", value));
    }

    /* access modifiers changed from: private */
    public static long integerToLong(ByteBuffer encoded) throws Asn1DecodingException {
        BigInteger value = integerToBigInteger(encoded);
        if (value.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) >= 0 && value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) <= 0) {
            return value.longValue();
        }
        throw new Asn1DecodingException(String.format("INTEGER cannot be represented as long: %1$d (0x%1$x)", value));
    }

    private static List<AnnotatedField> getAnnotatedFields(Class<?> containerClass) throws Asn1DecodingException {
        Field[] declaredFields = containerClass.getDeclaredFields();
        List<AnnotatedField> result = new ArrayList<>(declaredFields.length);
        for (Field field : declaredFields) {
            Asn1Field annotation = (Asn1Field) field.getDeclaredAnnotation(Asn1Field.class);
            if (annotation != null) {
                if (Modifier.isStatic(field.getModifiers())) {
                    throw new Asn1DecodingException(Asn1Field.class.getName() + " used on a static field: " + containerClass.getName() + "." + field.getName());
                }
                try {
                    result.add(new AnnotatedField(field, annotation));
                } catch (Asn1DecodingException e) {
                    throw new Asn1DecodingException("Invalid ASN.1 annotation on " + containerClass.getName() + "." + field.getName(), e);
                }
            }
        }
        return result;
    }

    /* access modifiers changed from: private */
    public static final class BerToJavaConverter {
        private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

        private BerToJavaConverter() {
        }

        public static void setFieldValue(Object obj, Field field, Asn1Type type, BerDataValue dataValue) throws Asn1DecodingException {
            try {
                switch (type) {
                    case SET_OF:
                    case SEQUENCE_OF:
                        if (Asn1OpaqueObject.class.equals(field.getType())) {
                            field.set(obj, convert(type, dataValue, field.getType()));
                            return;
                        } else {
                            field.set(obj, Asn1BerParser.parseSetOf(dataValue, Asn1BerParser.getElementType(field)));
                            return;
                        }
                    default:
                        field.set(obj, convert(type, dataValue, field.getType()));
                        return;
                }
            } catch (ReflectiveOperationException e) {
                throw new Asn1DecodingException("Failed to set value of " + obj.getClass().getName() + "." + field.getName(), e);
            }
        }

        /* JADX WARN: Type inference failed for: r2v12, types: [T, byte[]] */
        /* JADX WARNING: Unknown variable types count: 1 */
        /* Code decompiled incorrectly, please refer to instructions dump. */
        public static <T> T convert(com.android.apksig.internal.asn1.Asn1Type r7, com.android.apksig.internal.asn1.ber.BerDataValue r8, java.lang.Class<T> r9) throws com.android.apksig.internal.asn1.Asn1DecodingException {
            /*
            // Method dump skipped, instructions count: 348
            */
            throw new UnsupportedOperationException("Method not decompiled: com.android.apksig.internal.asn1.Asn1BerParser.BerToJavaConverter.convert(com.android.apksig.internal.asn1.Asn1Type, com.android.apksig.internal.asn1.ber.BerDataValue, java.lang.Class):java.lang.Object");
        }
    }
}
