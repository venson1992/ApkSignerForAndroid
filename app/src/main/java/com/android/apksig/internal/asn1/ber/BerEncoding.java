package com.android.apksig.internal.asn1.ber;

import com.android.apksig.ApkVerificationIssue;
import com.android.apksig.internal.asn1.Asn1TagClass;
import com.android.apksig.internal.asn1.Asn1Type;

public abstract class BerEncoding {
    public static final int ID_FLAG_CONSTRUCTED_ENCODING = 32;
    public static final int TAG_CLASS_APPLICATION = 1;
    public static final int TAG_CLASS_CONTEXT_SPECIFIC = 2;
    public static final int TAG_CLASS_PRIVATE = 3;
    public static final int TAG_CLASS_UNIVERSAL = 0;
    public static final int TAG_NUMBER_BIT_STRING = 3;
    public static final int TAG_NUMBER_BOOLEAN = 1;
    public static final int TAG_NUMBER_GENERALIZED_TIME = 24;
    public static final int TAG_NUMBER_INTEGER = 2;
    public static final int TAG_NUMBER_NULL = 5;
    public static final int TAG_NUMBER_OBJECT_IDENTIFIER = 6;
    public static final int TAG_NUMBER_OCTET_STRING = 4;
    public static final int TAG_NUMBER_SEQUENCE = 16;
    public static final int TAG_NUMBER_SET = 17;
    public static final int TAG_NUMBER_UTC_TIME = 23;

    private BerEncoding() {
    }

    public static int getTagNumber(Asn1Type dataType) {
        switch (AnonymousClass1.$SwitchMap$com$android$apksig$internal$asn1$Asn1Type[dataType.ordinal()]) {
            case 1:
                return 2;
            case 2:
                return 6;
            case 3:
                return 4;
            case 4:
                return 3;
            case 5:
                return 17;
            case 6:
            case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
                return 16;
            case 8:
                return 23;
            case 9:
                return 24;
            case ApkVerificationIssue.V3_SIG_NO_SIGNERS:
                return 1;
            default:
                throw new IllegalArgumentException("Unsupported data type: " + dataType);
        }
    }

    /* access modifiers changed from: package-private */
    /* renamed from: com.android.apksig.internal.asn1.ber.BerEncoding$1  reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$android$apksig$internal$asn1$Asn1Type = new int[Asn1Type.values().length];

        static {
            $SwitchMap$com$android$apksig$internal$asn1$Asn1TagClass = new int[Asn1TagClass.values().length];
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1TagClass[Asn1TagClass.APPLICATION.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1TagClass[Asn1TagClass.CONTEXT_SPECIFIC.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1TagClass[Asn1TagClass.PRIVATE.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1TagClass[Asn1TagClass.UNIVERSAL.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.INTEGER.ordinal()] = 1;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.OBJECT_IDENTIFIER.ordinal()] = 2;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.OCTET_STRING.ordinal()] = 3;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.BIT_STRING.ordinal()] = 4;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.SET_OF.ordinal()] = 5;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.SEQUENCE.ordinal()] = 6;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.SEQUENCE_OF.ordinal()] = 7;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.UTC_TIME.ordinal()] = 8;
            } catch (NoSuchFieldError e12) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.GENERALIZED_TIME.ordinal()] = 9;
            } catch (NoSuchFieldError e13) {
            }
            try {
                $SwitchMap$com$android$apksig$internal$asn1$Asn1Type[Asn1Type.BOOLEAN.ordinal()] = 10;
            } catch (NoSuchFieldError e14) {
            }
        }
    }

    public static int getTagClass(Asn1TagClass tagClass) {
        switch (tagClass) {
            case APPLICATION:
                return 1;
            case CONTEXT_SPECIFIC:
                return 2;
            case PRIVATE:
                return 3;
            case UNIVERSAL:
                return 0;
            default:
                throw new IllegalArgumentException("Unsupported tag class: " + tagClass);
        }
    }

    public static String tagClassToString(int typeClass) {
        switch (typeClass) {
            case TAG_CLASS_UNIVERSAL /*{ENCODED_INT: 0}*/:
                return "UNIVERSAL";
            case 1:
                return "APPLICATION";
            case 2:
                return "";
            case 3:
                return "PRIVATE";
            default:
                throw new IllegalArgumentException("Unsupported type class: " + typeClass);
        }
    }

    public static String tagClassAndNumberToString(int tagClass, int tagNumber) {
        String classString = tagClassToString(tagClass);
        String numberString = tagNumberToString(tagNumber);
        return classString.isEmpty() ? numberString : classString + " " + numberString;
    }

    public static String tagNumberToString(int tagNumber) {
        switch (tagNumber) {
            case 1:
                return "BOOLEAN";
            case 2:
                return "INTEGER";
            case 3:
                return "BIT STRING";
            case 4:
                return "OCTET STRING";
            case 5:
                return "NULL";
            case 6:
                return "OBJECT IDENTIFIER";
            case ApkVerificationIssue.V2_SIG_NO_CERTIFICATES:
            case 8:
            case 9:
            case ApkVerificationIssue.V3_SIG_NO_SIGNERS:
            case 11:
            case 12:
            case ApkVerificationIssue.V3_SIG_NO_SIGNATURES:
            case ApkVerificationIssue.V3_SIG_MALFORMED_CERTIFICATE:
            case ApkVerificationIssue.V3_SIG_NO_CERTIFICATES:
            case 18:
            case 19:
            case ApkVerificationIssue.SOURCE_STAMP_MALFORMED_SIGNATURE:
            case 21:
            case ApkVerificationIssue.SOURCE_STAMP_VERIFY_EXCEPTION:
            default:
                return "0x" + Integer.toHexString(tagNumber);
            case 16:
                return "SEQUENCE";
            case 17:
                return "SET";
            case 23:
                return "UTC TIME";
            case 24:
                return "GENERALIZED TIME";
        }
    }

    public static boolean isConstructed(byte firstIdentifierByte) {
        return (firstIdentifierByte & 32) != 0;
    }

    public static int getTagClass(byte firstIdentifierByte) {
        return (firstIdentifierByte & 255) >> 6;
    }

    public static byte setTagClass(byte firstIdentifierByte, int tagClass) {
        return (byte) ((firstIdentifierByte & 63) | (tagClass << 6));
    }

    public static int getTagNumber(byte firstIdentifierByte) {
        return firstIdentifierByte & 31;
    }

    public static byte setTagNumber(byte firstIdentifierByte, int tagNumber) {
        return (byte) ((firstIdentifierByte & -32) | tagNumber);
    }
}
