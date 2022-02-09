package com.android.apksig.internal.asn1.ber;

public class BerDataValueFormatException extends Exception {
    private static final long serialVersionUID = 1;

    public BerDataValueFormatException(String message) {
        super(message);
    }

    public BerDataValueFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
