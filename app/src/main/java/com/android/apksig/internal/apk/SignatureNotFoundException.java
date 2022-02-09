package com.android.apksig.internal.apk;

public class SignatureNotFoundException extends Exception {
    public SignatureNotFoundException(String message) {
        super(message);
    }

    public SignatureNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
