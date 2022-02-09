package com.android.apksig.apk;

public class MinSdkVersionException extends ApkFormatException {
    private static final long serialVersionUID = 1;

    public MinSdkVersionException(String message) {
        super(message);
    }

    public MinSdkVersionException(String message, Throwable cause) {
        super(message, cause);
    }
}
