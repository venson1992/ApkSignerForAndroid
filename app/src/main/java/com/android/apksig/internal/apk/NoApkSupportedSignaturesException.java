package com.android.apksig.internal.apk;

public class NoApkSupportedSignaturesException extends Exception {
    public NoApkSupportedSignaturesException(String message) {
        super(message);
    }
}
