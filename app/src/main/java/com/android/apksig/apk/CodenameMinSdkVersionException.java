package com.android.apksig.apk;

public class CodenameMinSdkVersionException extends MinSdkVersionException {
    private static final long serialVersionUID = 1;
    private final String mCodename;

    public CodenameMinSdkVersionException(String message, String codename) {
        super(message);
        this.mCodename = codename;
    }

    public String getCodename() {
        return this.mCodename;
    }
}
