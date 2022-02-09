package com.android.apksig.internal.apk;

import com.android.apksig.ApkVerificationIssue;
import java.util.ArrayList;
import java.util.List;

public class ApkSigResult {
    private final List<ApkVerificationIssue> mErrors = new ArrayList();
    public final List<ApkSignerInfo> mSigners = new ArrayList();
    private final List<ApkVerificationIssue> mWarnings = new ArrayList();
    public final int signatureSchemeVersion;
    public boolean verified;

    public ApkSigResult(int signatureSchemeVersion2) {
        this.signatureSchemeVersion = signatureSchemeVersion2;
    }

    public boolean containsErrors() {
        if (!this.mErrors.isEmpty()) {
            return true;
        }
        if (!this.mSigners.isEmpty()) {
            for (ApkSignerInfo signer : this.mSigners) {
                if (signer.containsErrors()) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean containsWarnings() {
        if (!this.mWarnings.isEmpty()) {
            return true;
        }
        if (!this.mSigners.isEmpty()) {
            for (ApkSignerInfo signer : this.mSigners) {
                if (signer.containsWarnings()) {
                    return true;
                }
            }
        }
        return false;
    }

    public void addError(int issueId, Object... parameters) {
        this.mErrors.add(new ApkVerificationIssue(issueId, parameters));
    }

    public void addWarning(int issueId, Object... parameters) {
        this.mWarnings.add(new ApkVerificationIssue(issueId, parameters));
    }

    public List<? extends ApkVerificationIssue> getErrors() {
        return this.mErrors;
    }

    public List<? extends ApkVerificationIssue> getWarnings() {
        return this.mWarnings;
    }
}
